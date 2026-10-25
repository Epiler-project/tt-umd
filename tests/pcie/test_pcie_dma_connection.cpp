// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Run the consuming TTDevice factory and every public PCIe DMA entrypoint
// through production UMD and tt-kmd-lib. Only the OS/driver boundary is fake;
// no physical device may be opened, even outside the active fixture.
//
// COVERS: UMD-PCIE-CONNECTION-001 pcie_dma_retained_connection
// COVERS: UMD-PCIE-CONNECTION-001 pcie_dma_lock_failure_and_unwind

#include <dlfcn.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "tt-kmd-lib/pci_ids.h"
#include "tt-kmd-lib/tt_kmd_lib.h"
#include "umd/device/arch/blackhole_implementation.hpp"
#include "umd/device/chip/local_chip.hpp"
#include "umd/device/pcie/pci_device.hpp"
#include "umd/device/pcie/silicon_tlb_window.hpp"
#include "umd/device/soc_descriptor.hpp"
#include "umd/device/tt_device/firmware/device_firmware.hpp"
#include "umd/device/tt_device/protocol/dma_interface.hpp"
#include "umd/device/tt_device/protocol/pcie_interface.hpp"
#include "umd/device/tt_device/protocol/pcie_protocol.hpp"
#include "umd/device/tt_device/tt_device.hpp"
#include "umd/device/tt_device/tt_device_error.hpp"
#include "umd/device/types/blackhole_eth.hpp"
#include "umd/device/types/telemetry.hpp"
#include "umd/device/utils/lock_manager.hpp"
#include "umd/device/utils/robust_mutex.hpp"

// ioctl.h owns legacy macro names which overlap public UMD enums.
#include "ioctl.h"

namespace {

constexpr std::string_view DeviceSysfsPath = "/sys/bus/pci/devices/0000:01:02.0/";
constexpr uint8_t ArcLockIndex = 16;
constexpr uint8_t DmaLockIndex = 21;
constexpr uint8_t MemoryBarrierLockIndex = 19;
constexpr std::array<uint32_t, 3> MemoryBarrierAddresses = {0x60000, 0x61000, 0x62000};
int nextFakeFd = 100000;
unsigned nextDeviceOrdinal = 0;
bool fixtureActive = false;

struct OpenRequest {
    int fd;
    int flags;
};

struct LockRequest {
    int fd;
    uint8_t index;
    uint32_t flags;
};

struct MemoryBarrierRelease {
    int fd;
    std::array<bool, 3> resetReadback;
};

struct Mapping {
    size_t size;
    int fd;
};

struct IoState {
    int deviceNumber = 0;
    std::string devicePath;
    std::vector<OpenRequest> opens;
    std::vector<int> closedFds;
    std::vector<int> queryFds;
    std::vector<int> mmapFds;
    std::vector<LockRequest> locks;
    std::unordered_map<uint8_t, int> heldLocks;
    std::unordered_map<uint32_t, int> liveTlbs;
    std::unordered_map<uint64_t, std::pair<uint64_t, int>> pinnedBuffers;
    std::unordered_map<void *, Mapping> mappings;
    unsigned unexpectedDeviceOpens = 0;
    unsigned operationsAfterClose = 0;
    unsigned duplicateCloses = 0;
    unsigned unknownIoctls = 0;
    unsigned deviceInfoQueries = 0;
    unsigned driverInfoQueries = 0;
    unsigned mappingQueries = 0;
    unsigned dmaAllocations = 0;
    unsigned tlbAllocations = 0;
    unsigned tlbFrees = 0;
    uint32_t nextTlbId = 1;
    unsigned lockAcquireErrors = 0;
    unsigned lockReleaseErrors = 0;
    unsigned pinOperations = 0;
    unsigned unpinOperations = 0;
    void *iatuCleanupMapping = nullptr;
    std::optional<uint32_t> retiredIatuControl;
    bool rejectDmaLockAcquire = false;
    int dmaAcquireError = EIO;
    int dmaReleaseError = 0;
    bool rejectChipInUseLockAcquire = false;
    int chipInUseAcquireError = EIO;
    int chipInUseReleaseError = 0;
    unsigned chipInUseAcquireErrors = 0;
    unsigned chipInUseReleaseErrors = 0;
    bool rejectArcLockAcquire = false;
    int arcAcquireError = ENODEV;
    unsigned arcAcquireErrors = 0;
    int arcReleaseError = 0;
    unsigned arcReleaseErrors = 0;
    int memoryBarrierAcquireError = 0;
    int memoryBarrierReleaseError = 0;
    unsigned memoryBarrierAcquireErrors = 0;
    unsigned memoryBarrierReleaseErrors = 0;
    bool observeMemoryBarrier = false;
    std::vector<MemoryBarrierRelease> memoryBarrierReleases;
    bool firmwareImageEnabled = false;
    std::vector<std::pair<int, uint16_t>> powerRequests;
    unsigned nextRetirementEvent = 0;
    unsigned lastUnmapEvent = 0;
    std::unordered_map<int, unsigned> closeEvents;

    bool isDeviceFd(int fd) const {
        return std::any_of(opens.begin(), opens.end(), [fd](const auto &open) { return open.fd == fd; });
    }

    bool isClosed(int fd) const { return std::find(closedFds.begin(), closedFds.end(), fd) != closedFds.end(); }

    int openFlags(int fd) const {
        for (const auto &open : opens)
            if (open.fd == fd)
                return open.flags;
        ADD_FAILURE() << "Unknown fake connection " << fd;
        return 0;
    }

    void releaseRemainingMappings() {
        for (const auto &mapping : mappings)
            syscall(SYS_munmap, mapping.first, mapping.second.size);
        mappings.clear();
    }
};

IoState io;

// This is the firmware-published memory image at the fake mmap boundary. The
// real Blackhole firmware, telemetry provider, SoC construction and training
// checks all consume it through the production PCIe protocol. No semantic
// firmware method or LocalChip construction phase is replaced.
void populateFirmwareWindow(void *mapping, size_t length) {
    if (!io.firmwareImageEnabled || length != 2 * 1024 * 1024)
        return;
    auto store32 = [mapping](size_t offset, uint32_t value) {
        std::memcpy(static_cast<uint8_t *>(mapping) + offset, &value, sizeof(value));
    };
    constexpr uint32_t controlAddress = 0x10000;
    constexpr uint32_t tableAddress = 0x11000;
    constexpr uint32_t valuesAddress = 0x12000;
    const uint64_t queueControl = (uint64_t{8} << 32) | 0x18000;
    std::memcpy(static_cast<uint8_t *>(mapping) + controlAddress, &queueControl, sizeof(queueControl));
    store32(tt::umd::blackhole::SCRATCH_RAM_2, 5);
    store32(tt::umd::blackhole::SCRATCH_RAM_11, controlAddress);
    store32(tt::umd::blackhole::SCRATCH_RAM_12, valuesAddress);
    store32(tt::umd::blackhole::SCRATCH_RAM_13, tableAddress);
    const std::pair<tt::umd::TelemetryTag, uint32_t> entries[] = {
        {tt::umd::TelemetryTag::BOARD_ID_HIGH, 0x400},
        {tt::umd::TelemetryTag::BOARD_ID_LOW, 0},
        {tt::umd::TelemetryTag::ENABLED_TENSIX_COL, 0x3fff},
        // Full Blackhole has exactly two harvested ETH channels.
        {tt::umd::TelemetryTag::ENABLED_ETH, 0x3ffc},
        {tt::umd::TelemetryTag::ENABLED_GDDR, 0xff},
        // P150 exposes PCIe0 as the endpoint and harvests PCIe1 (11, 0).
        {tt::umd::TelemetryTag::PCIE_USAGE, 1},
        {tt::umd::TelemetryTag::GDDR_STATUS, 0x5555},
        // LocalChip::close_device() reads the published clock before it
        // releases its startup guard. Publish the idle value so this fixture
        // exercises the normal close/unlock path rather than failing at the
        // unrelated missing-telemetry boundary.
        {tt::umd::TelemetryTag::AICLK, tt::umd::blackhole::AICLK_IDLE_VAL},
    };
    store32(tableAddress, 1);
    store32(tableAddress + 4, std::size(entries));
    for (size_t index = 0; index < std::size(entries); ++index) {
        store32(tableAddress + 8 + index * 4, (index << 16) | entries[index].first);
        store32(valuesAddress + index * 4, entries[index].second);
    }
    store32(tt::umd::blackhole::BOOT_RESULTS_ADDR + offsetof(tt::umd::blackhole::eth_status_t, port_status),
            static_cast<uint32_t>(tt::umd::EthTrainingStatus::SUCCESS));
}

bool hasMode(int flags) { return (flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE; }

bool isAnyDevicePath(const char *path) {
    return path != nullptr && std::string_view(path).substr(0, 16) == "/dev/tenstorrent";
}

std::optional<std::string_view> fakeSysfsContents(const char *path) {
    if (path == nullptr)
        return std::nullopt;
    const std::string_view value(path);
    if (value == "/sys/module/tenstorrent/version")
        return "2.10.0\n";
    if (value.substr(0, DeviceSysfsPath.size()) != DeviceSysfsPath)
        return std::nullopt;
    const auto attribute = value.substr(DeviceSysfsPath.size());
    if (attribute == "numa_node")
        return "-1\n";
    if (attribute == "revision")
        return "0\n";
    if (attribute == "iommu_group/type")
        return "none\n";
    return std::nullopt;
}

int rawOpenAt(int directory, const char *path, int flags, mode_t mode) {
    return static_cast<int>(syscall(SYS_openat, directory, path, flags, mode));
}

int sysfsFile(std::string_view content) {
    const int fd = static_cast<int>(syscall(SYS_memfd_create, "trex-umd-dma-sysfs", 0));
    if (fd == -1)
        return -1;
    if (write(fd, content.data(), content.size()) != static_cast<ssize_t>(content.size()) ||
        lseek(fd, 0, SEEK_SET) == -1) {
        const int error = errno;
        syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    return fd;
}

std::optional<int> interceptedOpen(const char *path, int flags = 0) {
    if (fixtureActive && path != nullptr && std::string_view(path) == io.devicePath) {
        const int fd = nextFakeFd++;
        io.opens.push_back({fd, flags});
        return fd;
    }
    if (isAnyDevicePath(path)) {
        if (fixtureActive)
            ++io.unexpectedDeviceOpens;
        errno = EPERM;
        return -1;
    }
    if (fixtureActive)
        if (const auto content = fakeSysfsContents(path))
            return sysfsFile(*content);
    return std::nullopt;
}

enum class DmaEntry { Write, Read, WriteCoreRange, ReadZeroCopy, WriteZeroCopy };
enum class MemoryBarrierEntry { L1Selected, L1All, DramCores, DramChannels, DramAll };
constexpr std::array<MemoryBarrierEntry, 5> MemoryBarrierEntries = {
    MemoryBarrierEntry::L1Selected, MemoryBarrierEntry::L1All, MemoryBarrierEntry::DramCores,
    MemoryBarrierEntry::DramChannels, MemoryBarrierEntry::DramAll};

using CoordinateException = tt::umd::error::UmdException<tt::umd::error::UnresolvableCoordinateError>;
using RuntimeException = tt::umd::error::UmdException<tt::umd::error::RuntimeError>;
using ConnectionException = tt::umd::error::UmdException<tt::umd::error::PciDeviceConnectionError>;

static_assert(std::is_nothrow_move_constructible_v<tt::umd::PcieResourceLock>);
static_assert(!std::is_move_assignable_v<tt::umd::PcieResourceLock>);
static_assert(!std::is_copy_constructible_v<tt::umd::PcieResourceLock>);

class PcieDmaConnectionTest : public ::testing::TestWithParam<DmaEntry> {
protected:
    void SetUp() override {
        io = {};
        // LockManager intentionally retains each registry entry for the whole
        // process. Never reuse a key or reset that production registry.
        io.deviceNumber = 1000000 + static_cast<int>(getpid() % 100000) * 32 +
                          static_cast<int>(nextDeviceOrdinal++);
        io.devicePath = "/dev/tenstorrent/" + std::to_string(io.deviceNumber);
        fixtureActive = true;
        auto pci = std::make_unique<tt::umd::PCIDevice>(io.deviceNumber);
        ASSERT_FALSE(io.opens.empty());
        ordinaryFd = io.opens.front().fd;
        EXPECT_EQ(io.openFlags(ordinaryFd) & O_APPEND, 0);
        auto *const actualPci = pci.get();
        auto *const actualHandle = pci->get_tt_device_handle();
        device = tt::umd::TTDevice::create(std::move(pci));
        ASSERT_NE(device, nullptr);
        ASSERT_EQ(device->get_pci_device(), actualPci);
        ASSERT_EQ(device->get_pci_device()->get_tt_device_handle(), actualHandle);
        ASSERT_EQ(device->get_communication_device_type(), tt::umd::IODeviceType::PCIe);
        ASSERT_NE(device->get_device_protocol(), nullptr);
        // The consuming PCIe factory owns PcieProtocol. Confirm both public
        // interface projections refer to that same actual transport before
        // using its concrete type in the no-RTTI test build.
        auto *const protocol = static_cast<tt::umd::PcieProtocol *>(device->get_device_protocol());
        ASSERT_EQ(static_cast<tt::umd::PcieInterface *>(protocol), device->get_pcie_interface());
        ASSERT_EQ(protocol->get_pci_device(), actualPci);
        ASSERT_FALSE(io.queryFds.empty());
        ASSERT_FALSE(io.mmapFds.empty());
        for (const int fd : io.queryFds)
            ASSERT_EQ(fd, ordinaryFd);
        for (const int fd : io.mmapFds)
            ASSERT_EQ(fd, ordinaryFd);
        ASSERT_EQ(io.tlbAllocations, 1u);
        ASSERT_EQ(io.dmaAllocations, 1u);
        ASSERT_TRUE(io.locks.empty());

        // ARC_MSG remains a separate lock-only connection in this bounded
        // cut. Observe its real index16 acquire/release before testing index21;
        // never mistake ARC's allowed O_APPEND open for a DMA reopen.
        {
            auto arc = tt::umd::LockManager::acquire_mutex(
                tt::umd::MutexType::ARC_MSG, io.deviceNumber, tt::umd::IODeviceType::PCIe);
        }
        ASSERT_EQ(io.locks.size(), 2u);
        ASSERT_EQ(io.locks[0].index, ArcLockIndex);
        ASSERT_EQ(io.locks[0].flags, TENSTORRENT_LOCK_CTL_ACQUIRE);
        ASSERT_EQ(io.locks[1].index, ArcLockIndex);
        ASSERT_EQ(io.locks[1].flags, TENSTORRENT_LOCK_CTL_RELEASE);
        ASSERT_EQ(io.locks[0].fd, io.locks[1].fd);
        arcFd = io.locks[0].fd;
        ASSERT_NE(arcFd, ordinaryFd);
        ASSERT_NE(io.openFlags(arcFd) & O_APPEND, 0);
        ASSERT_TRUE(io.heldLocks.empty());
        io.locks.clear();
    }

    void TearDown() override {
        device.reset();
        EXPECT_EQ(std::count(io.closedFds.begin(), io.closedFds.end(), ordinaryFd), 1);
        EXPECT_EQ(io.tlbFrees, io.tlbAllocations);
        EXPECT_TRUE(io.liveTlbs.empty());
        EXPECT_TRUE(io.pinnedBuffers.empty());
        EXPECT_TRUE(io.mappings.empty());
        EXPECT_TRUE(io.heldLocks.empty());
        EXPECT_EQ(io.operationsAfterClose, 0u);
        EXPECT_EQ(io.duplicateCloses, 0u);
        EXPECT_EQ(io.unknownIoctls, 0u);
        EXPECT_EQ(io.unexpectedDeviceOpens, 0u);
        // Remove only these test-owned shm names. Existing permanent registry
        // mappings remain valid after unlink and their keys are never reused.
        for (const char *kind : {"ARC_MSG", "PCIE_DMA", "MEM_BARRIER", "CHIP_IN_USE"}) {
            const auto name = "/TT_UMD_LOCK." + std::string(kind) + "_" +
                              std::to_string(io.deviceNumber) + "_PCIe";
            shm_unlink(name.c_str());
        }
        io.releaseRemainingMappings();
        fixtureActive = false;
    }

    void invokeDma() { invokeDma(*device); }

    void invokeDma(tt::umd::TTDevice &target) {
        uint32_t value = 0;
        // Real factory construction does not initialize a SocDescriptor. A
        // nonliteral coordinate fails in the actual typed resolver, after
        // lock acquisition but before any DMA/TLB transfer can begin.
        const tt::umd::CoreCoord core{1, 1, tt::CoreType::TENSIX, tt::CoordSystem::TRANSLATED};
        switch (GetParam()) {
        case DmaEntry::Write:
            target.dma_write(&value, 0, sizeof(value), core);
            break;
        case DmaEntry::Read:
            target.dma_read(&value, 0, sizeof(value), core);
            break;
        case DmaEntry::WriteCoreRange:
            target.dma_write_to_core_range(&value, 0, sizeof(value), core, core);
            break;
        case DmaEntry::ReadZeroCopy:
            target.dma_read_zero_copy(0x12340000, 0, sizeof(value), core);
            break;
        case DmaEntry::WriteZeroCopy:
            target.dma_write_zero_copy(0x12340000, 0, sizeof(value), core);
            break;
        }
    }

    void invokeZeroSizeDma() { invokeZeroSizeDma(*device); }

    void invokeZeroSizeDma(tt::umd::TTDevice &target) {
        uint32_t value = 0;
        // Literal coordinates exercise the actual production DMA success
        // exit without requiring a SocDescriptor. A size-zero transfer sets
        // up the real cached DMA TLB but never starts a DMA engine operation.
        const tt::umd::CoreCoord core{1, 1, tt::CoreType::TENSIX, tt::CoordSystem::LITERAL};
        switch (GetParam()) {
        case DmaEntry::Write:
            target.dma_write(&value, 0, 0, core);
            break;
        case DmaEntry::Read:
            target.dma_read(&value, 0, 0, core);
            break;
        case DmaEntry::WriteCoreRange:
            target.dma_write_to_core_range(&value, 0, 0, core, core);
            break;
        case DmaEntry::ReadZeroCopy:
            target.dma_read_zero_copy(0x12340000, 0, 0, core);
            break;
        case DmaEntry::WriteZeroCopy:
            target.dma_write_zero_copy(0x12340000, 0, 0, core);
            break;
        }
    }

    void expectSuccessfulDmaRelease() const {
        ASSERT_EQ(io.locks.size(), 2u);
        EXPECT_EQ(io.locks[0].flags, TENSTORRENT_LOCK_CTL_ACQUIRE);
        EXPECT_EQ(io.locks[1].flags, TENSTORRENT_LOCK_CTL_RELEASE);
        expectRetainedConnection();
    }

    void quarantineConnection() {
        io.rejectDmaLockAcquire = true;
        EXPECT_THROW(invokeDma(), ConnectionException);
        ASSERT_EQ(io.lockAcquireErrors, 1u);
        io.rejectDmaLockAcquire = false;
        ASSERT_FALSE(device->get_pci_device()->get_connection().is_valid());
        ASSERT_FALSE(io.isClosed(ordinaryFd));
    }

    template <typename Action>
    void expectQuarantined(Action action) const {
        const auto opens = io.opens.size();
        const auto locks = io.locks.size();
        const auto mappings = io.mmapFds.size();
        const auto queries = io.queryFds.size();
        const auto tlbs = io.tlbAllocations;
        bool rejected = false;
        try {
            action();
        } catch (const ConnectionException &failure) {
            rejected = true;
            EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
            EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockAcquireFailed);
            EXPECT_EQ(failure.error().data().error_code, EIO);
        } catch (const std::exception &failure) {
            ADD_FAILURE() << "Cached access returned a different error type: " << failure.what();
        } catch (...) {
            ADD_FAILURE() << "Cached access returned a nonstandard error type";
        }
        EXPECT_TRUE(rejected) << "Cached ordinary access must report the immutable connection failure";
        EXPECT_EQ(io.opens.size(), opens);
        EXPECT_EQ(io.locks.size(), locks);
        EXPECT_EQ(io.mmapFds.size(), mappings);
        EXPECT_EQ(io.queryFds.size(), queries);
        EXPECT_EQ(io.tlbAllocations, tlbs);
        EXPECT_FALSE(io.isClosed(ordinaryFd));
    }

    static std::vector<uint8_t> snapshot(const void *mapping, size_t size) {
        const auto *bytes = static_cast<const uint8_t *>(mapping);
        return {bytes, bytes + size};
    }

    void verifyCachedWindowRejectsIo(tt::umd::IoSafety safety) {
        tt::umd::SiliconTlbWindow window(device->get_pci_device()->allocate_tlb(2 * 1024 * 1024), {}, safety);
        window.write32(0, 0x12345678);
        ASSERT_EQ(window.read32(0), 0x12345678u);
        auto *const mapping = window.handle_ref().get_base();
        const auto original = snapshot(mapping, 32);
        quarantineConnection();
        uint32_t value = 0xabcdef01;
        uint32_t output = 0xfeedcafe;
        expectQuarantined([&] { window.write16(0, 0xabcd); });
        expectQuarantined([&] { (void)window.read16(0); });
        expectQuarantined([&] { window.write32(0, value); });
        expectQuarantined([&] { (void)window.read32(0); });
        expectQuarantined([&] { window.write_register(0, &value, sizeof(value)); });
        expectQuarantined([&] { window.read_register(0, &output, sizeof(output)); });
        expectQuarantined([&] { window.write_block(0, &value, sizeof(value)); });
        expectQuarantined([&] { window.read_block(0, &output, sizeof(output)); });
        expectQuarantined([&] { window.write_aligned(0, &value, sizeof(value)); });
        expectQuarantined([&] { window.read_aligned(0, &output, sizeof(output)); });
        EXPECT_EQ(output, 0xfeedcafeu);
        EXPECT_EQ(snapshot(mapping, 32), original);
    }

    void invokeProtocolZeroSizeDma() {
        uint32_t value = 0;
        auto *const dma = static_cast<tt::umd::PcieProtocol *>(device->get_device_protocol());
        const tt_xy_pair core{1, 1};
        const auto noc = tt::umd::NocId::DEFAULT_NOC;
        bool success = false;
        switch (GetParam()) {
        case DmaEntry::Write:
            success = dma->dma_write(&value, 0, 0, core, noc);
            break;
        case DmaEntry::Read:
            success = dma->dma_read(&value, 0, 0, core, noc);
            break;
        case DmaEntry::WriteCoreRange:
            success = dma->dma_multicast_write(&value, 0, 0, core, core, noc);
            break;
        case DmaEntry::ReadZeroCopy:
            success = dma->dma_read_zero_copy(0x12340000, 0, 0, core, noc);
            break;
        case DmaEntry::WriteZeroCopy:
            success = dma->dma_write_zero_copy(0x12340000, 0, 0, core, noc);
            break;
        }
        EXPECT_TRUE(success);
    }

    void expectZeroSizeReleaseFailure(int errorCode) {
        const auto opens = io.opens.size();
        io.dmaReleaseError = errorCode;
        try {
            invokeZeroSizeDma();
            FAIL() << "The actual public DMA success exit must check lock release";
        } catch (const ConnectionException &failure) {
            EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
            EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockReleaseFailed);
            EXPECT_EQ(failure.error().data().error_code, errorCode);
        }
        expectSuccessfulDmaRelease();
        ASSERT_EQ(io.lockReleaseErrors, 1u);
        EXPECT_EQ(io.tlbAllocations, 2u);
        EXPECT_FALSE(device->get_pci_device()->get_connection().is_valid());
        EXPECT_FALSE(io.isClosed(ordinaryFd));
        EXPECT_EQ(io.opens.size(), opens);
        io.dmaReleaseError = 0;
        const auto locks = io.locks.size();
        EXPECT_THROW(invokeZeroSizeDma(), ConnectionException);
        EXPECT_EQ(io.locks.size(), locks);
        EXPECT_EQ(io.opens.size(), opens);
        EXPECT_FALSE(io.isClosed(ordinaryFd));
        device.reset();
        EXPECT_TRUE(io.isClosed(ordinaryFd));
        EXPECT_TRUE(io.heldLocks.empty());
        EXPECT_TRUE(io.mappings.empty());
        EXPECT_TRUE(io.liveTlbs.empty());
    }

    void expectRetainedConnection() const {
        ASSERT_FALSE(io.locks.empty());
        for (const auto &lock : io.locks) {
            EXPECT_EQ(lock.index, DmaLockIndex);
            EXPECT_EQ(lock.fd, ordinaryFd);
            EXPECT_NE(lock.fd, arcFd);
            EXPECT_EQ(io.openFlags(lock.fd) & O_APPEND, 0);
        }
        for (const auto &open : io.opens) {
            if (open.fd != arcFd) {
                EXPECT_EQ(open.flags & O_APPEND, 0) << "non-ARC lock-only reopen fd=" << open.fd;
            }
        }
    }

    std::unique_ptr<tt::umd::LocalChip> createReadyLocalChip() {
        io.firmwareImageEnabled = true;
        for (const auto &entry : io.mappings)
            populateFirmwareWindow(entry.first, entry.second.size);
        auto *const pcie = device->get_pcie_interface();
        pcie->bar_write32(tt::umd::blackhole::NIU_CFG_NOC0_BAR_PCIE_ADDR +
                              tt::umd::blackhole::NOC_NODE_ID_OFFSET,
                          2);
        device->init_tt_device(std::chrono::milliseconds(50));
        EXPECT_EQ(device->get_chip_info().board_type, tt::BoardType::P150);
        EXPECT_FALSE(device->get_soc_descriptor().get_cores(tt::CoreType::ETH).empty());
        EXPECT_GT(device->get_soc_descriptor().get_num_dram_channels(), 0);
        auto chip = tt::umd::LocalChip::create(std::move(device), 0);
        const auto core = chip->get_soc_descriptor().get_cores(tt::CoreType::TENSIX).front();
        uint32_t value = 0;
        // Warm both actual LocalChip borrowers before quarantine, so teardown
        // must release them through their original connection as well.
        chip->read_from_device(core, &value, 0, sizeof(value));
        chip->read_from_device_reg(core, &value, 0, sizeof(value));
        return chip;
    }

    void expectLocalChipRetirement(std::unique_ptr<tt::umd::LocalChip> &chip, size_t expectedPowerRequests) {
        chip.reset();
        EXPECT_EQ(io.powerRequests.size(), expectedPowerRequests);
        EXPECT_EQ(std::count(io.closedFds.begin(), io.closedFds.end(), ordinaryFd), 1);
        ASSERT_NE(io.closeEvents.count(ordinaryFd), 0u);
        EXPECT_LT(io.lastUnmapEvent, io.closeEvents.at(ordinaryFd));
        EXPECT_TRUE(io.mappings.empty());
        EXPECT_TRUE(io.liveTlbs.empty());
        EXPECT_TRUE(io.pinnedBuffers.empty());
    }

    void expectLocalChipReleaseFailureRetirement(int errorCode) {
        auto chip = createReadyLocalChip();
        ASSERT_NE(chip, nullptr);
        ASSERT_EQ(io.powerRequests.size(), 1u);
        auto *const actual = chip->get_tt_device();
        io.dmaReleaseError = errorCode;
        bool rejected = false;
        try {
            invokeZeroSizeDma(*actual);
        } catch (const ConnectionException &failure) {
            rejected = true;
            EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
            EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockReleaseFailed);
            EXPECT_EQ(failure.error().data().error_code, errorCode);
        }
        EXPECT_TRUE(rejected);
        EXPECT_EQ(io.lockReleaseErrors, 1u);
        EXPECT_FALSE(actual->get_pci_device()->get_connection().is_valid());
        EXPECT_FALSE(io.isClosed(ordinaryFd));
        io.dmaReleaseError = 0;
        expectLocalChipRetirement(chip, 1);
    }

    void prepareMemoryBarrier(tt::umd::LocalChip &chip) {
        chip.set_barrier_address_params(
            {MemoryBarrierAddresses[0], MemoryBarrierAddresses[1], MemoryBarrierAddresses[2]});
        // Reset only the fake device's published storage. A preceding public
        // barrier must not leave RESET bytes which certify a later call.
        constexpr uint32_t sentinel = 0xdecafbad;
        for (const auto &mapping : io.mappings)
            if (mapping.second.size == 2 * 1024 * 1024)
                for (uint32_t address : MemoryBarrierAddresses)
                    std::memcpy(static_cast<uint8_t *>(mapping.first) + address, &sentinel, sizeof(sentinel));
        io.locks.clear();
        io.memoryBarrierReleases.clear();
        io.observeMemoryBarrier = true;
    }

    void invokeMemoryBarrier(tt::umd::LocalChip &chip, MemoryBarrierEntry entry) {
        const auto &soc = chip.get_soc_descriptor();
        switch (entry) {
        case MemoryBarrierEntry::L1Selected:
            chip.l1_membar({soc.get_cores(tt::CoreType::TENSIX).front()});
            break;
        case MemoryBarrierEntry::L1All:
            chip.l1_membar();
            break;
        case MemoryBarrierEntry::DramCores:
            chip.dram_membar(std::unordered_set<tt::umd::CoreCoord>{
                soc.get_dram_core_for_channel(0, 0, tt::CoordSystem::TRANSLATED)});
            break;
        case MemoryBarrierEntry::DramChannels:
            chip.dram_membar(std::unordered_set<uint32_t>{0}, 0);
            break;
        case MemoryBarrierEntry::DramAll:
            chip.dram_membar(std::unordered_set<tt::umd::CoreCoord>{});
            break;
        }
    }

    void expectMemoryBarrierSuccess(tt::umd::LocalChip &chip, MemoryBarrierEntry entry) {
        prepareMemoryBarrier(chip);
        const auto opens = io.opens.size();
        EXPECT_NO_THROW(invokeMemoryBarrier(chip, entry));
        const bool l1 = entry == MemoryBarrierEntry::L1Selected || entry == MemoryBarrierEntry::L1All;
        const size_t groups = l1 ? 3 : 1;
        ASSERT_EQ(io.locks.size(), groups * 2);
        ASSERT_EQ(io.memoryBarrierReleases.size(), groups);
        for (size_t group = 0; group < groups; ++group) {
            const auto &acquire = io.locks[group * 2];
            const auto &release = io.locks[group * 2 + 1];
            EXPECT_EQ(acquire.index, MemoryBarrierLockIndex);
            EXPECT_EQ(release.index, MemoryBarrierLockIndex);
            EXPECT_EQ(acquire.flags, TENSTORRENT_LOCK_CTL_ACQUIRE);
            EXPECT_EQ(release.flags, TENSTORRENT_LOCK_CTL_RELEASE);
            EXPECT_EQ(acquire.fd, ordinaryFd);
            EXPECT_EQ(release.fd, ordinaryFd);
            EXPECT_EQ(io.memoryBarrierReleases[group].fd, ordinaryFd);
        }
        // The public method itself performs SET/readback then RESET/readback.
        // At checked release its actual cached WC mapping must retain RESET.
        // This snapshot is not a substitute for a per-access hardware trace.
        const size_t firstAddress = l1 ? 0 : 2;
        EXPECT_TRUE(io.memoryBarrierReleases.front().resetReadback[firstAddress]);
        if (entry == MemoryBarrierEntry::L1All) {
            EXPECT_TRUE(io.memoryBarrierReleases[1].resetReadback[1]);
            EXPECT_TRUE(io.memoryBarrierReleases[2].resetReadback[2]);
        }
        EXPECT_EQ(io.opens.size(), opens);
        EXPECT_TRUE(io.heldLocks.empty());
        EXPECT_TRUE(chip.get_tt_device()->get_pci_device()->get_connection().is_valid());
        EXPECT_FALSE(io.isClosed(ordinaryFd));
    }

    int memoryBarrierFailureExitCode(MemoryBarrierEntry entry, bool releaseFailure, int errorCode) {
        auto chip = createReadyLocalChip();
        if (chip == nullptr || io.powerRequests.size() != 1)
            return 10;
        prepareMemoryBarrier(*chip);
        auto *const actual = chip->get_tt_device();
        const auto opens = io.opens.size();
        if (releaseFailure)
            io.memoryBarrierReleaseError = errorCode;
        else
            io.memoryBarrierAcquireError = errorCode;
        const auto status = releaseFailure ? tt::umd::PciDeviceConnectionStatus::LockReleaseFailed
                                           : tt::umd::PciDeviceConnectionStatus::LockAcquireFailed;
        bool exactFailure = false;
        try {
            invokeMemoryBarrier(*chip, entry);
        } catch (const ConnectionException &failure) {
            exactFailure = failure.error().data().device_num == io.deviceNumber &&
                           failure.error().data().status == status && failure.error().data().error_code == errorCode;
        } catch (...) {
        }
        io.memoryBarrierAcquireError = 0;
        io.memoryBarrierReleaseError = 0;
        if (!exactFailure || io.opens.size() != opens || actual->get_pci_device()->get_connection().is_valid() ||
            io.isClosed(ordinaryFd))
            return 11;
        if (io.memoryBarrierAcquireErrors != (releaseFailure ? 0u : 1u) ||
            io.memoryBarrierReleaseErrors != (releaseFailure ? 1u : 0u) ||
            io.locks.size() != (releaseFailure ? 2u : 1u))
            return 12;
        for (const auto &request : io.locks)
            if (request.index != MemoryBarrierLockIndex || request.fd != ordinaryFd)
                return 13;
        const auto locks = io.locks.size();
        for (bool dma : {false, true}) {
            bool rejected = false;
            try {
                if (dma)
                    invokeZeroSizeDma(*actual);
                else
                    invokeMemoryBarrier(*chip, entry);
            } catch (const ConnectionException &failure) {
                rejected = failure.error().data().device_num == io.deviceNumber &&
                           failure.error().data().status == status && failure.error().data().error_code == errorCode;
            } catch (...) {
            }
            if (!rejected || io.opens.size() != opens || io.locks.size() != locks)
                return 14;
        }
        chip.reset();
        if (io.powerRequests.size() != 1 || !io.isClosed(ordinaryFd) || !io.mappings.empty() ||
            !io.liveTlbs.empty() || !io.pinnedBuffers.empty() || !io.heldLocks.empty() ||
            std::count(io.closedFds.begin(), io.closedFds.end(), ordinaryFd) != 1 ||
            io.lastUnmapEvent >= io.closeEvents.at(ordinaryFd) || io.operationsAfterClose != 0 || io.duplicateCloses != 0)
            return 15;
        return 0;
    }

    std::unique_ptr<tt::umd::TTDevice> device;
    int ordinaryFd = -1;
    int arcFd = -1;
};

TEST_P(PcieDmaConnectionTest, AcquireFailureUsesRetainedConnectionWithoutStartingDma) {
    io.rejectDmaLockAcquire = true;
    EXPECT_THROW(invokeDma(), std::exception);
    // This prerequisite is essential: an earlier constructor/interface failure
    // is a fixture failure and cannot establish the retained-connection RED.
    ASSERT_EQ(io.lockAcquireErrors, 1u);
    ASSERT_EQ(io.locks.size(), 1u);
    ASSERT_EQ(io.locks.front().index, DmaLockIndex);
    ASSERT_EQ(io.locks.front().flags, TENSTORRENT_LOCK_CTL_ACQUIRE);
    ASSERT_TRUE(io.heldLocks.empty());
    EXPECT_EQ(io.tlbAllocations, 1u);
    EXPECT_EQ(io.dmaAllocations, 1u);
    expectRetainedConnection();
}

TEST_P(PcieDmaConnectionTest, ChipInUseGuardUsesRetainedConnectionAndChecksRelease) {
    const auto opens = io.opens.size();
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(
            device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::ChipInUse);
        ASSERT_EQ(io.opens.size(), opens);
        ASSERT_EQ(io.locks.size(), 1u);
        EXPECT_EQ(io.locks[0].index, 20u);
        EXPECT_EQ(io.locks[0].flags, TENSTORRENT_LOCK_CTL_ACQUIRE);
        EXPECT_EQ(io.locks[0].fd, ordinaryFd);
        EXPECT_EQ(io.heldLocks.at(20u), ordinaryFd);
        ASSERT_NO_THROW(guard.unlock());
    }
    ASSERT_EQ(io.locks.size(), 2u);
    EXPECT_EQ(io.locks[1].index, 20u);
    EXPECT_EQ(io.locks[1].flags, TENSTORRENT_LOCK_CTL_RELEASE);
    EXPECT_EQ(io.locks[1].fd, ordinaryFd);
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, ChipInUseAcquireFailureQuarantinesWithoutReopen) {
    const auto opens = io.opens.size();
    io.rejectChipInUseLockAcquire = true;
    EXPECT_THROW(
        (void)tt::umd::LockManager::acquire_pcie_resource(
            device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::ChipInUse),
        ConnectionException);
    EXPECT_EQ(io.chipInUseAcquireErrors, 1u);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_FALSE(device->get_pci_device()->get_connection().is_valid());
    io.rejectChipInUseLockAcquire = false;
    EXPECT_THROW(
        (void)tt::umd::LockManager::acquire_pcie_resource(
            device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::ChipInUse),
        ConnectionException);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_EQ(io.chipInUseAcquireErrors, 1u);
}

TEST_P(PcieDmaConnectionTest, ChipInUseReleaseFailureChecksOriginalConnection) {
    auto guard = tt::umd::LockManager::acquire_pcie_resource(
        device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::ChipInUse);
    io.chipInUseReleaseError = EIO;
    EXPECT_THROW(guard.unlock(), ConnectionException);
    EXPECT_EQ(io.chipInUseReleaseErrors, 1u);
    EXPECT_FALSE(device->get_pci_device()->get_connection().is_valid());
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    io.chipInUseReleaseError = 0;
}

TEST_P(PcieDmaConnectionTest, NumericPcieChipInUseHasNoCompatibilityFallback) {
    const auto opens = io.opens.size();
    EXPECT_THROW(
        tt::umd::LockManager::initialize_mutex(
            tt::umd::MutexType::CHIP_IN_USE, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_THROW(
        (void)tt::umd::LockManager::acquire_mutex(
            tt::umd::MutexType::CHIP_IN_USE, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_THROW(
        (void)tt::umd::LockManager::probe_mutex(
            tt::umd::MutexType::CHIP_IN_USE, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.locks.empty());
}

TEST_P(PcieDmaConnectionTest, ArcMessageLockAcquireDoesNotReopenAfterDeviceGenerationFailure) {
    const auto opens = io.opens.size();
    io.rejectArcLockAcquire = true;
    EXPECT_THROW(
        (void)tt::umd::LockManager::acquire_mutex(
            tt::umd::MutexType::ARC_MSG, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_EQ(io.arcAcquireErrors, 1u);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.isClosed(arcFd));
    EXPECT_EQ(std::count(io.closedFds.begin(), io.closedFds.end(), arcFd), 1);
}

TEST_P(PcieDmaConnectionTest, ArcMessageLockReleaseDoesNotReopenAfterDeviceGenerationFailure) {
    auto guard = tt::umd::LockManager::acquire_mutex(
        tt::umd::MutexType::ARC_MSG, io.deviceNumber, tt::umd::IODeviceType::PCIe);
    const auto opens = io.opens.size();
    io.arcReleaseError = ENODEV;
    EXPECT_NO_THROW(guard.unlock());
    EXPECT_EQ(io.arcReleaseErrors, 1u);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.isClosed(arcFd));
    EXPECT_EQ(std::count(io.closedFds.begin(), io.closedFds.end(), arcFd), 1);
}

TEST_P(PcieDmaConnectionTest, LocalChipStartRetainsChipInUseGuardOnOriginalConnection) {
    auto chip = createReadyLocalChip();
    ASSERT_NE(chip, nullptr);
    const auto opens = io.opens.size();
    ASSERT_NO_THROW(chip->start_device());
    ASSERT_EQ(io.opens.size(), opens);
    ASSERT_FALSE(io.locks.empty());
    ASSERT_EQ(io.locks.back().index, 20u);
    EXPECT_EQ(io.locks.back().fd, ordinaryFd);
    ASSERT_FALSE(io.heldLocks.empty());
    ASSERT_EQ(io.heldLocks.at(20u), ordinaryFd);
    ASSERT_NO_THROW(chip->close_device());
    ASSERT_EQ(io.locks.back().index, 20u);
    EXPECT_EQ(io.locks.back().flags, TENSTORRENT_LOCK_CTL_RELEASE);
    EXPECT_TRUE(io.heldLocks.empty());
    expectLocalChipRetirement(chip, 2);
}

TEST_P(PcieDmaConnectionTest, HealthyReadyLocalChipDestructionLowersPowerBeforeRetiringItsConnection) {
    auto chip = createReadyLocalChip();
    ASSERT_NE(chip, nullptr);
    ASSERT_EQ(io.powerRequests.size(), 1u);
    EXPECT_NE(io.powerRequests.front().second, 0);
    expectLocalChipRetirement(chip, 2);
    ASSERT_EQ(io.powerRequests.size(), 2u);
    EXPECT_EQ(io.powerRequests.back(), (std::pair<int, uint16_t>{ordinaryFd, 0}));
}

TEST_P(PcieDmaConnectionTest, QuarantinedReadyLocalChipDestructionRetiresWithoutNormalPowerRequest) {
    auto chip = createReadyLocalChip();
    ASSERT_NE(chip, nullptr);
    ASSERT_EQ(io.powerRequests.size(), 1u);
    auto *const actual = chip->get_tt_device();
    io.rejectDmaLockAcquire = true;
    EXPECT_THROW(invokeDma(*actual), ConnectionException);
    EXPECT_EQ(io.lockAcquireErrors, 1u);
    ASSERT_FALSE(actual->get_pci_device()->get_connection().is_valid());
    io.rejectDmaLockAcquire = false;
    expectLocalChipRetirement(chip, 1);
}

TEST_P(PcieDmaConnectionTest, ReleaseIoErrorReadyLocalChipDestructionRetiresWithoutNormalPowerRequest) {
    expectLocalChipReleaseFailureRetirement(EIO);
}

TEST_P(PcieDmaConnectionTest, ReleaseDeviceResetReadyLocalChipDestructionRetiresWithoutNormalPowerRequest) {
    expectLocalChipReleaseFailureRetirement(ENODEV);
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierPublicEntrypointsUseRetainedConnectionAndCompleteReadback) {
    auto chip = createReadyLocalChip();
    ASSERT_NE(chip, nullptr);
    for (const auto entry : MemoryBarrierEntries) {
        SCOPED_TRACE(static_cast<int>(entry));
        expectMemoryBarrierSuccess(*chip, entry);
    }
    expectLocalChipRetirement(chip, 2);
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierAcquireIoErrorQuarantinesWithoutReopenAndRetires) {
    for (const auto entry : MemoryBarrierEntries) {
        SCOPED_TRACE(static_cast<int>(entry));
        EXPECT_EXIT({ _exit(memoryBarrierFailureExitCode(entry, false, EIO)); }, ::testing::ExitedWithCode(0), "");
    }
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierAcquireDeviceResetQuarantinesWithoutReopenAndRetires) {
    for (const auto entry : MemoryBarrierEntries) {
        SCOPED_TRACE(static_cast<int>(entry));
        EXPECT_EXIT({ _exit(memoryBarrierFailureExitCode(entry, false, ENODEV)); }, ::testing::ExitedWithCode(0), "");
    }
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierReleaseIoErrorIsCheckedWithoutReopenAndRetires) {
    for (const auto entry : MemoryBarrierEntries) {
        SCOPED_TRACE(static_cast<int>(entry));
        EXPECT_EXIT({ _exit(memoryBarrierFailureExitCode(entry, true, EIO)); }, ::testing::ExitedWithCode(0), "");
    }
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierReleaseDeviceResetIsCheckedWithoutReopenAndRetires) {
    for (const auto entry : MemoryBarrierEntries) {
        SCOPED_TRACE(static_cast<int>(entry));
        EXPECT_EXIT({ _exit(memoryBarrierFailureExitCode(entry, true, ENODEV)); }, ::testing::ExitedWithCode(0), "");
    }
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierRejectsPriorDmaQuarantineBeforeLockOrReadback) {
    auto chip = createReadyLocalChip();
    ASSERT_NE(chip, nullptr);
    auto *const actual = chip->get_tt_device();
    io.rejectDmaLockAcquire = true;
    EXPECT_THROW(invokeDma(*actual), ConnectionException);
    io.rejectDmaLockAcquire = false;
    ASSERT_FALSE(actual->get_pci_device()->get_connection().is_valid());
    prepareMemoryBarrier(*chip);
    const auto opens = io.opens.size();
    for (const auto entry : MemoryBarrierEntries) {
        SCOPED_TRACE(static_cast<int>(entry));
        try {
            invokeMemoryBarrier(*chip, entry);
            ADD_FAILURE() << "Quarantined connection admitted a public memory barrier";
        } catch (const ConnectionException &failure) {
            EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
            EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockAcquireFailed);
            EXPECT_EQ(failure.error().data().error_code, EIO);
        }
        EXPECT_TRUE(io.locks.empty());
        EXPECT_TRUE(io.memoryBarrierReleases.empty());
        EXPECT_EQ(io.opens.size(), opens);
    }
    expectLocalChipRetirement(chip, 1);
}

TEST_P(PcieDmaConnectionTest, CoordinateFailureReleasesRetainedLockAndAllowsAnotherAcquire) {
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        SCOPED_TRACE(attempt);
        EXPECT_THROW(invokeDma(), CoordinateException);
        ASSERT_EQ(io.locks.size(), 2u * (attempt + 1));
        const auto &acquire = io.locks[2 * attempt];
        const auto &release = io.locks[2 * attempt + 1];
        ASSERT_EQ(acquire.index, DmaLockIndex);
        ASSERT_EQ(acquire.flags, TENSTORRENT_LOCK_CTL_ACQUIRE);
        ASSERT_EQ(release.index, DmaLockIndex);
        ASSERT_EQ(release.flags, TENSTORRENT_LOCK_CTL_RELEASE);
        ASSERT_EQ(acquire.fd, release.fd);
        ASSERT_TRUE(io.heldLocks.empty());
        EXPECT_EQ(io.tlbAllocations, 1u);
        EXPECT_EQ(io.dmaAllocations, 1u);
    }
    // A second real acquire also proves CompositeMutex released its robust
    // half when the first actual TTDevice call unwound.
    EXPECT_EQ(io.lockAcquireErrors, 0u);
    expectRetainedConnection();
}

TEST_P(PcieDmaConnectionTest, ZeroSizePublicDmaSuccessChecksRetainedConnectionRelease) {
    const auto opens = io.opens.size();
    EXPECT_NO_THROW(invokeZeroSizeDma());
    expectSuccessfulDmaRelease();
    EXPECT_TRUE(io.heldLocks.empty());
    EXPECT_TRUE(device->get_pci_device()->get_connection().is_valid());
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_EQ(io.tlbAllocations, 2u);
    EXPECT_EQ(io.dmaAllocations, 1u);
}

TEST_P(PcieDmaConnectionTest, ZeroSizePublicDmaSuccessPropagatesExactReleaseIoError) {
    expectZeroSizeReleaseFailure(EIO);
}

TEST_P(PcieDmaConnectionTest, ZeroSizePublicDmaSuccessPropagatesExactReleaseDeviceReset) {
    expectZeroSizeReleaseFailure(ENODEV);
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsCachedBarReadAndWrite) {
    constexpr uint32_t barAddress = 0x1fd00000;
    device->bar_write32(barAddress, 0x12345678);
    ASSERT_EQ(device->bar_read32(barAddress), 0x12345678u);
    auto *const mapping = device->get_pci_device()->get_bar0();
    const auto original = snapshot(mapping, sizeof(uint32_t));
    quarantineConnection();
    expectQuarantined([&] { (void)device->get_pci_device()->get_bar0(); });
    expectQuarantined([&] { (void)device->get_pci_device()->get_bar2_uc(); });
    expectQuarantined([&] { (void)device->bar_read32(barAddress); });
    expectQuarantined([&] { device->bar_write32(barAddress, 0xabcdef01); });
    EXPECT_EQ(snapshot(mapping, sizeof(uint32_t)), original);
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsDirectAndCachedTlbConfiguration) {
    auto *const pci = device->get_pci_device();
    auto handle = pci->allocate_tlb(2 * 1024 * 1024);
    tt::umd::tlb_data originalConfig{};
    originalConfig.x_end = 1;
    handle->configure(originalConfig);
    auto *const configMapping = pci->get_tlb_config_space();
    const auto original = snapshot(configMapping, tt::umd::PCIDevice::tlb_config_space_size);
    quarantineConnection();
    auto changed = originalConfig;
    changed.x_end = 2;
    expectQuarantined([&] { pci->configure_tlb(handle->get_tlb_id(), changed, true); });
    expectQuarantined([&] { handle->configure(changed); });
    EXPECT_EQ(handle->get_config().x_end, originalConfig.x_end);
    EXPECT_EQ(snapshot(configMapping, tt::umd::PCIDevice::tlb_config_space_size), original);
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsNewTlbAllocationWithOriginalTypedFailure) {
    quarantineConnection();
    expectQuarantined([&] { (void)device->get_pci_device()->allocate_tlb(2 * 1024 * 1024); });
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsCachedWindowIoWithoutSafetyWrapper) {
    verifyCachedWindowRejectsIo(tt::umd::IoSafety::Disabled);
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsCachedWindowIoWithSafetyWrapper) {
    verifyCachedWindowRejectsIo(tt::umd::IoSafety::Enabled);
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsWindowConfigurationAndRawMappingAccess) {
    auto *const pci = device->get_pci_device();
    tt::umd::SiliconTlbWindow window(pci->allocate_tlb(2 * 1024 * 1024));
    auto *const configMapping = pci->get_tlb_config_space();
    const auto original = snapshot(configMapping, tt::umd::PCIDevice::tlb_config_space_size);
    quarantineConnection();
    tt::umd::tlb_data changed{};
    changed.x_end = 2;
    expectQuarantined([&] { window.configure(changed); });
    tt::umd::TargetIoWindowConfig target{};
    target.core_start = {3, 4};
    target.addr = 0;
    target.noc = tt::umd::NocId::DEFAULT_NOC;
    expectQuarantined([&] { window.configure(target); });
    expectQuarantined([&] { window.configure(target, tt::umd::IoOrdering::Posted); });
    expectQuarantined([&] { (void)window.handle_ref().get_base(); });
    expectQuarantined([&] { (void)pci->get_tlb_config_space(); });
    expectQuarantined([&] { (void)pci->get_dma_buffer(); });
    EXPECT_EQ(snapshot(configMapping, tt::umd::PCIDevice::tlb_config_space_size), original);
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsWarmProtocolDataAndRegisterIo) {
    const tt::umd::CoreCoord core{1, 1, tt::CoreType::TENSIX, tt::CoordSystem::LITERAL};
    uint32_t value = 0x12345678;
    uint32_t output = 0;
    device->write_to_device(&value, core, 0, sizeof(value));
    device->read_from_device(&output, core, 0, sizeof(output));
    ASSERT_EQ(output, value);
    device->write_to_device_reg(&value, core, 0, sizeof(value));
    device->read_from_device_reg(&output, core, 0, sizeof(output));
    ASSERT_EQ(output, value);
    quarantineConnection();
    value = 0xabcdef01;
    output = 0xfeedcafe;
    expectQuarantined([&] { device->write_to_device(&value, core, 0, sizeof(value)); });
    expectQuarantined([&] { device->read_from_device(&output, core, 0, sizeof(output)); });
    expectQuarantined([&] { device->write_to_device_reg(&value, core, 0, sizeof(value)); });
    expectQuarantined([&] { device->read_from_device_reg(&output, core, 0, sizeof(output)); });
    expectQuarantined([&] {
        (void)device->get_device_protocol()->write_to_core_range(
            &value, {1, 1}, {1, 1}, 0, sizeof(value), tt::umd::NocId::DEFAULT_NOC);
    });
    EXPECT_EQ(output, 0xfeedcafeu);
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsWarmProtocolDmaWithoutAnotherDriverLock) {
    invokeProtocolZeroSizeDma();
    ASSERT_EQ(io.tlbAllocations, 2u);
    auto *const dma = static_cast<tt::umd::PcieProtocol *>(device->get_device_protocol());
    quarantineConnection();
    expectQuarantined([&] { invokeProtocolZeroSizeDma(); });
    expectQuarantined([&] {
        (void)dma->dma_multicast_write_zero_copy(
            0x12340000, 0, 0, {1, 1}, {1, 1}, tt::umd::NocId::DEFAULT_NOC);
    });
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionRejectsIatuConfigurationButAllowsRetirement) {
    auto *const mapping = device->get_pci_device()->get_bar2_uc();
    io.iatuCleanupMapping = mapping;
    device->configure_iatu_region(0, 0x100000000, 1ULL << 30);
    const auto original = snapshot(static_cast<uint8_t *>(mapping) + 0x1000, 0x24);
    quarantineConnection();
    expectQuarantined([&] { device->configure_iatu_region(0, 0x200000000, 1ULL << 30); });
    EXPECT_EQ(snapshot(static_cast<uint8_t *>(mapping) + 0x1000, 0x24), original);
    device.reset();
    ASSERT_TRUE(io.retiredIatuControl.has_value());
    EXPECT_EQ(*io.retiredIatuControl, 0u);
    EXPECT_TRUE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(io.mappings.empty());
}

TEST_P(PcieDmaConnectionTest, QuarantinedConnectionAllowsOriginalPinnedBufferRetirement) {
    const size_t size = static_cast<size_t>(getpagesize());
    void *const buffer = reinterpret_cast<void *>(syscall(SYS_mmap, nullptr, size, PROT_READ | PROT_WRITE,
                                                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    ASSERT_NE(buffer, MAP_FAILED);
    EXPECT_NE(device->get_pci_device()->map_for_dma(buffer, size), 0u);
    ASSERT_EQ(io.pinOperations, 1u);
    quarantineConnection();
    EXPECT_NO_THROW(device->get_pci_device()->unmap_for_dma(buffer, size));
    EXPECT_EQ(io.unpinOperations, 1u);
    EXPECT_TRUE(io.pinnedBuffers.empty());
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    syscall(SYS_munmap, buffer, size);
}

TEST_P(PcieDmaConnectionTest, AcquireIoErrorQuarantinesConnectionBeforeAnotherDriverOperation) {
    io.rejectDmaLockAcquire = true;
    EXPECT_THROW(invokeDma(), ConnectionException);
    ASSERT_EQ(io.lockAcquireErrors, 1u);
    ASSERT_EQ(io.locks.size(), 1u);
    const auto opens = io.opens.size();
    const auto locks = io.locks.size();
    io.rejectDmaLockAcquire = false;
    EXPECT_THROW(invokeDma(), ConnectionException);
    EXPECT_EQ(io.locks.size(), locks) << "An invalid original connection must not issue another LOCK_CTL";
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    EXPECT_THROW((void)device->get_pci_device()->get_tt_device_handle(), ConnectionException);
}

TEST_P(PcieDmaConnectionTest, AcquireDeviceResetQuarantinesWithoutReopeningOrClosingSharedConnection) {
    io.rejectDmaLockAcquire = true;
    io.dmaAcquireError = ENODEV;
    const auto opens = io.opens.size();
    EXPECT_THROW(invokeDma(), ConnectionException);
    ASSERT_GE(io.lockAcquireErrors, 1u);
    EXPECT_EQ(io.lockAcquireErrors, 1u) << "ENODEV must not reopen and retry the shared connection";
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    io.rejectDmaLockAcquire = false;
    const auto locks = io.locks.size();
    EXPECT_THROW(invokeDma(), ConnectionException);
    EXPECT_EQ(io.locks.size(), locks);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_THROW((void)device->get_pci_device()->get_tt_device_handle(), ConnectionException);
}

TEST_P(PcieDmaConnectionTest, UnwindReleaseIoErrorPreservesOriginalExceptionAndQuarantines) {
    EXPECT_EXIT(
        {
            io.dmaReleaseError = EIO;
            bool originalException = false;
            try {
                invokeDma();
            } catch (const CoordinateException &) {
                originalException = true;
            } catch (...) {
                _exit(10);
            }
            if (!originalException || io.lockReleaseErrors != 1 || io.locks.size() != 2)
                _exit(11);
            if (io.isClosed(ordinaryFd))
                _exit(12);
            const auto opens = io.opens.size();
            const auto locks = io.locks.size();
            io.dmaReleaseError = 0;
            try {
                invokeDma();
                _exit(13);
            } catch (const ConnectionException &) {
            } catch (...) {
                _exit(14);
            }
            if (io.opens.size() != opens || io.locks.size() != locks)
                _exit(15);
            device.reset();
            if (!io.mappings.empty() || !io.heldLocks.empty() || io.isClosed(ordinaryFd) == false)
                _exit(16);
            _exit(0);
        },
        ::testing::ExitedWithCode(0),
        ".*");
}

TEST_P(PcieDmaConnectionTest, UnwindReleaseDeviceResetNeverReopensSharedConnection) {
    EXPECT_EXIT(
        {
            io.dmaReleaseError = ENODEV;
            const auto opens = io.opens.size();
            bool originalException = false;
            try {
                invokeDma();
            } catch (const CoordinateException &) {
                originalException = true;
            } catch (...) {
                _exit(20);
            }
            if (!originalException || io.lockReleaseErrors != 1 || io.locks.size() != 2)
                _exit(21);
            if (io.opens.size() != opens || io.isClosed(ordinaryFd))
                _exit(22);
            io.dmaReleaseError = 0;
            const auto locks = io.locks.size();
            try {
                invokeDma();
                _exit(23);
            } catch (const ConnectionException &) {
            } catch (...) {
                _exit(24);
            }
            if (io.locks.size() != locks || io.opens.size() != opens)
                _exit(25);
            device.reset();
            if (!io.mappings.empty() || !io.heldLocks.empty() || !io.isClosed(ordinaryFd))
                _exit(26);
            _exit(0);
        },
        ::testing::ExitedWithCode(0),
        ".*");
}

TEST_P(PcieDmaConnectionTest, NumericPcieDmaInitializationHasNoCompatibilityFallback) {
    const auto opens = io.opens.size();
    EXPECT_THROW(
        tt::umd::LockManager::initialize_mutex(
            tt::umd::MutexType::PCIE_DMA, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.locks.empty());
}

TEST_P(PcieDmaConnectionTest, NumericPcieDmaAcquisitionHasNoCompatibilityFallback) {
    const auto opens = io.opens.size();
    EXPECT_THROW(
        (void)tt::umd::LockManager::acquire_mutex(
            tt::umd::MutexType::PCIE_DMA, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.locks.empty());
}

TEST_P(PcieDmaConnectionTest, NumericPcieDmaProbeHasNoCompatibilityFallback) {
    const auto opens = io.opens.size();
    EXPECT_THROW(
        (void)tt::umd::LockManager::probe_mutex(
            tt::umd::MutexType::PCIE_DMA, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.locks.empty());
}

TEST_P(PcieDmaConnectionTest, TwoLiveDeviceOwnersUseTheirOwnOriginalConnection) {
    const auto firstOpenCount = io.opens.size();
    auto secondPci = std::make_unique<tt::umd::PCIDevice>(io.deviceNumber);
    ASSERT_GT(io.opens.size(), firstOpenCount);
    const int secondFd = io.opens[firstOpenCount].fd;
    auto secondDevice = tt::umd::TTDevice::create(std::move(secondPci));
    ASSERT_NE(secondDevice, nullptr);
    ASSERT_NE(secondFd, ordinaryFd);
    EXPECT_THROW(invokeDma(), CoordinateException);
    ASSERT_EQ(io.locks.size(), 2u);
    EXPECT_EQ(io.locks[0].fd, ordinaryFd);
    EXPECT_EQ(io.locks[1].fd, ordinaryFd);
    EXPECT_THROW(invokeDma(*secondDevice), CoordinateException);
    ASSERT_EQ(io.locks.size(), 4u);
    EXPECT_EQ(io.locks[2].fd, secondFd);
    EXPECT_EQ(io.locks[3].fd, secondFd);
    secondDevice.reset();
    EXPECT_TRUE(io.isClosed(secondFd));
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    EXPECT_THROW(invokeDma(), CoordinateException);
    ASSERT_EQ(io.locks.size(), 6u);
    EXPECT_EQ(io.locks[4].fd, ordinaryFd);
    EXPECT_EQ(io.locks[5].fd, ordinaryFd);
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, GuardCheckedUnlockPublishesExactReleaseFailureAndRetainsOtherIndex) {
    auto &connection = device->get_pci_device()->get_connection();
    auto *const handle = connection.get_handle();
    int acquired = 0;
    ASSERT_EQ(tt_lock_acquire(handle, 33, &acquired), 0);
    ASSERT_EQ(acquired, 1);
    auto guard = tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::Dma);
    io.dmaReleaseError = EIO;
    try {
        guard.unlock();
        FAIL() << "Checked release must report its original driver failure";
    } catch (const ConnectionException &failure) {
        EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
        EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockReleaseFailed);
        EXPECT_EQ(failure.error().data().error_code, EIO);
    }
    ASSERT_EQ(io.lockReleaseErrors, 1u);
    EXPECT_FALSE(connection.is_valid());
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    EXPECT_EQ(io.heldLocks.at(33), ordinaryFd);
    const auto lockCount = io.locks.size();
    io.dmaReleaseError = 0;
    EXPECT_THROW((void)tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::Dma), ConnectionException);
    EXPECT_EQ(io.locks.size(), lockCount);
    int released = 0;
    ASSERT_EQ(tt_lock_release(handle, 33, &released), 0);
    EXPECT_EQ(released, 1);
    device.reset();
    EXPECT_FALSE(io.isClosed(ordinaryFd)) << "The live guard still retains only the original handle";
}

TEST_P(PcieDmaConnectionTest, GuardAcquisitionPreservesExactFirstFailureIdentity) {
    auto &connection = device->get_pci_device()->get_connection();
    io.rejectDmaLockAcquire = true;
    io.dmaAcquireError = ENODEV;
    const auto opens = io.opens.size();
    try {
        (void)tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::Dma);
        FAIL() << "The original driver failure must be surfaced";
    } catch (const ConnectionException &failure) {
        EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
        EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockAcquireFailed);
        EXPECT_EQ(failure.error().data().error_code, ENODEV);
    }
    ASSERT_EQ(io.lockAcquireErrors, 1u);
    io.dmaAcquireError = EIO;
    try {
        (void)connection.get_handle();
        FAIL() << "Quarantined ordinary access must fail";
    } catch (const ConnectionException &failure) {
        EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockAcquireFailed);
        EXPECT_EQ(failure.error().data().error_code, ENODEV);
    }
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_FALSE(io.isClosed(ordinaryFd));
}

TEST_P(PcieDmaConnectionTest, GuardMoveOutlivesDeviceWithoutRetainingMappingsOrRegistryConnection) {
    std::optional<tt::umd::PcieResourceLock> moved;
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::Dma);
        moved.emplace(std::move(guard));
        device.reset();
        EXPECT_TRUE(io.mappings.empty());
        EXPECT_FALSE(io.isClosed(ordinaryFd));
        ASSERT_EQ(io.heldLocks.at(DmaLockIndex), ordinaryFd);
    }
    ASSERT_EQ(io.locks.size(), 1u) << "Moved-from destructor must not release the transferred guard";
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    moved.reset();
    ASSERT_EQ(io.locks.size(), 2u);
    EXPECT_EQ(io.locks.back().fd, ordinaryFd);
    EXPECT_EQ(io.locks.back().flags, TENSTORRENT_LOCK_CTL_RELEASE);
    EXPECT_TRUE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, RegistryDoesNotKeepOriginalConnectionAfterSuccessfulGuardDies) {
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::Dma);
        guard.unlock();
    }
    device.reset();
    EXPECT_TRUE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(io.mappings.empty());
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, SuccessfulGuardReleaseDoesNotReleaseAnotherIndexOnSameHandle) {
    auto &connection = device->get_pci_device()->get_connection();
    auto *const handle = connection.get_handle();
    int acquired = 0;
    ASSERT_EQ(tt_lock_acquire(handle, 33, &acquired), 0);
    ASSERT_EQ(acquired, 1);
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::Dma);
        guard.unlock();
    }
    EXPECT_EQ(io.heldLocks.count(DmaLockIndex), 0u);
    EXPECT_EQ(io.heldLocks.at(33), ordinaryFd);
    EXPECT_TRUE(connection.is_valid());
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    int released = 0;
    ASSERT_EQ(tt_lock_release(handle, 33, &released), 0);
    EXPECT_EQ(released, 1);
}

TEST_P(PcieDmaConnectionTest, LockOnlyObserverUsesExplicitAppendConnectionAndClosesAfterProbe) {
    const auto opens = io.opens.size();
    int observerFd = -1;
    {
        tt::umd::PciDeviceConnection observer(io.deviceNumber, tt::umd::PciDeviceConnectionMode::LockOnly);
        ASSERT_EQ(io.opens.size(), opens + 1);
        observerFd = io.opens.back().fd;
        EXPECT_NE(io.openFlags(observerFd) & O_APPEND, 0);
        EXPECT_FALSE(tt::umd::LockManager::probe_pcie_resource(observer, tt::umd::PcieResourceLockKind::Dma).has_value());
        ASSERT_EQ(io.locks.size(), 2u);
        EXPECT_EQ(io.locks[0].fd, observerFd);
        EXPECT_EQ(io.locks[1].fd, observerFd);
        EXPECT_EQ(io.locks[0].index, DmaLockIndex);
        EXPECT_EQ(io.locks[1].index, DmaLockIndex);
    }
    EXPECT_TRUE(io.isClosed(observerFd));
    EXPECT_FALSE(io.isClosed(ordinaryFd));
}

TEST_P(PcieDmaConnectionTest, LockOnlyObserverCannotBecomePciDeviceOrAllocateMappings) {
    const auto mappings = io.mmapFds.size();
    const auto queries = io.queryFds.size();
    const auto allocations = io.dmaAllocations;
    tt::umd::PciDeviceConnection observer(io.deviceNumber, tt::umd::PciDeviceConnectionMode::LockOnly);
    const int observerFd = io.opens.back().fd;
    EXPECT_THROW((void)tt::umd::PCIDevice(std::move(observer)), RuntimeException);
    EXPECT_EQ(io.mmapFds.size(), mappings);
    EXPECT_EQ(io.queryFds.size(), queries);
    EXPECT_EQ(io.dmaAllocations, allocations);
    EXPECT_TRUE(io.isClosed(observerFd));
}

TEST_P(PcieDmaConnectionTest, ProbeRecognizesExistingRobustOnlyParticipantWithoutDriverAcquire) {
    tt::umd::RobustMutex oldParticipant("PCIE_DMA_" + std::to_string(io.deviceNumber) + "_PCIe");
    oldParticipant.initialize();
    oldParticipant.lock();
    const auto owner = tt::umd::LockManager::probe_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::Dma);
    EXPECT_TRUE(owner.has_value());
    if (owner) {
        EXPECT_EQ(owner->first, getpid());
    }
    EXPECT_TRUE(io.locks.empty());
    oldParticipant.unlock();
    EXPECT_FALSE(tt::umd::LockManager::probe_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::Dma).has_value());
    ASSERT_EQ(io.locks.size(), 2u);
    EXPECT_EQ(io.locks[0].fd, ordinaryFd);
    EXPECT_EQ(io.locks[1].fd, ordinaryFd);
}

TEST_P(PcieDmaConnectionTest, TwoThreadsShareTheExistingRobustParticipantBeforeDriverLock) {
    tt::umd::RobustMutex oldParticipant("PCIE_DMA_" + std::to_string(io.deviceNumber) + "_PCIe");
    oldParticipant.initialize();
    oldParticipant.lock();
    std::atomic<bool> entered{false};
    std::atomic<bool> acquired{false};
    std::exception_ptr failure;
    std::thread contender([&] {
        entered.store(true, std::memory_order_release);
        try {
            auto guard = tt::umd::LockManager::acquire_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::Dma);
            acquired.store(true, std::memory_order_release);
            guard.unlock();
        } catch (...) {
            failure = std::current_exception();
        }
    });
    while (!entered.load(std::memory_order_acquire))
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(acquired.load(std::memory_order_acquire));
    oldParticipant.unlock();
    contender.join();
    EXPECT_EQ(failure, nullptr);
    EXPECT_TRUE(acquired.load(std::memory_order_acquire));
    ASSERT_EQ(io.locks.size(), 2u);
    EXPECT_EQ(io.locks[0].fd, ordinaryFd);
    EXPECT_EQ(io.locks[1].fd, ordinaryFd);
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, CheckedUnlockDeviceResetRetainsExactFailureAndNeverReopens) {
    auto &connection = device->get_pci_device()->get_connection();
    const auto opens = io.opens.size();
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::Dma);
        io.dmaReleaseError = ENODEV;
        try {
            guard.unlock();
            FAIL() << "Checked unlock must report ENODEV";
        } catch (const ConnectionException &failure) {
            EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
            EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockReleaseFailed);
            EXPECT_EQ(failure.error().data().error_code, ENODEV);
        }
        EXPECT_FALSE(io.isClosed(ordinaryFd));
        EXPECT_EQ(io.opens.size(), opens);
        EXPECT_EQ(io.lockReleaseErrors, 1u);
    }
    EXPECT_EQ(io.lockReleaseErrors, 1u) << "Destructor must not retry uncertain checked release";
    io.dmaReleaseError = 0;
    device.reset();
    EXPECT_TRUE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(io.heldLocks.empty());
    EXPECT_TRUE(io.mappings.empty());
}

TEST_P(PcieDmaConnectionTest, DiagnosticProbeReportsDriverContentionAndNeverReleasesForeignOwner) {
    tt::umd::PciDeviceConnection observer(io.deviceNumber, tt::umd::PciDeviceConnectionMode::LockOnly);
    int acquired = 0;
    ASSERT_EQ(tt_lock_acquire(observer.get_handle(), DmaLockIndex, &acquired), 0);
    ASSERT_EQ(acquired, 1);
    const auto owner = tt::umd::LockManager::probe_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::Dma);
    ASSERT_TRUE(owner.has_value());
    EXPECT_EQ(owner->first, 0);
    EXPECT_EQ(owner->second, 0);
    int released = 0;
    ASSERT_EQ(tt_lock_release(observer.get_handle(), DmaLockIndex, &released), 0);
    EXPECT_EQ(released, 1);
    EXPECT_FALSE(tt::umd::LockManager::probe_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::Dma).has_value());
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, DiagnosticProbePropagatesReleaseFailureAndClosesItsOwnObserverOnly) {
    int observerFd = -1;
    {
        tt::umd::PciDeviceConnection observer(io.deviceNumber, tt::umd::PciDeviceConnectionMode::LockOnly);
        observerFd = io.opens.back().fd;
        io.dmaReleaseError = EIO;
        try {
            (void)tt::umd::LockManager::probe_pcie_resource(observer, tt::umd::PcieResourceLockKind::Dma);
            FAIL() << "Failed release cannot be reported FREE";
        } catch (const ConnectionException &failure) {
            EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
            EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockReleaseFailed);
            EXPECT_EQ(failure.error().data().error_code, EIO);
        }
        EXPECT_FALSE(observer.is_valid());
        EXPECT_FALSE(io.isClosed(observerFd));
        EXPECT_FALSE(io.isClosed(ordinaryFd));
    }
    io.dmaReleaseError = 0;
    EXPECT_TRUE(io.isClosed(observerFd));
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(device->get_pci_device()->get_connection().is_valid());
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, NumericPcieMemoryBarrierInitializationHasNoCompatibilityFallback) {
    const auto opens = io.opens.size();
    EXPECT_THROW(
        tt::umd::LockManager::initialize_mutex(
            tt::umd::MutexType::MEM_BARRIER, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.locks.empty());
}

TEST_P(PcieDmaConnectionTest, NumericPcieMemoryBarrierAcquisitionHasNoCompatibilityFallback) {
    const auto opens = io.opens.size();
    EXPECT_THROW(
        (void)tt::umd::LockManager::acquire_mutex(
            tt::umd::MutexType::MEM_BARRIER, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.locks.empty());
}

TEST_P(PcieDmaConnectionTest, NumericPcieMemoryBarrierProbeHasNoCompatibilityFallback) {
    const auto opens = io.opens.size();
    EXPECT_THROW(
        (void)tt::umd::LockManager::probe_mutex(
            tt::umd::MutexType::MEM_BARRIER, io.deviceNumber, tt::umd::IODeviceType::PCIe),
        RuntimeException);
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.locks.empty());
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierGuardCheckedUnlockPublishesExactReleaseFailureAndRetainsOtherIndex) {
    auto &connection = device->get_pci_device()->get_connection();
    auto *const handle = connection.get_handle();
    int acquired = 0;
    ASSERT_EQ(tt_lock_acquire(handle, 33, &acquired), 0);
    ASSERT_EQ(acquired, 1);
    auto guard = tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::MemoryBarrier);
    io.memoryBarrierReleaseError = EIO;
    try {
        guard.unlock();
        FAIL() << "Checked release must report its original driver failure";
    } catch (const ConnectionException &failure) {
        EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
        EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockReleaseFailed);
        EXPECT_EQ(failure.error().data().error_code, EIO);
    }
    ASSERT_EQ(io.memoryBarrierReleaseErrors, 1u);
    EXPECT_FALSE(connection.is_valid());
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    EXPECT_EQ(io.heldLocks.at(33), ordinaryFd);
    const auto lockCount = io.locks.size();
    io.memoryBarrierReleaseError = 0;
    EXPECT_THROW((void)tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::MemoryBarrier), ConnectionException);
    EXPECT_EQ(io.locks.size(), lockCount);
    int released = 0;
    ASSERT_EQ(tt_lock_release(handle, 33, &released), 0);
    EXPECT_EQ(released, 1);
    device.reset();
    EXPECT_FALSE(io.isClosed(ordinaryFd)) << "The live guard still retains only the original handle";
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierGuardAcquisitionPreservesExactFirstFailureIdentity) {
    auto &connection = device->get_pci_device()->get_connection();
    io.memoryBarrierAcquireError = ENODEV;
    const auto opens = io.opens.size();
    try {
        (void)tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::MemoryBarrier);
        FAIL() << "The original driver failure must be surfaced";
    } catch (const ConnectionException &failure) {
        EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
        EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockAcquireFailed);
        EXPECT_EQ(failure.error().data().error_code, ENODEV);
    }
    ASSERT_EQ(io.memoryBarrierAcquireErrors, 1u);
    io.memoryBarrierAcquireError = EIO;
    try {
        (void)connection.get_handle();
        FAIL() << "Quarantined ordinary access must fail";
    } catch (const ConnectionException &failure) {
        EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockAcquireFailed);
        EXPECT_EQ(failure.error().data().error_code, ENODEV);
    }
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_FALSE(io.isClosed(ordinaryFd));
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierGuardMoveOutlivesDeviceWithoutRetainingMappingsOrRegistryConnection) {
    std::optional<tt::umd::PcieResourceLock> moved;
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::MemoryBarrier);
        moved.emplace(std::move(guard));
        device.reset();
        EXPECT_TRUE(io.mappings.empty());
        EXPECT_FALSE(io.isClosed(ordinaryFd));
        ASSERT_EQ(io.heldLocks.at(MemoryBarrierLockIndex), ordinaryFd);
    }
    ASSERT_EQ(io.locks.size(), 1u) << "Moved-from destructor must not release the transferred guard";
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    moved.reset();
    ASSERT_EQ(io.locks.size(), 2u);
    EXPECT_EQ(io.locks.back().fd, ordinaryFd);
    EXPECT_EQ(io.locks.back().flags, TENSTORRENT_LOCK_CTL_RELEASE);
    EXPECT_TRUE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierRegistryDoesNotKeepOriginalConnectionAfterSuccessfulGuardDies) {
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::MemoryBarrier);
        guard.unlock();
    }
    device.reset();
    EXPECT_TRUE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(io.mappings.empty());
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierSuccessfulGuardReleaseDoesNotReleaseAnotherIndexOnSameHandle) {
    auto &connection = device->get_pci_device()->get_connection();
    auto *const handle = connection.get_handle();
    int acquired = 0;
    ASSERT_EQ(tt_lock_acquire(handle, 33, &acquired), 0);
    ASSERT_EQ(acquired, 1);
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::MemoryBarrier);
        guard.unlock();
    }
    EXPECT_EQ(io.heldLocks.count(MemoryBarrierLockIndex), 0u);
    EXPECT_EQ(io.heldLocks.at(33), ordinaryFd);
    EXPECT_TRUE(connection.is_valid());
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    int released = 0;
    ASSERT_EQ(tt_lock_release(handle, 33, &released), 0);
    EXPECT_EQ(released, 1);
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierLockOnlyObserverUsesExplicitAppendConnectionAndClosesAfterProbe) {
    const auto opens = io.opens.size();
    int observerFd = -1;
    {
        tt::umd::PciDeviceConnection observer(io.deviceNumber, tt::umd::PciDeviceConnectionMode::LockOnly);
        ASSERT_EQ(io.opens.size(), opens + 1);
        observerFd = io.opens.back().fd;
        EXPECT_NE(io.openFlags(observerFd) & O_APPEND, 0);
        EXPECT_FALSE(tt::umd::LockManager::probe_pcie_resource(observer, tt::umd::PcieResourceLockKind::MemoryBarrier).has_value());
        ASSERT_EQ(io.locks.size(), 2u);
        EXPECT_EQ(io.locks[0].fd, observerFd);
        EXPECT_EQ(io.locks[1].fd, observerFd);
        EXPECT_EQ(io.locks[0].index, MemoryBarrierLockIndex);
        EXPECT_EQ(io.locks[1].index, MemoryBarrierLockIndex);
    }
    EXPECT_TRUE(io.isClosed(observerFd));
    EXPECT_FALSE(io.isClosed(ordinaryFd));
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierProbeRecognizesExistingRobustOnlyParticipantWithoutDriverAcquire) {
    tt::umd::RobustMutex oldParticipant("MEM_BARRIER_" + std::to_string(io.deviceNumber) + "_PCIe");
    oldParticipant.initialize();
    oldParticipant.lock();
    const auto owner = tt::umd::LockManager::probe_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::MemoryBarrier);
    EXPECT_TRUE(owner.has_value());
    if (owner) {
        EXPECT_EQ(owner->first, getpid());
    }
    EXPECT_TRUE(io.locks.empty());
    oldParticipant.unlock();
    EXPECT_FALSE(tt::umd::LockManager::probe_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::MemoryBarrier).has_value());
    ASSERT_EQ(io.locks.size(), 2u);
    EXPECT_EQ(io.locks[0].fd, ordinaryFd);
    EXPECT_EQ(io.locks[1].fd, ordinaryFd);
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierTwoThreadsShareTheExistingRobustParticipantBeforeDriverLock) {
    tt::umd::RobustMutex oldParticipant("MEM_BARRIER_" + std::to_string(io.deviceNumber) + "_PCIe");
    oldParticipant.initialize();
    oldParticipant.lock();
    std::atomic<bool> entered{false};
    std::atomic<bool> acquired{false};
    std::exception_ptr failure;
    std::thread contender([&] {
        entered.store(true, std::memory_order_release);
        try {
            auto guard = tt::umd::LockManager::acquire_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::MemoryBarrier);
            acquired.store(true, std::memory_order_release);
            guard.unlock();
        } catch (...) {
            failure = std::current_exception();
        }
    });
    while (!entered.load(std::memory_order_acquire))
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(acquired.load(std::memory_order_acquire));
    oldParticipant.unlock();
    contender.join();
    EXPECT_EQ(failure, nullptr);
    EXPECT_TRUE(acquired.load(std::memory_order_acquire));
    ASSERT_EQ(io.locks.size(), 2u);
    EXPECT_EQ(io.locks[0].fd, ordinaryFd);
    EXPECT_EQ(io.locks[1].fd, ordinaryFd);
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierCheckedUnlockDeviceResetRetainsExactFailureAndNeverReopens) {
    auto &connection = device->get_pci_device()->get_connection();
    const auto opens = io.opens.size();
    {
        auto guard = tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::MemoryBarrier);
        io.memoryBarrierReleaseError = ENODEV;
        try {
            guard.unlock();
            FAIL() << "Checked unlock must report ENODEV";
        } catch (const ConnectionException &failure) {
            EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
            EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockReleaseFailed);
            EXPECT_EQ(failure.error().data().error_code, ENODEV);
        }
        EXPECT_FALSE(io.isClosed(ordinaryFd));
        EXPECT_EQ(io.opens.size(), opens);
        EXPECT_EQ(io.memoryBarrierReleaseErrors, 1u);
    }
    EXPECT_EQ(io.memoryBarrierReleaseErrors, 1u) << "Destructor must not retry uncertain checked release";
    io.memoryBarrierReleaseError = 0;
    device.reset();
    EXPECT_TRUE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(io.heldLocks.empty());
    EXPECT_TRUE(io.mappings.empty());
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierDiagnosticProbeReportsDriverContentionAndNeverReleasesForeignOwner) {
    tt::umd::PciDeviceConnection observer(io.deviceNumber, tt::umd::PciDeviceConnectionMode::LockOnly);
    int acquired = 0;
    ASSERT_EQ(tt_lock_acquire(observer.get_handle(), MemoryBarrierLockIndex, &acquired), 0);
    ASSERT_EQ(acquired, 1);
    const auto owner = tt::umd::LockManager::probe_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::MemoryBarrier);
    ASSERT_TRUE(owner.has_value());
    EXPECT_EQ(owner->first, 0);
    EXPECT_EQ(owner->second, 0);
    int released = 0;
    ASSERT_EQ(tt_lock_release(observer.get_handle(), MemoryBarrierLockIndex, &released), 0);
    EXPECT_EQ(released, 1);
    EXPECT_FALSE(tt::umd::LockManager::probe_pcie_resource(device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::MemoryBarrier).has_value());
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierDiagnosticProbePropagatesReleaseFailureAndClosesItsOwnObserverOnly) {
    int observerFd = -1;
    {
        tt::umd::PciDeviceConnection observer(io.deviceNumber, tt::umd::PciDeviceConnectionMode::LockOnly);
        observerFd = io.opens.back().fd;
        io.memoryBarrierReleaseError = EIO;
        try {
            (void)tt::umd::LockManager::probe_pcie_resource(observer, tt::umd::PcieResourceLockKind::MemoryBarrier);
            FAIL() << "Failed release cannot be reported FREE";
        } catch (const ConnectionException &failure) {
            EXPECT_EQ(failure.error().data().device_num, io.deviceNumber);
            EXPECT_EQ(failure.error().data().status, tt::umd::PciDeviceConnectionStatus::LockReleaseFailed);
            EXPECT_EQ(failure.error().data().error_code, EIO);
        }
        EXPECT_FALSE(observer.is_valid());
        EXPECT_FALSE(io.isClosed(observerFd));
        EXPECT_FALSE(io.isClosed(ordinaryFd));
    }
    io.memoryBarrierReleaseError = 0;
    EXPECT_TRUE(io.isClosed(observerFd));
    EXPECT_FALSE(io.isClosed(ordinaryFd));
    EXPECT_TRUE(device->get_pci_device()->get_connection().is_valid());
    EXPECT_TRUE(io.heldLocks.empty());
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierAndDmaGuardsUseSeparateIndicesOnOneRetainedOwner) {
    auto &connection = device->get_pci_device()->get_connection();
    const auto opens = io.opens.size();
    {
        auto dma = tt::umd::LockManager::acquire_pcie_resource(connection, tt::umd::PcieResourceLockKind::Dma);
        auto barrier = tt::umd::LockManager::acquire_pcie_resource(
            connection, tt::umd::PcieResourceLockKind::MemoryBarrier);
        EXPECT_EQ(io.heldLocks.at(DmaLockIndex), ordinaryFd);
        EXPECT_EQ(io.heldLocks.at(MemoryBarrierLockIndex), ordinaryFd);
        barrier.unlock();
        EXPECT_EQ(io.heldLocks.count(MemoryBarrierLockIndex), 0u);
        EXPECT_EQ(io.heldLocks.at(DmaLockIndex), ordinaryFd);
        dma.unlock();
    }
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.heldLocks.empty());
    EXPECT_TRUE(connection.is_valid());
    ASSERT_EQ(io.locks.size(), 4u);
    for (const auto &request : io.locks)
        EXPECT_EQ(request.fd, ordinaryFd);
    EXPECT_EQ(io.locks[0].index, DmaLockIndex);
    EXPECT_EQ(io.locks[1].index, MemoryBarrierLockIndex);
    EXPECT_EQ(io.locks[2].index, MemoryBarrierLockIndex);
    EXPECT_EQ(io.locks[3].index, DmaLockIndex);
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierUnwindReleaseFailuresPreserveOriginalExceptionWithoutReopen) {
    for (int errorCode : {EIO, ENODEV}) {
        SCOPED_TRACE(errorCode);
        EXPECT_EXIT(
            {
                const auto opens = io.opens.size();
                bool originalException = false;
                io.memoryBarrierReleaseError = errorCode;
                try {
                    auto guard = tt::umd::LockManager::acquire_pcie_resource(
                        device->get_pci_device()->get_connection(), tt::umd::PcieResourceLockKind::MemoryBarrier);
                    throw std::runtime_error("original barrier body failure");
                } catch (const std::runtime_error &failure) {
                    originalException = std::string_view(failure.what()) == "original barrier body failure";
                } catch (...) {
                    _exit(10);
                }
                io.memoryBarrierReleaseError = 0;
                if (!originalException || io.memoryBarrierReleaseErrors != 1 || io.locks.size() != 2 ||
                    io.opens.size() != opens || io.isClosed(ordinaryFd))
                    _exit(11);
                for (const auto &request : io.locks)
                    if (request.index != MemoryBarrierLockIndex || request.fd != ordinaryFd)
                        _exit(12);
                auto &connection = device->get_pci_device()->get_connection();
                try {
                    (void)connection.get_handle();
                    _exit(13);
                } catch (const ConnectionException &failure) {
                    if (failure.error().data().status != tt::umd::PciDeviceConnectionStatus::LockReleaseFailed ||
                        failure.error().data().error_code != errorCode)
                        _exit(14);
                } catch (...) {
                    _exit(15);
                }
                device.reset();
                if (!io.isClosed(ordinaryFd) || !io.mappings.empty() || !io.liveTlbs.empty() || !io.heldLocks.empty() ||
                    io.operationsAfterClose != 0 || io.duplicateCloses != 0)
                    _exit(16);
                _exit(0);
            },
            ::testing::ExitedWithCode(0),
            ".*");
    }
}

TEST_P(PcieDmaConnectionTest, MemoryBarrierJtagNumericOwnerRetainsRobustOnlyBehavior) {
    const auto opens = io.opens.size();
    const auto name = "MEM_BARRIER_" + std::to_string(io.deviceNumber) + "_JTAG";
    tt::umd::LockManager::initialize_mutex(
        tt::umd::MutexType::MEM_BARRIER, io.deviceNumber, tt::umd::IODeviceType::JTAG);
    tt::umd::RobustMutex oldParticipant(name);
    oldParticipant.initialize();
    {
        auto guard = tt::umd::LockManager::acquire_mutex(
            tt::umd::MutexType::MEM_BARRIER, io.deviceNumber, tt::umd::IODeviceType::JTAG);
        const auto owner = oldParticipant.probe_lock(std::chrono::seconds(0));
        ASSERT_TRUE(owner.has_value());
        EXPECT_EQ(owner->first, getpid());
    }
    EXPECT_FALSE(tt::umd::LockManager::probe_mutex(
                     tt::umd::MutexType::MEM_BARRIER, io.deviceNumber, tt::umd::IODeviceType::JTAG)
                     .has_value());
    EXPECT_EQ(io.opens.size(), opens);
    EXPECT_TRUE(io.locks.empty());
    shm_unlink(("/TT_UMD_LOCK." + name).c_str());
}

INSTANTIATE_TEST_SUITE_P(
    PublicEntrypoints,
    PcieDmaConnectionTest,
    ::testing::Values(
        DmaEntry::Write, DmaEntry::Read, DmaEntry::WriteCoreRange, DmaEntry::ReadZeroCopy, DmaEntry::WriteZeroCopy),
    [](const ::testing::TestParamInfo<DmaEntry> &info) {
        switch (info.param) {
        case DmaEntry::Write:
            return "Write";
        case DmaEntry::Read:
            return "Read";
        case DmaEntry::WriteCoreRange:
            return "WriteCoreRange";
        case DmaEntry::ReadZeroCopy:
            return "ReadZeroCopy";
        case DmaEntry::WriteZeroCopy:
            return "WriteZeroCopy";
        }
        return "Unknown";
    });

}  // namespace

extern "C" __attribute__((visibility("default"))) FILE *fopen(const char *path, const char *mode) {
    if (const auto fd = interceptedOpen(path)) {
        if (*fd == -1)
            return nullptr;
        FILE *file = fdopen(*fd, mode);
        if (file == nullptr) {
            const int error = errno;
            close(*fd);
            errno = error;
        }
        return file;
    }
    using OpenFile = FILE *(*)(const char *, const char *);
    static const auto realFopen = reinterpret_cast<OpenFile>(dlsym(RTLD_NEXT, "fopen"));
    return realFopen(path, mode);
}

extern "C" __attribute__((visibility("default"))) FILE *fopen64(const char *path, const char *mode) {
    if (const auto fd = interceptedOpen(path)) {
        if (*fd == -1)
            return nullptr;
        FILE *file = fdopen(*fd, mode);
        if (file == nullptr) {
            const int error = errno;
            close(*fd);
            errno = error;
        }
        return file;
    }
    using OpenFile = FILE *(*)(const char *, const char *);
    static const auto realFopen = reinterpret_cast<OpenFile>(dlsym(RTLD_NEXT, "fopen64"));
    return realFopen(path, mode);
}

extern "C" __attribute__((visibility("default"))) int open(const char *path, int flags, ...) {
    if (const auto fd = interceptedOpen(path, flags))
        return *fd;
    va_list arguments;
    va_start(arguments, flags);
    const mode_t mode = hasMode(flags) ? va_arg(arguments, mode_t) : 0;
    va_end(arguments);
    return rawOpenAt(AT_FDCWD, path, flags, mode);
}

extern "C" __attribute__((visibility("default"))) int open64(const char *path, int flags, ...) {
    if (const auto fd = interceptedOpen(path, flags))
        return *fd;
    va_list arguments;
    va_start(arguments, flags);
    const mode_t mode = hasMode(flags) ? va_arg(arguments, mode_t) : 0;
    va_end(arguments);
    return rawOpenAt(AT_FDCWD, path, flags, mode);
}

extern "C" __attribute__((visibility("default"))) int __open_2(const char *path, int flags) {
    if (const auto fd = interceptedOpen(path, flags))
        return *fd;
    return rawOpenAt(AT_FDCWD, path, flags, 0);
}

extern "C" __attribute__((visibility("default"))) int __open64_2(const char *path, int flags) {
    if (const auto fd = interceptedOpen(path, flags))
        return *fd;
    return rawOpenAt(AT_FDCWD, path, flags, 0);
}

extern "C" __attribute__((visibility("default"))) int __openat_2(int directory, const char *path, int flags) {
    if (const auto fd = interceptedOpen(path, flags))
        return *fd;
    return rawOpenAt(directory, path, flags, 0);
}

extern "C" __attribute__((visibility("default"))) int __openat64_2(int directory, const char *path, int flags) {
    if (const auto fd = interceptedOpen(path, flags))
        return *fd;
    return rawOpenAt(directory, path, flags, 0);
}

extern "C" __attribute__((visibility("default"))) int openat(int directory, const char *path, int flags, ...) {
    if (const auto fd = interceptedOpen(path, flags))
        return *fd;
    va_list arguments;
    va_start(arguments, flags);
    const mode_t mode = hasMode(flags) ? va_arg(arguments, mode_t) : 0;
    va_end(arguments);
    return rawOpenAt(directory, path, flags, mode);
}

extern "C" __attribute__((visibility("default"))) int openat64(int directory, const char *path, int flags, ...) {
    if (const auto fd = interceptedOpen(path, flags))
        return *fd;
    va_list arguments;
    va_start(arguments, flags);
    const mode_t mode = hasMode(flags) ? va_arg(arguments, mode_t) : 0;
    va_end(arguments);
    return rawOpenAt(directory, path, flags, mode);
}

extern "C" __attribute__((visibility("default"))) int close(int fd) {
    if (!fixtureActive || !io.isDeviceFd(fd))
        return static_cast<int>(syscall(SYS_close, fd));
    if (io.isClosed(fd))
        ++io.duplicateCloses;
    io.closedFds.push_back(fd);
    io.closeEvents.emplace(fd, ++io.nextRetirementEvent);
    for (auto held = io.heldLocks.begin(); held != io.heldLocks.end();) {
        if (held->second == fd)
            held = io.heldLocks.erase(held);
        else
            ++held;
    }
    return 0;
}

extern "C" __attribute__((visibility("default"))) int ioctl(int fd, unsigned long request, ...) noexcept {
    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    if (!fixtureActive || !io.isDeviceFd(fd))
        return static_cast<int>(syscall(SYS_ioctl, fd, request, argument));
    if (io.isClosed(fd)) {
        ++io.operationsAfterClose;
        errno = EBADF;
        return -1;
    }
    switch (request) {
    case TENSTORRENT_IOCTL_SET_POWER_STATE: {
        const auto *power = static_cast<tenstorrent_power_state *>(argument);
        EXPECT_EQ(power->argsz, sizeof(*power));
        EXPECT_EQ(power->flags, 0u);
        io.powerRequests.emplace_back(fd, power->power_flags);
        return 0;
    }
    case TENSTORRENT_IOCTL_GET_DEVICE_INFO: {
        ++io.deviceInfoQueries;
        io.queryFds.push_back(fd);
        auto *info = static_cast<tenstorrent_get_device_info *>(argument);
        info->out.output_size_bytes = sizeof(info->out);
        info->out.vendor_id = 0x1e52;
        info->out.device_id = TT_BLACKHOLE_PCI_DEVICE_ID;
        info->out.subsystem_vendor_id = 0x1e52;
        info->out.subsystem_id = 0;
        info->out.bus_dev_fn = static_cast<uint16_t>((1u << 8) | (2u << 3));
        info->out.pci_domain = 0;
        return 0;
    }
    case TENSTORRENT_IOCTL_GET_DRIVER_INFO: {
        ++io.driverInfoQueries;
        io.queryFds.push_back(fd);
        auto *info = static_cast<tenstorrent_get_driver_info *>(argument);
        info->out.output_size_bytes = sizeof(info->out);
        info->out.driver_version = TENSTORRENT_DRIVER_VERSION;
        info->out.driver_version_major = 2;
        info->out.driver_version_minor = 10;
        info->out.driver_version_patch = 0;
        return 0;
    }
    case TENSTORRENT_IOCTL_QUERY_MAPPINGS: {
        ++io.mappingQueries;
        io.queryFds.push_back(fd);
        auto *query = static_cast<tenstorrent_query_mappings *>(argument);
        query->in.output_mapping_count = 2;
        auto *mappings = query->out.mappings;
        std::memset(mappings, 0, 2 * sizeof(*mappings));
        mappings[0].mapping_id = TENSTORRENT_MAPPING_RESOURCE0_UC;
        mappings[0].mapping_base = 0;
        mappings[0].mapping_size = 3 * 1024 * 1024;
        mappings[1].mapping_id = TENSTORRENT_MAPPING_RESOURCE1_UC;
        mappings[1].mapping_base = 0x400000;
        mappings[1].mapping_size = 3 * 1024 * 1024;
        return 0;
    }
    case TENSTORRENT_IOCTL_ALLOCATE_DMA_BUF: {
        ++io.dmaAllocations;
        auto *allocation = static_cast<tenstorrent_allocate_dma_buf *>(argument);
        allocation->out.mapping_offset = 0x10000000;
        allocation->out.physical_address = 0x12340000;
        allocation->out.size = allocation->in.requested_size;
        return 0;
    }
    case TENSTORRENT_IOCTL_ALLOCATE_TLB: {
        ++io.tlbAllocations;
        auto *allocation = static_cast<tenstorrent_allocate_tlb *>(argument);
        EXPECT_EQ(allocation->in.size, 2 * 1024 * 1024u);
        allocation->out.id = io.nextTlbId++;
        EXPECT_TRUE(io.liveTlbs.emplace(allocation->out.id, fd).second);
        allocation->out.mmap_offset_uc = 0x20000000 + allocation->out.id * 0x200000;
        allocation->out.mmap_offset_wc = 0x30000000 + allocation->out.id * 0x200000;
        return 0;
    }
    case TENSTORRENT_IOCTL_PIN_PAGES: {
        ++io.pinOperations;
        auto *pin = static_cast<tenstorrent_pin_pages_in *>(argument);
        EXPECT_TRUE(io.pinnedBuffers.emplace(pin->virtual_address, std::pair{pin->size, fd}).second);
        auto *output = reinterpret_cast<tenstorrent_pin_pages_out_extended *>(pin + 1);
        output->physical_address = 0x23450000;
        output->noc_address = 0x34560000;
        return 0;
    }
    case TENSTORRENT_IOCTL_UNPIN_PAGES: {
        ++io.unpinOperations;
        const auto *unpin = static_cast<tenstorrent_unpin_pages *>(argument);
        const auto pin = io.pinnedBuffers.find(unpin->in.virtual_address);
        EXPECT_NE(pin, io.pinnedBuffers.end());
        if (pin != io.pinnedBuffers.end()) {
            EXPECT_EQ(pin->second.first, unpin->in.size);
            EXPECT_EQ(pin->second.second, fd);
            io.pinnedBuffers.erase(pin);
        }
        return 0;
    }
    case TENSTORRENT_IOCTL_FREE_TLB: {
        ++io.tlbFrees;
        const auto *release = static_cast<tenstorrent_free_tlb *>(argument);
        const auto tlb = io.liveTlbs.find(release->in.id);
        EXPECT_NE(tlb, io.liveTlbs.end());
        if (tlb != io.liveTlbs.end()) {
            EXPECT_EQ(tlb->second, fd);
            io.liveTlbs.erase(tlb);
        }
        return 0;
    }
    case TENSTORRENT_IOCTL_LOCK_CTL: {
        auto *lock = static_cast<tenstorrent_lock_ctl *>(argument);
        EXPECT_EQ(lock->in.output_size_bytes, sizeof(lock->out));
        io.locks.push_back({fd, lock->in.index, lock->in.flags});
        if (lock->in.index == ArcLockIndex && lock->in.flags == TENSTORRENT_LOCK_CTL_ACQUIRE &&
            io.rejectArcLockAcquire) {
            ++io.arcAcquireErrors;
            errno = io.arcAcquireError;
            return -1;
        }
        if (lock->in.index == ArcLockIndex && lock->in.flags == TENSTORRENT_LOCK_CTL_RELEASE &&
            io.arcReleaseError != 0) {
            ++io.arcReleaseErrors;
            errno = io.arcReleaseError;
            return -1;
        }
        if (lock->in.index == DmaLockIndex && lock->in.flags == TENSTORRENT_LOCK_CTL_ACQUIRE &&
            io.rejectDmaLockAcquire) {
            ++io.lockAcquireErrors;
            errno = io.dmaAcquireError;
            return -1;
        }
        if (lock->in.index == DmaLockIndex && lock->in.flags == TENSTORRENT_LOCK_CTL_RELEASE &&
            io.dmaReleaseError != 0) {
            ++io.lockReleaseErrors;
            errno = io.dmaReleaseError;
            return -1;
        }
        if (lock->in.index == 20u && lock->in.flags == TENSTORRENT_LOCK_CTL_ACQUIRE &&
            io.rejectChipInUseLockAcquire) {
            ++io.chipInUseAcquireErrors;
            errno = io.chipInUseAcquireError;
            return -1;
        }
        if (lock->in.index == 20u && lock->in.flags == TENSTORRENT_LOCK_CTL_RELEASE &&
            io.chipInUseReleaseError != 0) {
            ++io.chipInUseReleaseErrors;
            errno = io.chipInUseReleaseError;
            return -1;
        }
        if (lock->in.index == MemoryBarrierLockIndex && lock->in.flags == TENSTORRENT_LOCK_CTL_ACQUIRE &&
            io.memoryBarrierAcquireError != 0) {
            ++io.memoryBarrierAcquireErrors;
            errno = io.memoryBarrierAcquireError;
            return -1;
        }
        if (lock->in.index == MemoryBarrierLockIndex && lock->in.flags == TENSTORRENT_LOCK_CTL_RELEASE) {
            if (io.observeMemoryBarrier) {
                MemoryBarrierRelease release{fd, {false, false, false}};
                for (const auto &mapping : io.mappings) {
                    if (mapping.second.size != 2 * 1024 * 1024)
                        continue;
                    for (size_t index = 0; index < MemoryBarrierAddresses.size(); ++index) {
                        uint32_t value = 0;
                        std::memcpy(&value, static_cast<const uint8_t *>(mapping.first) + MemoryBarrierAddresses[index],
                                    sizeof(value));
                        release.resetReadback[index] |= value == tt::umd::MemBarFlag::RESET;
                    }
                }
                io.memoryBarrierReleases.push_back(release);
            }
            if (io.memoryBarrierReleaseError != 0) {
                ++io.memoryBarrierReleaseErrors;
                errno = io.memoryBarrierReleaseError;
                return -1;
            }
        }
        const auto held = io.heldLocks.find(lock->in.index);
        switch (lock->in.flags) {
        case TENSTORRENT_LOCK_CTL_ACQUIRE:
            lock->out.value = held == io.heldLocks.end() ? 1 : 0;
            if (lock->out.value != 0)
                io.heldLocks.emplace(lock->in.index, fd);
            return 0;
        case TENSTORRENT_LOCK_CTL_RELEASE:
            lock->out.value = held != io.heldLocks.end() && held->second == fd ? 1 : 0;
            if (lock->out.value != 0)
                io.heldLocks.erase(held);
            return 0;
        case TENSTORRENT_LOCK_CTL_TEST:
            lock->out.value = held == io.heldLocks.end() ? 0 : 2 | (held->second == fd ? 1 : 0);
            return 0;
        default:
            errno = EINVAL;
            return -1;
        }
    }
    default:
        ++io.unknownIoctls;
        errno = ENOTTY;
        return -1;
    }
}

extern "C" __attribute__((visibility("default"))) void *mmap(
    void *address, size_t length, int protection, int flags, int fd, off_t offset) noexcept {
    if (!fixtureActive || !io.isDeviceFd(fd))
        return reinterpret_cast<void *>(syscall(SYS_mmap, address, length, protection, flags, fd, offset));
    if (io.isClosed(fd)) {
        ++io.operationsAfterClose;
        errno = EBADF;
        return MAP_FAILED;
    }
    io.mmapFds.push_back(fd);
    void *mapping = reinterpret_cast<void *>(syscall(
        SYS_mmap, address, length, protection, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    if (mapping != MAP_FAILED) {
        io.mappings.emplace(mapping, Mapping{length, fd});
        populateFirmwareWindow(mapping, length);
    }
    return mapping;
}

extern "C" __attribute__((visibility("default"))) int munmap(void *address, size_t length) noexcept {
    if (fixtureActive) {
        const auto mapping = io.mappings.find(address);
        if (mapping != io.mappings.end()) {
            io.lastUnmapEvent = ++io.nextRetirementEvent;
            EXPECT_EQ(length, mapping->second.size);
            if (address == io.iatuCleanupMapping)
                io.retiredIatuControl = *reinterpret_cast<const uint32_t *>(static_cast<uint8_t *>(address) + 0x1004);
            if (io.isClosed(mapping->second.fd))
                ++io.operationsAfterClose;
            io.mappings.erase(mapping);
        }
    }
    return static_cast<int>(syscall(SYS_munmap, address, length));
}
