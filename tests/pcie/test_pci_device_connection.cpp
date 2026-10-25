// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Run the real PCIDevice constructor through the linked tt-umd DSO. The ELF
// syscall boundary below is interposed by the executable, so this never opens
// a physical device. Attribute queries, BAR mappings and DMA setup still use
// production PCIDevice and tt-kmd-lib code.
//
// COVERS: UMD-PCIE-CONNECTION-001 one_open_file_description
// COVERS: UMD-PCIE-CONNECTION-001 constructor_failure_release_order

#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "tt-kmd-lib/pci_ids.h"
#include "tt-kmd-lib/tt_kmd_lib.h"
#include "umd/device/arch/blackhole_implementation.hpp"
#include "umd/device/chip/local_chip.hpp"
#include "umd/device/pcie/pci_device.hpp"
#include "umd/device/topology/topology_discovery.hpp"
#include "umd/device/tt_device/protocol/pcie_protocol.hpp"

// ioctl.h owns legacy macro names which overlap public UMD enums.
#include "ioctl.h"

namespace {

constexpr std::string_view DevicePath = "/dev/tenstorrent/42";
constexpr std::string_view SecondDevicePath = "/dev/tenstorrent/43";
constexpr std::string_view DeviceSysfsPath = "/sys/bus/pci/devices/0000:01:02.0/";
constexpr std::string_view SecondDeviceSysfsPath = "/sys/bus/pci/devices/0000:02:02.0/";
constexpr int FirstDeviceFd = 700;
constexpr size_t BarSize = 3 * 1024 * 1024;
constexpr off_t Bar0Offset = 509 * 1024 * 1024;
constexpr off_t TlbOffset = 0x1fc00000;
constexpr off_t Bar2Offset = 0x400000;
constexpr off_t DmaOffset = 0x10000000;

struct Mapping {
    size_t size;
};

struct MapRequest {
    size_t size;
    off_t offset;
    int protection;
    int flags;
};

struct IoState {
    unsigned deviceOpens = 0;
    unsigned deviceCloses = 0;
    unsigned deviceMmapAttempts = 0;
    unsigned deviceMappings = 0;
    unsigned deviceMunmaps = 0;
    unsigned deviceInfoQueries = 0;
    unsigned driverInfoQueries = 0;
    unsigned barQueries = 0;
    unsigned dmaAllocations = 0;
    unsigned tlbAllocations = 0;
    unsigned tlbFrees = 0;
    void *tlbMapping = nullptr;
    unsigned tlbMunmapEvent = 0;
    unsigned tlbFreeEvent = 0;
    unsigned unexpectedDeviceOpens = 0;
    unsigned operationsAfterClose = 0;
    unsigned duplicateCloses = 0;
    bool iommuEnabled = false;
    unsigned pins = 0;
    unsigned unpins = 0;
    void *iommuMapping = nullptr;
    size_t iommuMappingSize = 0;
    unsigned pinEvent = 0;
    unsigned unpinEvent = 0;
    unsigned iommuMunmapEvent = 0;
    void *sysmemMapping = nullptr;
    unsigned sysmemMunmapEvent = 0;
    unsigned powerStateRequests = 0;
    bool rejectChipInfo = false;
    unsigned nextEvent = 0;
    unsigned failMmapAttempt = 0;
    unsigned long failIoctlRequest = 0;
    bool failDeviceOpen = false;
    bool discoveryActive = false;
    bool changeSelectedIdentity = false;
    bool reverseBdfOrder = false;
    unsigned discoveryDirectoryOpens = 0;
    std::string discoveryDirectory;
    int closeError = 0;
    int nextDeviceFd = FirstDeviceFd;
    std::vector<int> deviceFds;
    std::unordered_map<int, int> deviceNumbers;
    std::unordered_map<int, int> deviceOpenFlags;
    std::vector<int> ioctlFds;
    std::vector<int> tlbAllocationFds;
    std::vector<int> mmapFds;
    std::vector<int> closedFds;
    std::vector<MapRequest> mapRequests;
    std::vector<std::string_view> sysfsReads;
    std::vector<unsigned> munmapEvents;
    std::vector<unsigned> closeEvents;
    std::unordered_map<void *, Mapping> mappings;

    bool isDeviceFd(int fd) const { return fd >= FirstDeviceFd && fd < nextDeviceFd; }

    bool isClosed(int fd) const {
        for (const int closed : closedFds)
            if (closed == fd)
                return true;
        return false;
    }

    unsigned event() { return ++nextEvent; }

    void releaseRemainingMappings() {
        for (const auto &mapping : mappings)
            syscall(SYS_munmap, mapping.first, mapping.second.size);
        mappings.clear();
    }
};

IoState io;
bool fixtureActive = false;

// Keep the real PCIDevice, PcieProtocol, TTDevice and LocalChip lifetime chain.
// Only the firmware boundary rejects the constructor's first power request,
// after LocalChip has adopted the real TLB and sysmem managers.
class RejectingPowerFirmware final : public tt::umd::DeviceFirmware {
public:
    void init_firmware(std::chrono::milliseconds, tt::umd::NocId) override { unexpected(); }
    tt::umd::DeviceCommandResult send_device_command(
        uint32_t, const std::vector<uint32_t> &, std::chrono::milliseconds, tt::umd::NocId) override {
        unexpected();
    }
    void set_clock_state(tt::umd::ClockState, tt::umd::NocId) override { unexpected(); }
    void set_power_state(tt::umd::PowerState, tt::umd::NocId) override {
        ++io.powerStateRequests;
        throw std::runtime_error("test firmware rejected LocalChip power request");
    }
    bool get_noc_translation_enabled(tt::umd::NocId) override { unexpected(); }
    tt::ChipInfo get_chip_info(tt::umd::NocId) override {
        if (io.rejectChipInfo)
            throw std::runtime_error("test firmware rejected LocalChip identity query");
        return {};
    }
    tt_xy_pair get_firmware_noc_coord(tt::umd::NocId) const override { unexpected(); }
    bool wait_eth_core_training(tt_xy_pair, std::chrono::milliseconds, tt::umd::NocId) override {
        unexpected();
    }
    tt::umd::EthTrainingStatus get_eth_core_training_status(tt_xy_pair, tt::umd::NocId) override {
        unexpected();
    }
    bool wait_dram_channel_training(uint32_t, std::chrono::milliseconds, tt::umd::NocId) override { unexpected(); }

private:
    [[noreturn]] static void unexpected() { throw std::logic_error("unexpected test firmware operation"); }
};

class LocalChipFailureModel final : public tt::umd::TTDeviceModel {
public:
    explicit LocalChipFailureModel(std::unique_ptr<tt::umd::PCIDevice> pci_device) :
        protocol_(std::move(pci_device)) {}

    tt::umd::DeviceProtocol *get_device_protocol() override { return &protocol_; }
    tt::umd::PcieInterface *get_pcie_interface() override { return &protocol_; }
    tt::umd::PCIDevice *get_pci_device() override { return protocol_.get_pci_device(); }
    tt::umd::DeviceFirmware *get_device_firmware() override { return &firmware_; }
    tt::umd::ArchitectureImplementation *get_architecture_impl() override { return &architecture_; }
    tt::umd::SocArchDescriptor *get_soc_arch_descriptor() override { return nullptr; }
    std::shared_ptr<tt::umd::SocArchDescriptor> get_shared_soc_arch_descriptor() override { return nullptr; }

private:
    tt::umd::PcieProtocol protocol_;
    tt::umd::BlackholeImplementation architecture_;
    RejectingPowerFirmware firmware_;
};

class LocalChipFailureDevice final : public tt::umd::TTDevice {
public:
    explicit LocalChipFailureDevice(std::unique_ptr<tt::umd::PCIDevice> pci_device) :
        TTDevice(std::make_unique<LocalChipFailureModel>(std::move(pci_device))) {}
    void read_from_arc_apb(void *, uint64_t, size_t) override { throw std::logic_error("unexpected ARC read"); }
    void write_to_arc_apb(const void *, uint64_t, size_t) override { throw std::logic_error("unexpected ARC write"); }
    uint32_t get_clock() override { throw std::logic_error("unexpected clock query"); }
    uint32_t get_min_clock_freq() override { throw std::logic_error("unexpected minimum clock query"); }
};

// Exposes the existing protected acquisition phase without running firmware
// initialization or substituting the semantic TopologyDiscovery factory.
class TopologyDiscoveryAccess : public tt::umd::TopologyDiscovery {
public:
    using TopologyDiscovery::create_topology_discovery;
    using TopologyDiscovery::get_connected_devices;
};

bool hasMode(int flags) { return (flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE; }

bool isDevicePath(const char *path) {
    return path != nullptr &&
           (std::string_view(path) == DevicePath ||
            (io.discoveryActive && std::string_view(path) == SecondDevicePath));
}

bool isAnyDevicePath(const char *path) {
    return path != nullptr && std::string_view(path).substr(0, 16) == "/dev/tenstorrent";
}

std::optional<std::string_view> fakeSysfsContents(const char *path) {
    if (path == nullptr)
        return std::nullopt;
    const std::string_view value(path);
    if (value == "/sys/module/tenstorrent/version")
        return "2.10.0\n";
    const auto prefix = io.discoveryActive && value.substr(0, SecondDeviceSysfsPath.size()) == SecondDeviceSysfsPath
                            ? SecondDeviceSysfsPath
                            : DeviceSysfsPath;
    if (value.substr(0, prefix.size()) != prefix)
        return std::nullopt;
    const auto attribute = value.substr(prefix.size());
    if (attribute == "numa_node")
        return "-1\n";
    if (attribute == "revision")
        return "0\n";
    if (attribute == "iommu_group/type")
        return io.iommuEnabled ? "DMA\n" : "none\n";
    return std::nullopt;
}

int rawOpenAt(int directory, const char *path, int flags, mode_t mode) {
    return static_cast<int>(syscall(SYS_openat, directory, path, flags, mode));
}

int sysfsFile(std::string_view content) {
    const int fd = static_cast<int>(syscall(SYS_memfd_create, "trex-umd-sysfs", 0));
    if (fd == -1)
        return -1;
    const auto written = write(fd, content.data(), content.size());
    if (written != static_cast<ssize_t>(content.size()) || lseek(fd, 0, SEEK_SET) == -1) {
        const int error = errno;
        syscall(SYS_close, fd);
        errno = error;
        return -1;
    }
    return fd;
}

std::optional<int> interceptedOpen(const char *path, int flags = 0) {
    // libstdc++ directory_iterator uses open/openat followed by fdopendir.
    if (fixtureActive && io.discoveryActive && path != nullptr &&
        (std::string_view(path) == "/dev/tenstorrent" || std::string_view(path) == "/dev/tenstorrent/")) {
        ++io.discoveryDirectoryOpens;
        return rawOpenAt(AT_FDCWD, io.discoveryDirectory.c_str(), flags, 0);
    }
    if (fixtureActive && isDevicePath(path)) {
        ++io.deviceOpens;
        if (io.failDeviceOpen) {
            errno = EACCES;
            return -1;
        }
        const int fd = io.nextDeviceFd++;
        io.deviceFds.push_back(fd);
        io.deviceNumbers.emplace(fd, std::string_view(path) == SecondDevicePath ? 43 : 42);
        io.deviceOpenFlags.emplace(fd, flags);
        return fd;
    }
    if (isAnyDevicePath(path)) {
        if (fixtureActive)
            ++io.unexpectedDeviceOpens;
        errno = EPERM;
        return -1;
    }
    if (fixtureActive) {
        if (const auto contents = fakeSysfsContents(path)) {
            // The vector stores only these canonical constant paths.
            if (std::string_view(path) == "/sys/module/tenstorrent/version")
                io.sysfsReads.push_back("version");
            else
                io.sysfsReads.push_back(std::string_view(path).substr(DeviceSysfsPath.size()) == "numa_node"
                                            ? "numa_node"
                                            : std::string_view(path).substr(DeviceSysfsPath.size()) == "revision"
                                                  ? "revision"
                                                  : "iommu_group/type");
            return sysfsFile(*contents);
        }
    }
    return std::nullopt;
}

void fillDeviceInfo(tenstorrent_get_device_info *info, int fd) {
    info->out.output_size_bytes = sizeof(info->out);
    info->out.vendor_id = 0x1e52;
    info->out.device_id = TT_BLACKHOLE_PCI_DEVICE_ID;
    info->out.subsystem_vendor_id = 0x1e52;
    info->out.subsystem_id = 0;
    info->out.bus_dev_fn = static_cast<uint16_t>((1u << 8) | (2u << 3));
    info->out.pci_domain = 0;
    if (io.deviceNumbers.at(fd) == 43)
        info->out.bus_dev_fn = static_cast<uint16_t>((2u << 8) | (2u << 3));
    if (io.reverseBdfOrder) {
        const unsigned bus = io.deviceNumbers.at(fd) == 42 ? 2 : 1;
        info->out.bus_dev_fn = static_cast<uint16_t>((bus << 8) | (2u << 3));
    }
    if (io.changeSelectedIdentity && (io.deviceOpenFlags.at(fd) & O_APPEND) == 0)
        info->out.subsystem_id = 1;
}

void fillMappings(tenstorrent_query_mappings *query) {
    query->in.output_mapping_count = 2;
    auto *mappings = query->out.mappings;
    std::memset(mappings, 0, 2 * sizeof(*mappings));
    mappings[0].mapping_id = TENSTORRENT_MAPPING_RESOURCE0_UC;
    mappings[0].mapping_base = 0;
    mappings[0].mapping_size = 3 * 1024 * 1024;
    mappings[1].mapping_id = TENSTORRENT_MAPPING_RESOURCE1_UC;
    mappings[1].mapping_base = 0x400000;
    mappings[1].mapping_size = 3 * 1024 * 1024;
}

class PciDeviceConnectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        io = {};
        fixtureActive = true;
    }

    void TearDown() override {
        // The current RED candidate leaks on a throwing constructor. Do not
        // retain its test-owned fake BAR allocations in the process.
        io.releaseRemainingMappings();
        fixtureActive = false;
        io = {};
    }

    static void expectOneConnectionForEveryDriverOperation() {
        ASSERT_EQ(io.deviceOpens, 1u);
        ASSERT_EQ(io.deviceFds.size(), 1u);
        EXPECT_EQ(io.unexpectedDeviceOpens, 0u);
        EXPECT_EQ(io.operationsAfterClose, 0u);
        EXPECT_EQ(io.duplicateCloses, 0u);
        ASSERT_FALSE(io.ioctlFds.empty());
        ASSERT_FALSE(io.mmapFds.empty());
        for (const int fd : io.ioctlFds)
            EXPECT_EQ(fd, io.deviceFds.front());
        for (const int fd : io.mmapFds)
            EXPECT_EQ(fd, io.deviceFds.front());
    }

    static void expectMappingsReleasedBeforeClose() {
        ASSERT_EQ(io.deviceCloses, 1u);
        ASSERT_EQ(io.closeEvents.size(), 1u);
        ASSERT_EQ(io.deviceMunmaps, io.deviceMappings);
        EXPECT_TRUE(io.mappings.empty());
        EXPECT_EQ(io.operationsAfterClose, 0u);
        EXPECT_EQ(io.duplicateCloses, 0u);
        for (const unsigned unmap : io.munmapEvents)
            EXPECT_LT(unmap, io.closeEvents.front());
    }

    static void expectConstructorQueries() {
        EXPECT_EQ(io.deviceInfoQueries, 1u);
        EXPECT_EQ(io.driverInfoQueries, 1u);
        EXPECT_EQ(io.barQueries, 1u);
        ASSERT_EQ(io.sysfsReads.size(), 4u);
        for (const std::string_view attribute : {"numa_node", "revision", "version", "iommu_group/type"})
            EXPECT_EQ(std::count(io.sysfsReads.begin(), io.sysfsReads.end(), attribute), 1);
    }

    static void expectBarMappings() {
        ASSERT_GE(io.mapRequests.size(), 3u);
        EXPECT_EQ(io.mapRequests[0].size, BarSize);
        EXPECT_EQ(io.mapRequests[0].offset, Bar0Offset);
        EXPECT_EQ(io.mapRequests[1].size, 4096u);
        EXPECT_EQ(io.mapRequests[1].offset, TlbOffset);
        EXPECT_EQ(io.mapRequests[2].size, BarSize);
        EXPECT_EQ(io.mapRequests[2].offset, Bar2Offset);
        for (const auto &request : io.mapRequests) {
            EXPECT_EQ(request.protection, PROT_READ | PROT_WRITE);
            EXPECT_EQ(request.flags, MAP_SHARED);
        }
    }
};

class PciDeviceDiscoveryTest : public PciDeviceConnectionTest {
protected:
    void SetUp() override {
        PciDeviceConnectionTest::SetUp();
        if (const char *visibility = std::getenv("TT_VISIBLE_DEVICES"))
            savedVisibility = visibility;
        unsetenv("TT_VISIBLE_DEVICES");
        char directory[] = "/tmp/trex-umd-discovery-XXXXXX";
        ASSERT_NE(mkdtemp(directory), nullptr);
        io.discoveryDirectory = directory;
        io.discoveryActive = true;
        addDevice(42);
        addDevice(43);
    }

    void TearDown() override {
        if (savedVisibility)
            setenv("TT_VISIBLE_DEVICES", savedVisibility->c_str(), 1);
        else
            unsetenv("TT_VISIBLE_DEVICES");
        for (int device : {42, 43})
            unlink((io.discoveryDirectory + "/" + std::to_string(device)).c_str());
        rmdir(io.discoveryDirectory.c_str());
        PciDeviceConnectionTest::TearDown();
    }

    void addDevice(int number) {
        const auto path = io.discoveryDirectory + "/" + std::to_string(number);
        const int fd = rawOpenAt(AT_FDCWD, path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        ASSERT_GE(fd, 0);
        syscall(SYS_close, fd);
    }

    std::vector<int> ordinaryConnections() const {
        std::vector<int> handles;
        for (int fd : io.deviceFds)
            if ((io.deviceOpenFlags.at(fd) & O_APPEND) == 0)
                handles.push_back(fd);
        return handles;
    }

private:
    std::optional<std::string> savedVisibility;
};

TEST_F(PciDeviceDiscoveryTest, AcquisitionRetainsOnlyTheSelectedDeviceAfterMetadataFiltering) {
    setenv("TT_VISIBLE_DEVICES", "0,0000:01:02.0,0", 1);
    {
        std::unique_ptr<tt::umd::TopologyDiscovery> discovery;
        try {
            discovery = TopologyDiscoveryAccess::create_topology_discovery();
        } catch (const std::exception &error) {
            FAIL() << error.what() << "; directory opens=" << io.discoveryDirectoryOpens
                   << "; device opens=" << io.deviceOpens << "; unexpected opens=" << io.unexpectedDeviceOpens
                   << "; attrs queries=" << io.deviceInfoQueries;
        }
        ASSERT_NE(discovery, nullptr);
        const auto connections = ordinaryConnections();
        ASSERT_EQ(connections.size(), 1u);
        const int selected = connections.front();
        EXPECT_EQ(io.deviceNumbers.at(selected), 42);
        EXPECT_FALSE(io.isClosed(selected));
        ASSERT_FALSE(io.mmapFds.empty());
        for (int fd : io.mmapFds)
            EXPECT_EQ(fd, selected);
        EXPECT_EQ(io.dmaAllocations, 1u);
    }
    EXPECT_TRUE(io.mappings.empty());
    EXPECT_EQ(io.deviceMunmaps, io.deviceMappings);
    EXPECT_EQ(io.operationsAfterClose, 0u);
    EXPECT_EQ(io.duplicateCloses, 0u);
    for (int fd : io.deviceFds)
        EXPECT_TRUE(io.isClosed(fd));
}

TEST_F(PciDeviceDiscoveryTest, FixtureMetadataReaderUsesTheRealDriverQuery) {
    const auto info = tt::umd::PCIDevice::read_device_info(std::string(DevicePath));
    EXPECT_EQ(info.pci_bdf, "0000:01:02.0");
    EXPECT_EQ(io.deviceInfoQueries, 1u);
}

TEST_F(PciDeviceDiscoveryTest, AcquisitionRejectsChangedSelectedIdentityBeforeMapping) {
    setenv("TT_VISIBLE_DEVICES", "0", 1);
    io.changeSelectedIdentity = true;
    EXPECT_THROW((void)TopologyDiscoveryAccess::create_topology_discovery(), std::exception);
    ASSERT_EQ(ordinaryConnections().size(), 1u);
    EXPECT_TRUE(io.mapRequests.empty());
    EXPECT_EQ(io.dmaAllocations, 0u);
    for (int fd : io.deviceFds)
        EXPECT_TRUE(io.isClosed(fd));
}

TEST_F(PciDeviceDiscoveryTest, EmptyVisibilityDoesNotAcquireAnyDevice) {
    setenv("TT_VISIBLE_DEVICES", "", 1);
    EXPECT_EQ(TopologyDiscoveryAccess::create_topology_discovery(), nullptr);
    EXPECT_TRUE(io.deviceFds.empty());
    EXPECT_TRUE(io.mapRequests.empty());
}

TEST_F(PciDeviceDiscoveryTest, MoveFactoryProcessesRetainedDevicesInBdfOrder) {
    io.reverseBdfOrder = true;
    auto discovery = TopologyDiscoveryAccess::create_topology_discovery();
    ASSERT_NE(discovery, nullptr);
    ASSERT_EQ(ordinaryConnections().size(), 2u);
    // Stop at the real TTDevice factory's first hang-detector TLB acquisition.
    // The first actual retained handle reaching that boundary proves which
    // selected owner was moved first, without initializing physical firmware.
    io.failIoctlRequest = TENSTORRENT_IOCTL_ALLOCATE_TLB;
    const auto connect = &TopologyDiscoveryAccess::get_connected_devices;
    EXPECT_THROW((discovery.get()->*connect)(), std::exception);
    ASSERT_FALSE(io.tlbAllocationFds.empty());
    EXPECT_EQ(io.deviceNumbers.at(io.tlbAllocationFds.front()), 43);
    discovery.reset();
    EXPECT_TRUE(io.mappings.empty());
    EXPECT_EQ(io.deviceMappings, io.deviceMunmaps);
    EXPECT_EQ(io.operationsAfterClose, 0u);
    EXPECT_EQ(io.duplicateCloses, 0u);
}

TEST_F(PciDeviceDiscoveryTest, InvalidVisibilityDoesNotAcquireOrdinaryConnections) {
    for (const char *token : {"2", "not-a-device", "0000:ff:ff.0"}) {
        setenv("TT_VISIBLE_DEVICES", token, 1);
        EXPECT_THROW((void)TopologyDiscoveryAccess::create_topology_discovery(), std::exception);
        EXPECT_TRUE(ordinaryConnections().empty());
        EXPECT_TRUE(io.mapRequests.empty());
    }
}

TEST_F(PciDeviceConnectionTest, ConstructorUsesOneConnectionForQueriesMappingsAndDma) {
    {
        tt::umd::PCIDevice device(42);
        EXPECT_EQ(device.get_device_num(), 42);
        EXPECT_EQ(device.get_arch(), tt::ARCH::BLACKHOLE);
        EXPECT_FALSE(device.is_iommu_enabled());
        EXPECT_NE(device.get_dma_buffer().buffer, nullptr);
        EXPECT_EQ(device.get_dma_buffer().buffer_pa, 0x12340000u);
    }

    // A raw BAR reopen, metadata-query reopen or separate KMD handle makes
    // this observable as a second independent open file description.
    expectConstructorQueries();
    expectBarMappings();
    EXPECT_EQ(io.dmaAllocations, 1u);
    ASSERT_EQ(io.mapRequests.size(), 4u);
    EXPECT_EQ(io.mapRequests[3].size, 512 * 1024 + static_cast<size_t>(sysconf(_SC_PAGESIZE)));
    EXPECT_EQ(io.mapRequests[3].offset, DmaOffset);
    EXPECT_EQ(io.deviceMappings, 4u);
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, FailedThirdBarMappingReleasesEarlierMappingsBeforeClosingConnection) {
    // BAR0 and the static-TLB page are live when Blackhole BAR2 mapping is
    // attempted. This catches a throwing constructor that strands those
    // mappings, or closes the driver connection before it releases them.
    io.failMmapAttempt = 3;
    EXPECT_THROW((void)tt::umd::PCIDevice(42), std::exception);

    expectConstructorQueries();
    expectBarMappings();
    EXPECT_EQ(io.dmaAllocations, 0u);
    EXPECT_EQ(io.deviceMmapAttempts, 3u);
    EXPECT_EQ(io.deviceMappings, 2u);
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, IommuDmaPagesAreUnpinnedBeforeUnmappingAndClosingConnection) {
    io.iommuEnabled = true;
    {
        tt::umd::PCIDevice device(42);
        EXPECT_TRUE(device.is_iommu_enabled());
        ASSERT_NE(device.get_dma_buffer().buffer, nullptr);
        EXPECT_EQ(device.get_dma_buffer().buffer_pa, 0x12340000u);
    }

    expectConstructorQueries();
    expectBarMappings();
    EXPECT_EQ(io.dmaAllocations, 0u);
    ASSERT_EQ(io.pins, 1u);
    ASSERT_EQ(io.unpins, 1u);
    EXPECT_LT(io.pinEvent, io.unpinEvent);
    EXPECT_LT(io.unpinEvent, io.iommuMunmapEvent);
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
    EXPECT_LT(io.iommuMunmapEvent, io.closeEvents.front());
}

TEST_F(PciDeviceConnectionTest, RetainedConnectionTransfersToDeviceWithoutReopening) {
    {
        tt::umd::PciDeviceConnection connection(42);
        auto *const handle = connection.get_handle();
        ASSERT_NE(handle, nullptr);
        tt::umd::PCIDevice device(std::move(connection));
        EXPECT_EQ(connection.get_handle(), nullptr);
        EXPECT_EQ(device.get_tt_device_handle(), handle);
    }
    expectConstructorQueries();
    expectBarMappings();
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, LocalChipConstructorFailureReleasesSysmemBeforeItsDevice) {
    io.iommuEnabled = true;
    auto device = std::make_unique<LocalChipFailureDevice>(std::make_unique<tt::umd::PCIDevice>(42));
    EXPECT_THROW(
        (void)tt::umd::LocalChip::create(std::move(device), 1),
        std::runtime_error);

    EXPECT_EQ(device, nullptr);
    ASSERT_EQ(io.powerStateRequests, 1u);
    ASSERT_NE(io.sysmemMapping, nullptr);
    ASSERT_NE(io.sysmemMunmapEvent, 0u);
    ASSERT_EQ(io.closeEvents.size(), 1u);
    EXPECT_LT(io.sysmemMunmapEvent, io.closeEvents.front());
    EXPECT_TRUE(io.mappings.empty());
    EXPECT_EQ(io.operationsAfterClose, 0u);
    EXPECT_EQ(io.duplicateCloses, 0u);
    // No process-lifetime DMA lock retains the ordinary connection after the
    // LocalChip unwind; other mutex kinds retain their existing ownership.
}

TEST_F(PciDeviceConnectionTest, LocalChipBaseFailureReleasesSysmemBeforeItsDevice) {
    io.iommuEnabled = true;
    io.rejectChipInfo = true;
    auto device = std::make_unique<LocalChipFailureDevice>(std::make_unique<tt::umd::PCIDevice>(42));
    EXPECT_THROW(
        (void)tt::umd::LocalChip::create(std::move(device), 1),
        std::runtime_error);
    EXPECT_EQ(device, nullptr);
    EXPECT_EQ(io.powerStateRequests, 0u);
    ASSERT_NE(io.sysmemMapping, nullptr);
    ASSERT_NE(io.sysmemMunmapEvent, 0u);
    ASSERT_EQ(io.closeEvents.size(), 1u);
    EXPECT_LT(io.sysmemMunmapEvent, io.closeEvents.front());
    EXPECT_TRUE(io.mappings.empty());
    EXPECT_EQ(io.operationsAfterClose, 0u);
    EXPECT_EQ(io.duplicateCloses, 0u);
}

TEST_F(PciDeviceConnectionTest, TypedFactoryRetainsTheActualPciDeviceAndOpaqueConnection) {
    int retainedFd = -1;
    {
        auto pci_device = std::make_unique<tt::umd::PCIDevice>(42);
        auto *const actualDevice = pci_device.get();
        auto *const actualHandle = pci_device->get_tt_device_handle();
        retainedFd = io.deviceFds.front();
        auto device = tt::umd::TTDevice::create(std::move(pci_device));
        EXPECT_EQ(pci_device, nullptr);
        ASSERT_NE(device, nullptr);
        EXPECT_EQ(device->get_pci_device(), actualDevice);
        EXPECT_EQ(device->get_pci_device()->get_tt_device_handle(), actualHandle);
        EXPECT_FALSE(io.isClosed(retainedFd));
        unsigned ordinaryOpens = 0;
        for (int fd : io.deviceFds)
            ordinaryOpens += (io.deviceOpenFlags.at(fd) & O_APPEND) == 0;
        EXPECT_EQ(ordinaryOpens, 1u);
        for (int fd : io.mmapFds)
            EXPECT_EQ(fd, retainedFd);
    }
    EXPECT_TRUE(io.isClosed(retainedFd));
    EXPECT_TRUE(io.mappings.empty());
    EXPECT_EQ(io.deviceMappings, io.deviceMunmaps);
    EXPECT_EQ(io.operationsAfterClose, 0u);
    EXPECT_EQ(io.duplicateCloses, 0u);
    ASSERT_EQ(io.tlbAllocations, 1u);
    ASSERT_EQ(io.tlbFrees, 1u);
    EXPECT_LT(io.tlbFreeEvent, io.closeEvents.back());
}

TEST_F(PciDeviceConnectionTest, TypedFactoryRejectsEmptyDeviceWithoutOpeningAnything) {
    EXPECT_THROW(
        (void)tt::umd::TTDevice::create(std::unique_ptr<tt::umd::PCIDevice>{}),
        std::exception);
    EXPECT_TRUE(io.deviceFds.empty());
    EXPECT_TRUE(io.mapRequests.empty());
}

TEST_F(PciDeviceConnectionTest, TypedFactoryDescriptorFailureReleasesTheAdoptedDevice) {
    auto pci_device = std::make_unique<tt::umd::PCIDevice>(42);
    auto descriptor = std::make_shared<tt::umd::SocArchDescriptor>(tt::ARCH::WORMHOLE_B0);
    EXPECT_THROW((void)tt::umd::TTDevice::create(std::move(pci_device), false, descriptor), std::exception);
    EXPECT_EQ(pci_device, nullptr);
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, TlbAllocationAndReleaseUseTheRetainedConnection) {
    {
        tt::umd::PCIDevice device(42);
        auto tlb = device.allocate_tlb(2 * 1024 * 1024);
        ASSERT_NE(tlb, nullptr);
        EXPECT_EQ(tlb->get_size(), 2 * 1024 * 1024u);
    }
    expectConstructorQueries();
    expectBarMappings();
    ASSERT_EQ(io.tlbAllocations, 1u);
    ASSERT_EQ(io.tlbFrees, 1u);
    EXPECT_LT(io.tlbMunmapEvent, io.tlbFreeEvent);
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
    EXPECT_LT(io.tlbFreeEvent, io.closeEvents.front());
}

TEST_F(PciDeviceConnectionTest, FailedFirstDmaMappingRetriesOnTheRetainedConnection) {
    io.failMmapAttempt = 4;
    {
        tt::umd::PCIDevice device(42);
        ASSERT_NE(device.get_dma_buffer().buffer, nullptr);
        EXPECT_EQ(device.get_dma_buffer().size, 256 * 1024u);
    }
    expectConstructorQueries();
    expectBarMappings();
    EXPECT_EQ(io.dmaAllocations, 2u);
    EXPECT_EQ(io.deviceMmapAttempts, 5u);
    EXPECT_EQ(io.deviceMappings, 4u);
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, ConnectionCloseErrorDoesNotRetryConsumedHandle) {
    io.closeError = EIO;
    { tt::umd::PCIDevice device(42); }
    expectConstructorQueries();
    expectBarMappings();
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, FailedDeviceOpenDoesNotQueryMapOrCloseAnotherConnection) {
    io.failDeviceOpen = true;
    EXPECT_THROW((void)tt::umd::PCIDevice(42), std::exception);
    EXPECT_EQ(io.deviceOpens, 1u);
    EXPECT_TRUE(io.deviceFds.empty());
    EXPECT_TRUE(io.ioctlFds.empty());
    EXPECT_TRUE(io.mapRequests.empty());
    EXPECT_EQ(io.deviceCloses, 0u);
}

TEST_F(PciDeviceConnectionTest, FailedAttributeQueryClosesConnectionBeforeAnyMapping) {
    io.failIoctlRequest = TENSTORRENT_IOCTL_GET_DEVICE_INFO;
    EXPECT_THROW((void)tt::umd::PCIDevice(42), std::exception);
    EXPECT_EQ(io.deviceOpens, 1u);
    EXPECT_EQ(io.ioctlFds.size(), 1u);
    EXPECT_TRUE(io.mapRequests.empty());
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, FailedBarQueryClosesConnectionBeforeAnyMapping) {
    io.failIoctlRequest = TENSTORRENT_IOCTL_QUERY_MAPPINGS;
    EXPECT_THROW((void)tt::umd::PCIDevice(42), std::exception);
    expectConstructorQueries();
    EXPECT_EQ(io.deviceOpens, 1u);
    EXPECT_TRUE(io.mapRequests.empty());
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, FailedFirstBarMappingClosesTheRetainedConnection) {
    io.failMmapAttempt = 1;
    EXPECT_THROW((void)tt::umd::PCIDevice(42), std::exception);
    expectConstructorQueries();
    EXPECT_EQ(io.deviceMmapAttempts, 1u);
    EXPECT_EQ(io.deviceMappings, 0u);
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, FailedTlbConfigurationMappingReleasesBar0BeforeClosingConnection) {
    io.failMmapAttempt = 2;
    EXPECT_THROW((void)tt::umd::PCIDevice(42), std::exception);
    expectConstructorQueries();
    EXPECT_EQ(io.deviceMmapAttempts, 2u);
    EXPECT_EQ(io.deviceMappings, 1u);
    expectOneConnectionForEveryDriverOperation();
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, BarMappingRejectsInvalidArgumentsWithoutCallingMmap) {
    {
        tt::umd::PciDeviceConnection connection(42);
        auto *handle = connection.get_handle();
        void *mapping = reinterpret_cast<void *>(1);
        EXPECT_EQ(tt_device_map_bar(nullptr, 0, 4096, &mapping), -EINVAL);
        EXPECT_EQ(mapping, nullptr);
        mapping = reinterpret_cast<void *>(1);
        EXPECT_EQ(tt_device_map_bar(handle, 0, 0, &mapping), -EINVAL);
        EXPECT_EQ(mapping, nullptr);
        EXPECT_EQ(tt_device_map_bar(handle, 0, 4096, nullptr), -EINVAL);
        EXPECT_EQ(io.deviceMmapAttempts, 0u);
    }
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, BarMappingRejectsOffsetOverflowWithoutCallingMmap) {
    {
        tt::umd::PciDeviceConnection connection(42);
        void *mapping = reinterpret_cast<void *>(1);
        EXPECT_EQ(
            tt_device_map_bar(connection.get_handle(), std::numeric_limits<uint64_t>::max(), 4096, &mapping),
            -EOVERFLOW);
        EXPECT_EQ(mapping, nullptr);
        EXPECT_EQ(io.deviceMmapAttempts, 0u);
    }
    expectMappingsReleasedBeforeClose();
}

TEST_F(PciDeviceConnectionTest, BarMappingPreservesMmapErrnoAndClearsOutput) {
    io.failMmapAttempt = 1;
    {
        tt::umd::PciDeviceConnection connection(42);
        void *mapping = reinterpret_cast<void *>(1);
        EXPECT_EQ(tt_device_map_bar(connection.get_handle(), Bar0Offset, 4096, &mapping), -ENOMEM);
        EXPECT_EQ(mapping, nullptr);
        ASSERT_EQ(io.mapRequests.size(), 1u);
        EXPECT_EQ(io.mapRequests.front().offset, Bar0Offset);
        EXPECT_EQ(io.mapRequests.front().size, 4096u);
        EXPECT_EQ(io.mapRequests.front().protection, PROT_READ | PROT_WRITE);
        EXPECT_EQ(io.mapRequests.front().flags, MAP_SHARED);
        EXPECT_EQ(io.deviceMappings, 0u);
    }
    expectMappingsReleasedBeforeClose();
}

} // namespace

// CMake must set ENABLE_EXPORTS on the test target. These ELF interposers
// reach calls from the linked tt-umd DSO; linker --wrap only rewrites objects
// linked directly into this executable.
extern "C" __attribute__((visibility("default"))) int stat(const char *path, struct stat *buffer) noexcept {
    if (fixtureActive && io.discoveryActive &&
        (std::string_view(path) == "/dev/tenstorrent" || std::string_view(path) == "/dev/tenstorrent/"))
        path = io.discoveryDirectory.c_str();
    return static_cast<int>(syscall(SYS_newfstatat, AT_FDCWD, path, buffer, 0));
}

extern "C" __attribute__((visibility("default"))) DIR *opendir(const char *path) {
    if (fixtureActive && io.discoveryActive &&
        (std::string_view(path) == "/dev/tenstorrent" || std::string_view(path) == "/dev/tenstorrent/")) {
        ++io.discoveryDirectoryOpens;
        path = io.discoveryDirectory.c_str();
    }
    using OpenDirectory = DIR *(*)(const char *);
    static const auto realOpendir = reinterpret_cast<OpenDirectory>(dlsym(RTLD_NEXT, "opendir"));
    return realOpendir(path);
}

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
    if (const auto intercepted = interceptedOpen(path, flags))
        return *intercepted;
    va_list arguments;
    va_start(arguments, flags);
    const mode_t mode = hasMode(flags) ? va_arg(arguments, mode_t) : 0;
    va_end(arguments);
    return rawOpenAt(AT_FDCWD, path, flags, mode);
}

extern "C" __attribute__((visibility("default"))) int open64(const char *path, int flags, ...) {
    if (const auto intercepted = interceptedOpen(path, flags))
        return *intercepted;
    va_list arguments;
    va_start(arguments, flags);
    const mode_t mode = hasMode(flags) ? va_arg(arguments, mode_t) : 0;
    va_end(arguments);
    return rawOpenAt(AT_FDCWD, path, flags, mode);
}

extern "C" __attribute__((visibility("default"))) int __open_2(const char *path, int flags) {
    if (const auto intercepted = interceptedOpen(path, flags))
        return *intercepted;
    return rawOpenAt(AT_FDCWD, path, flags, 0);
}

extern "C" __attribute__((visibility("default"))) int __open64_2(const char *path, int flags) {
    if (const auto intercepted = interceptedOpen(path, flags))
        return *intercepted;
    return rawOpenAt(AT_FDCWD, path, flags, 0);
}

extern "C" __attribute__((visibility("default"))) int __openat_2(int directory, const char *path, int flags) {
    if (const auto intercepted = interceptedOpen(path, flags))
        return *intercepted;
    return rawOpenAt(directory, path, flags, 0);
}

extern "C" __attribute__((visibility("default"))) int __openat64_2(int directory, const char *path, int flags) {
    if (const auto intercepted = interceptedOpen(path, flags))
        return *intercepted;
    return rawOpenAt(directory, path, flags, 0);
}

extern "C" __attribute__((visibility("default"))) int openat(int directory, const char *path, int flags, ...) {
    if (const auto intercepted = interceptedOpen(path, flags))
        return *intercepted;
    va_list arguments;
    va_start(arguments, flags);
    const mode_t mode = hasMode(flags) ? va_arg(arguments, mode_t) : 0;
    va_end(arguments);
    return rawOpenAt(directory, path, flags, mode);
}

extern "C" __attribute__((visibility("default"))) int openat64(int directory, const char *path, int flags, ...) {
    if (const auto intercepted = interceptedOpen(path, flags))
        return *intercepted;
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
    ++io.deviceCloses;
    io.closedFds.push_back(fd);
    io.closeEvents.push_back(io.event());
    if (io.closeError != 0) {
        errno = io.closeError;
        return -1;
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

    io.ioctlFds.push_back(fd);
    if (request == TENSTORRENT_IOCTL_ALLOCATE_TLB)
        io.tlbAllocationFds.push_back(fd);
    if (io.isClosed(fd))
        ++io.operationsAfterClose;
    if (io.failIoctlRequest == request) {
        if (request == TENSTORRENT_IOCTL_GET_DEVICE_INFO)
            ++io.deviceInfoQueries;
        if (request == TENSTORRENT_IOCTL_QUERY_MAPPINGS)
            ++io.barQueries;
        errno = EIO;
        return -1;
    }
    switch (request) {
    case TENSTORRENT_IOCTL_GET_DEVICE_INFO:
        ++io.deviceInfoQueries;
        fillDeviceInfo(static_cast<tenstorrent_get_device_info *>(argument), fd);
        return 0;
    case TENSTORRENT_IOCTL_GET_DRIVER_INFO: {
        ++io.driverInfoQueries;
        auto *info = static_cast<tenstorrent_get_driver_info *>(argument);
        info->out.output_size_bytes = sizeof(info->out);
        info->out.driver_version = TENSTORRENT_DRIVER_VERSION;
        info->out.driver_version_major = 2;
        info->out.driver_version_minor = 10;
        info->out.driver_version_patch = 0;
        return 0;
    }
    case TENSTORRENT_IOCTL_QUERY_MAPPINGS:
        ++io.barQueries;
        fillMappings(static_cast<tenstorrent_query_mappings *>(argument));
        return 0;
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
        allocation->out.id = 1;
        allocation->out.mmap_offset_uc = 0x20000000;
        allocation->out.mmap_offset_wc = 0x30000000;
        return 0;
    }
    case TENSTORRENT_IOCTL_FREE_TLB: {
        ++io.tlbFrees;
        io.tlbFreeEvent = io.event();
        const auto *release = static_cast<tenstorrent_free_tlb *>(argument);
        EXPECT_EQ(release->in.id, 1u);
        EXPECT_EQ(io.mappings.find(io.tlbMapping), io.mappings.end());
        return 0;
    }
    case TENSTORRENT_IOCTL_PIN_PAGES: {
        ++io.pins;
        io.pinEvent = io.event();
        auto *pin = static_cast<tenstorrent_pin_pages *>(argument);
        auto *address = reinterpret_cast<void *>(pin->in.virtual_address);
        const auto mapping = io.mappings.find(address);
        EXPECT_EQ(address, io.iommuMapping);
        EXPECT_NE(mapping, io.mappings.end());
        if (mapping == io.mappings.end()) {
            errno = EFAULT;
            return -1;
        }
        EXPECT_EQ(pin->in.size, mapping->second.size);
        EXPECT_EQ(pin->in.flags, 0u);
        pin->out.physical_address = 0x12340000;
        return 0;
    }
    case TENSTORRENT_IOCTL_UNPIN_PAGES: {
        ++io.unpins;
        io.unpinEvent = io.event();
        const auto *unpin = static_cast<tenstorrent_unpin_pages *>(argument);
        EXPECT_EQ(reinterpret_cast<void *>(unpin->in.virtual_address), io.iommuMapping);
        EXPECT_EQ(unpin->in.size, io.iommuMappingSize);
        EXPECT_NE(io.mappings.find(io.iommuMapping), io.mappings.end());
        return 0;
    }
    default:
        errno = ENOTTY;
        return -1;
    }
}

extern "C" __attribute__((visibility("default"))) void *mmap(
    void *address, size_t length, int protection, int flags, int fd, off_t offset) noexcept {
    const bool sysmem = fixtureActive && io.iommuEnabled && fd == -1 &&
                        (flags & MAP_ANONYMOUS) != 0 && length >= (1ULL << 30);
    if (sysmem) {
        // Reserve the actual address range without hugepage or MAP_POPULATE
        // effects; constructor unwind never reads or writes this buffer.
        void *mapping = reinterpret_cast<void *>(syscall(
            SYS_mmap, address, length, protection, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0));
        if (mapping != MAP_FAILED) {
            ++io.deviceMappings;
            io.mappings.emplace(mapping, Mapping{length});
            io.sysmemMapping = mapping;
        }
        return mapping;
    }
    const bool iommuDma = fixtureActive && io.iommuEnabled && fd == -1 &&
                          flags == (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE);
    if (!fixtureActive || (!io.isDeviceFd(fd) && !iommuDma))
        return reinterpret_cast<void *>(syscall(SYS_mmap, address, length, protection, flags, fd, offset));
    if (iommuDma) {
        void *mapping = reinterpret_cast<void *>(
            syscall(SYS_mmap, address, length, protection, flags, fd, offset));
        if (mapping != MAP_FAILED) {
            ++io.deviceMappings;
            io.mappings.emplace(mapping, Mapping{length});
            io.iommuMapping = mapping;
            io.iommuMappingSize = length;
        }
        return mapping;
    }
    ++io.deviceMmapAttempts;
    io.mmapFds.push_back(fd);
    io.mapRequests.push_back(MapRequest{length, offset, protection, flags});
    if (io.isClosed(fd))
        ++io.operationsAfterClose;
    if (io.failMmapAttempt == io.deviceMmapAttempts) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    void *mapping = reinterpret_cast<void *>(syscall(
        SYS_mmap, address, length, protection, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    if (mapping == MAP_FAILED)
        return MAP_FAILED;
    ++io.deviceMappings;
    io.mappings.emplace(mapping, Mapping{length});
    if (offset == 0x20000000)
        io.tlbMapping = mapping;
    return mapping;
}

extern "C" __attribute__((visibility("default"))) int munmap(void *address, size_t length) noexcept {
    if (!fixtureActive)
        return static_cast<int>(syscall(SYS_munmap, address, length));
    const auto iterator = io.mappings.find(address);
    if (iterator == io.mappings.end())
        return static_cast<int>(syscall(SYS_munmap, address, length));
    EXPECT_EQ(length, iterator->second.size);
    io.mappings.erase(iterator);
    ++io.deviceMunmaps;
    io.munmapEvents.push_back(io.event());
    if (address == io.iommuMapping)
        io.iommuMunmapEvent = io.munmapEvents.back();
    if (address == io.tlbMapping)
        io.tlbMunmapEvent = io.munmapEvents.back();
    if (address == io.sysmemMapping)
        io.sysmemMunmapEvent = io.munmapEvents.back();
    return static_cast<int>(syscall(SYS_munmap, address, length));
}
