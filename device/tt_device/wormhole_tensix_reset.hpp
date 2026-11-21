// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>

#include "umd/device/types/core_coordinates.hpp"
#include "umd/device/utils/error.hpp"

namespace tt::umd::wormhole {

// Wormhole B0 has no Blackhole bit-10 erratum (WormholeB0/TensixTile/SoftReset.md):
// pulsing bit 10 of RISCV_DEBUG_REG_SOFT_RESET_0 while all five RISCs stay in soft
// reset (0x47800) resets the Vector Unit (SFPU FlagStack, UseLaneFlagsForLaneEnable,
// LReg[0..7], LaneConfig, LoadMacroConfig, PRNG) and Matrix Unit, then clears bit 10
// so RISCV_DEBUG_REG_SOFT_RESET_0 holds only 0x47800 before BRISC boot.
template <class Hardware>
class TensixReset {
public:
    static constexpr uint32_t kRiscSoftResetMask = 0x47800u;
    static constexpr uint32_t kVectorMatrixSoftResetBit = 1u << 10;
    static constexpr uint32_t kSfpuPulseSoftResetMask = kRiscSoftResetMask | kVectorMatrixSoftResetBit;

    explicit TensixReset(Hardware& hardware) : hw(hardware) {}

    uint64_t run(CoreCoord worker) {
        std::lock_guard guard(mutex);
        observed_worker.reset();
        require_exclusive_execution();
        hw.check_worker(worker);
        hw.power_up();

        hw.write_soft_reset(worker, kRiscSoftResetMask);
        UMD_ASSERT(
            hw.read_soft_reset(worker) == kRiscSoftResetMask,
            error::RuntimeError,
            "Wormhole Tensix RISCs did not enter soft reset.");

        hw.write_soft_reset(worker, kSfpuPulseSoftResetMask);
        UMD_ASSERT(
            hw.read_soft_reset(worker) == kSfpuPulseSoftResetMask,
            error::RuntimeError,
            "Wormhole Tensix Vector/Matrix soft reset did not latch.");

        hw.write_soft_reset(worker, kRiscSoftResetMask);
        UMD_ASSERT(
            hw.read_soft_reset(worker) == kRiscSoftResetMask,
            error::RuntimeError,
            "Wormhole Tensix Vector/Matrix soft reset did not clear.");

        require_exclusive_execution();
        uint64_t previous = last_epoch.load(std::memory_order_relaxed);
        do {
            UMD_ASSERT(
                previous != std::numeric_limits<uint64_t>::max(),
                error::RuntimeError,
                "Tensix reset epochs exhausted.");
        } while (!last_epoch.compare_exchange_weak(previous, previous + 1, std::memory_order_relaxed));
        epoch = previous + 1;
        observed_worker = worker;
        return epoch;
    }

    bool matches(CoreCoord worker, uint64_t candidate) const {
        std::lock_guard guard(mutex);
        return observed_worker && *observed_worker == worker && epoch == candidate && hw.has_exclusive_execution();
    }

private:
    void require_exclusive_execution() const {
        UMD_ASSERT(
            hw.has_exclusive_execution(), error::RuntimeError, "Tensix reset requires exclusive PCIe execution.");
    }

    Hardware& hw;
    mutable std::mutex mutex;
    std::optional<CoreCoord> observed_worker;
    uint64_t epoch = 0;
    inline static std::atomic<uint64_t> last_epoch{0};
};

}  // namespace tt::umd::wormhole
