// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <limits>
#include <mutex>
#include <optional>

#include "umd/device/tt_device/firmware/device_firmware.hpp"
#include "umd/device/types/blackhole_arc.hpp"
#include "umd/device/types/core_coordinates.hpp"
#include "umd/device/utils/error.hpp"
#include "umd/device/utils/semver.hpp"

namespace tt::umd::blackhole {

// tt-zephyr-platforms v19.5.0, app/smc/pytest/e2e_smoke.py::tensix_reset_sequence.
// This is an ASIC-wide pre-boot operation. Only the selected physical worker is witnessed.
template <class Hardware>
class TensixReset {
public:
    explicit TensixReset(Hardware& hardware) : hw(hardware) {}

    uint64_t run(CoreCoord worker) {
        std::lock_guard guard(mutex);
        observed_worker.reset();
        require_lease();
        // FirmwareBundleVersion ordering deliberately folds the fourth component for capability
        // ranges. This exact sequence is from one released SMC bundle, including that component.
        const SemVer version = hw.firmware_version();
        UMD_ASSERT(
            version == SemVer(19, 5, 0, 0),
            error::RuntimeError,
            "Tensix reset requires Blackhole SMC bundle 19.5.0.0.");
        hw.check_worker(worker);
        hw.power_up();
        const uint32_t marked = hw.read_marker(worker) | 1u;
        hw.write_marker(worker, marked);
        UMD_ASSERT(hw.read_marker(worker) == marked, error::RuntimeError, "Tensix reset marker did not latch.");

        send(ArcMessageType::FORCE_AICLK, 250);
        for (uint32_t bank = 0; bank < 8; ++bank) {
            hw.write_risc_bank(bank, 0);
        }
        send(ArcMessageType::TOGGLE_TENSIX_RESET);
        send(ArcMessageType::REINIT_TENSIX);
        hw.hold_riscs();
        for (uint32_t bank = 0; bank < 8; ++bank) {
            hw.write_risc_bank(bank, UINT32_MAX);
        }
        send(ArcMessageType::FORCE_AICLK, 0);
        UMD_ASSERT((hw.read_marker(worker) & 1u) == 0, error::RuntimeError, "Tensix reset marker remained set.");
        require_lease();
        // No two retained device instances may recognize the same epoch, including after close/reopen.
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
    void require_lease() const {
        UMD_ASSERT(
            hw.has_exclusive_execution(), error::RuntimeError, "Tensix reset requires exclusive PCIe execution.");
    }

    void send(ArcMessageType msg, uint32_t arg = 0) {
        const DeviceCommandResult result = hw.send(msg, arg);
        UMD_ASSERT(
            result.exit_code == 0 && result.handler_status == 0,
            error::RuntimeError,
            fmt::format(
                "Tensix reset SMC command 0x{:x} failed (status {}, result {}).",
                static_cast<unsigned>(msg),
                result.handler_status,
                result.exit_code));
    }

    Hardware& hw;
    mutable std::mutex mutex;
    std::optional<CoreCoord> observed_worker;
    uint64_t epoch = 0;
    inline static std::atomic<uint64_t> last_epoch{0};
};

}  // namespace tt::umd::blackhole
