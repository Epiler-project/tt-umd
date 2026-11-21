// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <cstdint>

#include "umd/device/pcie/pci_device.hpp"

namespace tt::umd {

// Private state shared only by a logical connection and its outstanding guards.
// Registry entries must never retain this state or its opaque driver handle.
struct PciDeviceConnectionState {
    PciDeviceConnectionState(int number, PciDeviceConnectionMode mode, tt_device_t *handle) :
        device_num(number), mode(mode), handle(handle) {}
    ~PciDeviceConnectionState() noexcept;

    void quarantine(PciDeviceConnectionStatus status, int error_code) noexcept {
        uint64_t expected = 0;
        const uint64_t failure = (static_cast<uint64_t>(status) << 32) | static_cast<uint32_t>(error_code);
        first_failure.compare_exchange_strong(expected, failure, std::memory_order_acq_rel);
    }

    void require_valid() const {
        const uint64_t failure = first_failure.load(std::memory_order_acquire);
        if (failure != 0) {
            UMD_THROW(
                error::PciDeviceConnectionError,
                (PciDeviceConnectionFailure{
                    device_num,
                    static_cast<PciDeviceConnectionStatus>(failure >> 32),
                    static_cast<int>(static_cast<uint32_t>(failure))}));
        }
    }

    const int device_num;
    const PciDeviceConnectionMode mode;
    tt_device_t *const handle;
    std::atomic<uint64_t> first_failure{0};
};

}  // namespace tt::umd
