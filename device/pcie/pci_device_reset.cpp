// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include "pcie/pci_device_reset.hpp"

#include <fcntl.h>
#include <fmt/format.h>

#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include "tt-kmd-lib/tt_kmd_lib.h"
#include "umd/device/utils/error.hpp"

namespace tt::umd::detail {

void send_reset_ioctl(int device_id, std::uint32_t flags) {
    std::string device_path = fmt::format("/dev/tenstorrent/{}", device_id);
    tt_device_t* dev = nullptr;
    int err = tt_device_open(device_path.c_str(), &dev, O_RDWR | O_CLOEXEC | O_APPEND);
    if (err != 0) {
        UMD_THROW(error::RuntimeError, fmt::format("Failed to open device {}: {}", device_id, strerror(-err)));
    }

    std::unique_ptr<tt_device_t, decltype(&tt_device_close)> owner(dev, &tt_device_close);
    auto refuse = [&](ResetRefusalReason reason, int system_error, std::string message) -> void {
        const int close_error = tt_device_close(owner.release());
        if (close_error != 0) {
            message += fmt::format("; closing retained reset handle also failed: {}", strerror(-close_error));
        }
        throw ResetRefusal(
            reason, system_error == 0 ? 0 : -system_error, close_error == 0 ? 0 : -close_error, std::move(message));
    };

    tt_reset_lease_info_t lease{};
    err = tt_device_reset_lease_query(owner.get(), &lease);
    if (err != 0) {
        refuse(
            ResetRefusalReason::LeaseQueryFailed,
            err,
            fmt::format(
                "Reset refused for device {} with flags {:#x}: reset lease query failed: {}",
                device_id,
                flags,
                strerror(-err)));
    }

    if (lease.state == TT_RESET_LEASE_INVALIDATED ||
        (lease.state == TT_RESET_LEASE_HELD && lease.lease_reset_generation != lease.device_reset_generation)) {
        refuse(
            ResetRefusalReason::LeaseInvalidated,
            0,
            fmt::format(
                "Reset refused for device {} with flags {:#x}: invalidated reset lease generation {} (device {})",
                device_id,
                flags,
                lease.lease_reset_generation,
                lease.device_reset_generation));
    }

    if ((lease.capabilities & TT_RESET_LEASE_CAP_STRICT_RESET) == 0) {
        refuse(
            ResetRefusalReason::StrictResetUnsupported,
            0,
            fmt::format(
                "Reset refused for device {} with flags {:#x}: KMD does not advertise a strict reset lease",
                device_id,
                flags));
    }

    if (lease.state != TT_RESET_LEASE_HELD || lease.lease_id == 0) {
        refuse(
            ResetRefusalReason::LeaseNotHeld,
            0,
            fmt::format(
                "Reset refused for device {} with flags {:#x}: original handle does not hold a reset lease",
                device_id,
                flags));
    }

    refuse(
        ResetRefusalReason::ResetOutcomeUnverifiable,
        0,
        fmt::format(
            "Reset refused for device {} with flags {:#x}: UMD has no verifiable lease-reset completion contract",
            device_id,
            flags));
}

}  // namespace tt::umd::detail
