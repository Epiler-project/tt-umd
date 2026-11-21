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
    std::string message = fmt::format(
        "Reset refused for device {} with flags {:#x}: UMD has no verifiable reset-ioctl completion contract",
        device_id,
        flags);
    const int close_error = tt_device_close(owner.release());
    if (close_error != 0) {
        message += fmt::format("; closing retained reset handle also failed: {}", strerror(-close_error));
    }
    throw ResetRefusal(
        ResetRefusalReason::ResetOutcomeUnverifiable, 0, close_error == 0 ? 0 : -close_error, std::move(message));
}

}  // namespace tt::umd::detail
