// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include "pcie/pci_device_reset.hpp"

#include <fcntl.h>
#include <fmt/format.h>

#include <cstring>
#include <memory>
#include <string>

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
    err = tt_device_reset(owner.get(), flags);
    const int close_error = tt_device_close(owner.release());
    if (err != 0) {
        UMD_THROW(
            error::RuntimeError,
            fmt::format(
                "Sending reset command failed on device {} with flags {:#x}: {}", device_id, flags, strerror(-err)));
    }
    if (close_error != 0) {
        UMD_THROW(
            error::RuntimeError, fmt::format("Closing reset device {} failed: {}", device_id, strerror(-close_error)));
    }
}

}  // namespace tt::umd::detail
