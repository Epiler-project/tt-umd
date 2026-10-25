// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

namespace tt::umd::detail {

// Private single-device sender used by PCIDevice's public bulk reset entry.
void send_reset_ioctl(int device_id, std::uint32_t flags);

}  // namespace tt::umd::detail
