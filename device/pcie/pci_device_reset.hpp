// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>

#include "umd/device/utils/error.hpp"

namespace tt::umd::detail {

enum class ResetRefusalReason {
    LeaseQueryFailed,
    LeaseInvalidated,
    StrictResetUnsupported,
    LeaseNotHeld,
    ResetOutcomeUnverifiable,
};

class ResetRefusal final : public error::UmdBaseException {
public:
    ResetRefusal(ResetRefusalReason reason, int system_error, int close_error, std::string message) :
        UmdBaseException(message), reason_(reason), system_error_(system_error), close_error_(close_error) {}

    ResetRefusalReason reason() const noexcept { return reason_; }

    int system_error() const noexcept { return system_error_; }

    int close_error() const noexcept { return close_error_; }

private:
    ResetRefusalReason reason_;
    int system_error_;
    int close_error_;
};

// Private single-device sender used by PCIDevice's public bulk reset entry.
void send_reset_ioctl(int device_id, std::uint32_t flags);

}  // namespace tt::umd::detail
