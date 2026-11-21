// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include <fcntl.h>
#include <gtest/gtest.h>

#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

#include "pcie/pci_device_reset.hpp"
#include "tt-kmd-lib/tt_kmd_lib.h"
#include "umd/device/utils/error.hpp"

// Match the production C source: ioctl.h defines names also used by public enums.
#include "ioctl.h"

namespace {

// Only the syscall/allocation boundary is substituted. tt_device_open, reset
// and close are the real library implementation.
constexpr int device_fd = 701;
constexpr const char* device_path = "/dev/tenstorrent/42";

struct IoState {
    unsigned opens = 0;
    unsigned ioctls = 0;
    unsigned closes = 0;
    unsigned frees = 0;
    int open_error = 0;
    int ioctl_error = 0;
    int close_error = 0;
    int free_errno = 0;
    bool capture_allocation = false;
    bool fail_allocation = false;
    bool freed = false;
    void* allocation = nullptr;
    int open_flags = 0;
    uint32_t input_size = 0;
    uint32_t input_flags = 0;
    uint32_t output_size = sizeof(tenstorrent_reset_device_out);
    uint32_t output_result = 0;
};

IoState io;

}  // namespace

extern "C" void* __real_calloc(size_t count, size_t size);
extern "C" void __real_free(void* pointer);

extern "C" void* __wrap_calloc(size_t count, size_t size) {
    if (!io.capture_allocation) {
        return __real_calloc(count, size);
    }
    io.capture_allocation = false;
    if (io.fail_allocation) {
        return nullptr;
    }
    io.allocation = __real_calloc(count, size);
    return io.allocation;
}

extern "C" void __wrap_free(void* pointer) {
    const bool device_allocation = pointer != nullptr && pointer == io.allocation && !io.freed;
    if (device_allocation) {
        ++io.frees;
        io.freed = true;
    }
    __real_free(pointer);
    if (device_allocation && io.free_errno != 0) {
        errno = io.free_errno;
    }
}

extern "C" int __wrap_open(const char* path, int flags, ...) {
    // No test path can reach a real device, including an unexpected open.
    if (std::strcmp(path, device_path) != 0) {
        errno = ENODEV;
        return -1;
    }
    ++io.opens;
    io.open_flags = flags;
    if (io.open_error != 0) {
        errno = io.open_error;
        return -1;
    }
    return device_fd;
}

extern "C" int __wrap___open_2(const char* path, int flags) { return __wrap_open(path, flags); }

extern "C" int __wrap_close(int fd) {
    if (fd != device_fd) {
        errno = EBADF;
        return -1;
    }
    ++io.closes;
    if (io.close_error != 0) {
        errno = io.close_error;
        return -1;
    }
    return 0;
}

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) {
    if (fd != device_fd) {
        errno = ENOTTY;
        return -1;
    }
    va_list args;
    va_start(args, request);
    if (request != TENSTORRENT_IOCTL_RESET_DEVICE) {
        va_end(args);
        errno = ENOTTY;
        return -1;
    }
    ++io.ioctls;
    auto* reset = va_arg(args, tenstorrent_reset_device*);
    va_end(args);
    io.input_size = reset->in.output_size_bytes;
    io.input_flags = reset->in.flags;
    if (io.ioctl_error != 0) {
        errno = io.ioctl_error;
        return -1;
    }
    reset->out.output_size_bytes = io.output_size;
    reset->out.result = io.output_result;
    return 0;
}

namespace {

class KmdResetTest : public ::testing::Test {
protected:
    void SetUp() override { io = {}; }

    void TearDown() override {
        if (io.allocation != nullptr && !io.freed) {
            if (io.closes == 0 && io.opens != 0) {
                tt_device_close(static_cast<tt_device_t*>(io.allocation));
            }
            if (!io.freed) {
                __real_free(io.allocation);
            }
        }
        io = {};
    }

    tt_device_t* open_device() {
        tt_device_t* device = nullptr;
        io.capture_allocation = true;
        const int result = tt_device_open(device_path, &device, O_APPEND);
        if (result != 0 || device == nullptr) {
            throw std::runtime_error("Test device open failed: " + std::to_string(result));
        }
        return device;
    }

    void expect_retained() {
        EXPECT_EQ(io.closes, 0u);
        EXPECT_EQ(io.frees, 0u);
        EXPECT_FALSE(io.freed);
    }

    std::string sender_error() {
        io.capture_allocation = true;
        try {
            tt::umd::detail::send_reset_ioctl(42, 6);
        } catch (const tt::umd::error::UmdBaseException& error) {
            return error.message();
        }
        ADD_FAILURE() << "Sender did not report failure";
        return {};
    }

    tt::umd::detail::ResetRefusal sender_refusal() {
        io.capture_allocation = true;
        try {
            tt::umd::detail::send_reset_ioctl(42, 6);
        } catch (const tt::umd::detail::ResetRefusal& error) {
            return error;
        } catch (const tt::umd::error::UmdBaseException& error) {
            ADD_FAILURE() << "Sender returned an untyped refusal: " << error.message();
        }
        ADD_FAILURE() << "Sender did not refuse reset";
        return {tt::umd::detail::ResetRefusalReason::ResetOutcomeUnverifiable, 0, 0, "missing reset refusal"};
    }
};

TEST_F(KmdResetTest, LegacyResetApiRefusesWithoutSideEffectOrConsumingHandle) {
    tt_device_t* device = open_device();
    EXPECT_EQ(tt_device_reset(device, 6), -EOPNOTSUPP);
    EXPECT_EQ(io.ioctls, 0u);
    expect_retained();
    EXPECT_FALSE(io.freed);
    EXPECT_EQ(tt_device_close(device), 0);
    EXPECT_EQ(io.closes, 1u);
    EXPECT_EQ(io.frees, 1u);
}

TEST_F(KmdResetTest, LegacyResetApiRejectsNullHandleWithoutIoctl) {
    EXPECT_EQ(tt_device_reset(nullptr, 6), -ENODEV);
    EXPECT_EQ(io.ioctls, 0u);
}

TEST_F(KmdResetTest, ExplicitCloseConsumesHandle) {
    tt_device_t* device = open_device();
    EXPECT_EQ(tt_device_close(device), 0);
    EXPECT_EQ(io.closes, 1u);
    EXPECT_EQ(io.frees, 1u);
}

class FailedDeviceCloseTest : public KmdResetTest, public ::testing::WithParamInterface<int> {};

TEST_P(FailedDeviceCloseTest, ConsumesHandleAndPreservesErrorWithoutRetry) {
    tt_device_t* device = open_device();
    io.close_error = GetParam();
    io.free_errno = ENOMEM;
    EXPECT_EQ(tt_device_close(device), -GetParam());
    EXPECT_EQ(io.closes, 1u);
    EXPECT_EQ(io.frees, 1u);
}

INSTANTIATE_TEST_SUITE_P(LinuxClose, FailedDeviceCloseTest, ::testing::Values(EIO, EINTR, EBADF));

TEST_F(KmdResetTest, OpenFailureFreesAllocationWithoutClose) {
    io.open_error = EACCES;
    io.capture_allocation = true;
    tt_device_t* device = nullptr;
    EXPECT_EQ(tt_device_open(device_path, &device, O_APPEND), -EACCES);
    EXPECT_EQ(device, nullptr);
    EXPECT_EQ(io.opens, 1u);
    EXPECT_EQ(io.closes, 0u);
    EXPECT_EQ(io.frees, 1u);
}

TEST_F(KmdResetTest, AllocationFailureHasNoOpenOrClose) {
    io.fail_allocation = true;
    io.capture_allocation = true;
    tt_device_t* device = nullptr;
    EXPECT_EQ(tt_device_open(device_path, &device, 0), -ENOMEM);
    EXPECT_EQ(device, nullptr);
    EXPECT_EQ(io.opens, 0u);
    EXPECT_EQ(io.closes, 0u);
}

TEST_F(KmdResetTest, SenderRefusesUnverifiableResetWithoutCallingLegacyIoctl) {
    io.capture_allocation = true;
    const auto refusal = sender_refusal();
    EXPECT_EQ(refusal.reason(), tt::umd::detail::ResetRefusalReason::ResetOutcomeUnverifiable);
    EXPECT_NE(std::string(refusal.message()).find("no verifiable reset-ioctl completion contract"), std::string::npos);
    EXPECT_EQ(io.opens, 1u);
    EXPECT_EQ(io.ioctls, 0u);
    EXPECT_EQ(io.open_flags, O_RDWR | O_CLOEXEC | O_APPEND);
    EXPECT_EQ(io.closes, 1u);
    EXPECT_EQ(io.frees, 1u);
}

class SenderCloseFailureTest : public KmdResetTest, public ::testing::WithParamInterface<int> {};

TEST_P(SenderCloseFailureTest, ResetRefusalReportsCloseErrorWithoutRetry) {
    io.close_error = GetParam();
    const auto refusal = sender_refusal();
    EXPECT_EQ(refusal.reason(), tt::umd::detail::ResetRefusalReason::ResetOutcomeUnverifiable);
    EXPECT_EQ(refusal.close_error(), GetParam());
    EXPECT_NE(std::string(refusal.message()).find("no verifiable reset-ioctl completion contract"), std::string::npos);
    EXPECT_NE(std::string(refusal.message()).find(std::strerror(GetParam())), std::string::npos);
    EXPECT_EQ(io.ioctls, 0u);
    EXPECT_EQ(io.closes, 1u);
    EXPECT_EQ(io.frees, 1u);
}

INSTANTIATE_TEST_SUITE_P(LinuxClose, SenderCloseFailureTest, ::testing::Values(EIO, EINTR));

TEST_F(KmdResetTest, SenderOpenFailureReleasesAllocationWithoutClose) {
    io.open_error = EACCES;
    EXPECT_NE(sender_error().find(std::strerror(EACCES)), std::string::npos);
    EXPECT_EQ(io.opens, 1u);
    EXPECT_EQ(io.ioctls, 0u);
    EXPECT_EQ(io.closes, 0u);
    EXPECT_EQ(io.frees, 1u);
}

TEST_F(KmdResetTest, SenderAllocationFailureDoesNotOpenOrClose) {
    io.fail_allocation = true;
    EXPECT_NE(sender_error().find(std::strerror(ENOMEM)), std::string::npos);
    EXPECT_EQ(io.opens, 0u);
    EXPECT_EQ(io.ioctls, 0u);
    EXPECT_EQ(io.closes, 0u);
}

}  // namespace
