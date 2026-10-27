// SPDX-License-Identifier: Apache-2.0
// Link the real tt-kmd-lib implementation; only Linux syscall edges are fake.
// This verifies retained-handle query admission and response validation, not
// kernel exclusion, strict reset, clean state, or bootstrap.
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tt-kmd-lib/tt_kmd_lib.h"

// The wire header contains legacy power macros that also name public enums.
#include "ioctl.h"

_Static_assert(
    TT_RESET_LEASE_CAP_EXCLUSIVE == TENSTORRENT_RESET_LEASE_CAP_EXCLUSIVE,
    "public exclusive capability matches the versioned wire ABI");
_Static_assert(
    TT_RESET_LEASE_CAP_STRICT_RESET == TENSTORRENT_RESET_LEASE_CAP_STRICT_RESET,
    "public strict reset capability matches the versioned wire ABI");
_Static_assert(
    TT_RESET_LEASE_NONE == TENSTORRENT_RESET_LEASE_NONE && TT_RESET_LEASE_HELD == TENSTORRENT_RESET_LEASE_HELD &&
        TT_RESET_LEASE_RELEASED == TENSTORRENT_RESET_LEASE_RELEASED &&
        TT_RESET_LEASE_INVALIDATED == TENSTORRENT_RESET_LEASE_INVALIDATED,
    "public lease states match the versioned wire ABI");

// Weak references let the same executable report that the pre-cutover library
// has no mutation API. There is no test or production fallback implementation.
extern int tt_device_reset_lease_acquire(tt_device_t *, tt_reset_lease_info_t *) __attribute__((weak));
extern int tt_device_reset_lease_release(tt_device_t *, tt_reset_lease_info_t *) __attribute__((weak));

static unsigned checks, failures, opens, closes, calls, unexpected;
static int next_fd = 73, expected_fd, kernel_error;
static uint32_t expected_operation = TENSTORRENT_RESET_LEASE_QUERY;
static bool closed[4];
static struct tenstorrent_reset_lease_out response;

static void expect(bool value, const char *behavior) {
    ++checks;
    if (!value) {
        ++failures;
        fprintf(stderr, "FAIL lease query: %s\n", behavior);
    }
}

static int open_device(const char *path, int flags) {
    expect(strcmp(path, "/dev/tenstorrent/42") == 0, "open retains the selected device path");
    expect(
        (flags & (O_RDWR | O_CLOEXEC | O_APPEND)) == (O_RDWR | O_CLOEXEC | O_APPEND),
        "original open carries explicit lock-only flags");
    ++opens;
    return next_fd++;
}

int open(const char *path, int flags, ...) { return open_device(path, flags); }

// Optimized glibc builds route this two-argument open through the fortify edge.
int __open_2(const char *path, int flags) { return open_device(path, flags); }

int close(int fd) {
    expect(fd >= 73 && fd < next_fd, "close consumes an actual opened handle");
    if (fd < 73 || fd >= next_fd) {
        return -1;
    }
    expect(!closed[fd - 73], "original handle closes exactly once");
    closed[fd - 73] = true;
    ++closes;
    return 0;
}

int ioctl(int fd, unsigned long command, ...) {
    ++calls;
    expect(
        fd == expected_fd && fd >= 73 && fd < next_fd && !closed[fd - 73],
        "query uses the original retained open description");
    if (command != TENSTORRENT_IOCTL_RESET_LEASE) {
        ++unexpected;
        errno = ENOTTY;
        return -1;
    }
    va_list args;
    va_start(args, command);
    struct tenstorrent_reset_lease *request = va_arg(args, struct tenstorrent_reset_lease *);
    va_end(args);
    expect(
        request->in.argsz == sizeof(*request) && request->in.version == TENSTORRENT_RESET_LEASE_VERSION &&
            request->in.operation == expected_operation && !request->in.reserved,
        "lease call sends the exact versioned ABI and requested operation");
    const struct tenstorrent_reset_lease_out empty = {0};
    expect(memcmp(&request->out, &empty, sizeof(empty)) == 0, "query initializes the complete kernel output buffer");
    if (kernel_error) {
        errno = kernel_error;
        return -1;
    }
    request->out = response;
    return 0;
}

typedef int (*LeaseCall)(tt_device_t *, tt_reset_lease_info_t *);

static void exchange(tt_device_t *device, LeaseCall call, int wanted, const char *behavior) {
    tt_reset_lease_info_t output;
    memset(&output, 0x5a, sizeof(output));
    const tt_reset_lease_info_t before = output;
    const unsigned prior_calls = calls, prior_opens = opens, prior_closes = closes;
    expect(call(device, &output) == wanted, behavior);
    expect(
        calls == prior_calls + 1 && opens == prior_opens && closes == prior_closes && unexpected == 0,
        "one lease call never closes, reopens, resets, or issues another operation");
    if (wanted) {
        expect(
            memcmp(&output, &before, sizeof(output)) == 0,
            "failed query does not publish partial capability or identity");
    } else {
        expect(
            output.capabilities == response.capabilities && (unsigned)output.state == response.state &&
                output.lease_id == response.lease_id &&
                output.lease_reset_generation == response.lease_reset_generation &&
                output.device_reset_generation == response.device_reset_generation,
            "successful query preserves all kernel correlation fields");
    }
}

static void query(tt_device_t *device, int wanted, const char *behavior) {
    expected_operation = TENSTORRENT_RESET_LEASE_QUERY;
    exchange(device, tt_device_reset_lease_query, wanted, behavior);
}

static void mutations(tt_device_t *device) {
    expect(tt_device_reset_lease_acquire != NULL, "the actual C library exports retained-handle lease acquire");
    expect(tt_device_reset_lease_release != NULL, "the actual C library exports retained-handle lease release");
    if (tt_device_reset_lease_acquire == NULL || tt_device_reset_lease_release == NULL) {
        return;
    }
    const LeaseCall operations[] = {tt_device_reset_lease_acquire, tt_device_reset_lease_release};
    const unsigned states[] = {TENSTORRENT_RESET_LEASE_HELD, TENSTORRENT_RESET_LEASE_RELEASED};
    for (unsigned op = 0; op < 2; ++op) {
        expected_operation = op == 0 ? TENSTORRENT_RESET_LEASE_ACQUIRE : TENSTORRENT_RESET_LEASE_RELEASE;
        response = (struct tenstorrent_reset_lease_out){
            .capabilities = TENSTORRENT_RESET_LEASE_CAP_EXCLUSIVE,
            .state = states[op],
            .lease_id = 12,
            .lease_reset_generation = 7,
            .device_reset_generation = 7};
        exchange(device, operations[op], 0, "lease mutation returns its checked held or released result");

        for (unsigned state = TENSTORRENT_RESET_LEASE_NONE; state <= TENSTORRENT_RESET_LEASE_INVALIDATED; ++state) {
            if (state == states[op]) {
                continue;
            }
            response = (struct tenstorrent_reset_lease_out){
                .capabilities = TENSTORRENT_RESET_LEASE_CAP_EXCLUSIVE,
                .state = state,
                .lease_id = state ? 12 : 0,
                .lease_reset_generation = state ? 7 : 0,
                .device_reset_generation = 7};
            exchange(device, operations[op], -EPROTO, "mutation cannot publish a different valid lease state");
        }
        for (unsigned fault = 0; fault < 7; ++fault) {
            response = (struct tenstorrent_reset_lease_out){
                .capabilities = TENSTORRENT_RESET_LEASE_CAP_EXCLUSIVE,
                .state = states[op],
                .lease_id = 12,
                .lease_reset_generation = 7,
                .device_reset_generation = 7};
            switch (fault) {
                case 0:
                    response.capabilities = 0;
                    break;
                case 1:
                    response.capabilities = TENSTORRENT_RESET_LEASE_CAP_STRICT_RESET;
                    break;
                case 2:
                    response.capabilities |= 8;
                    break;
                case 3:
                    response.reserved[0] = 1;
                    break;
                case 4:
                    response.reserved[1] = 1;
                    break;
                case 5:
                    response.lease_id = 0;
                    break;
                case 6:
                    response.lease_reset_generation = 6;
                    break;
            }
            exchange(device, operations[op], -EPROTO, "mutation rejects malformed capability or owner identity");
        }
        // A successful ioctl with a malformed response may have mutated the
        // kernel owner. Unchanged output is not evidence of an unheld lease.
        response = (struct tenstorrent_reset_lease_out){
            .capabilities = TENSTORRENT_RESET_LEASE_CAP_EXCLUSIVE,
            .state = states[op],
            .lease_id = 12,
            .lease_reset_generation = 7,
            .device_reset_generation = 7};
        query(device, 0, "after protocol failure the original handle queries the actual acquired or released state");
        expected_operation = op == 0 ? TENSTORRENT_RESET_LEASE_ACQUIRE : TENSTORRENT_RESET_LEASE_RELEASE;
        const int errors[] = {ENOTTY, EINVAL, EPERM, EBUSY, EALREADY, EOVERFLOW, ENODEV, ESTALE, EIO, EFAULT};
        for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
            kernel_error = errors[i];
            exchange(device, operations[op], -errors[i], "mutation preserves kernel errors without a hidden retry");
        }
        kernel_error = 0;
        const unsigned prior_calls = calls;
        tt_reset_lease_info_t output;
        memset(&output, 0x5a, sizeof(output));
        const tt_reset_lease_info_t before = output;
        expect(
            operations[op](NULL, &output) == -EINVAL && operations[op](device, NULL) == -EINVAL &&
                calls == prior_calls && memcmp(&output, &before, sizeof(output)) == 0,
            "mutation rejects null host arguments without changing state or output");
    }
}

int main(void) {
    tt_device_t *device = NULL;
    expect(tt_device_open("/dev/tenstorrent/42", &device, O_APPEND) == 0, "original device opens");
    if (device == NULL) {
        return 1;
    }
    expected_fd = 73;
    for (unsigned state = 0; state < 4; ++state) {
        response = (struct tenstorrent_reset_lease_out){
            .capabilities = 1,
            .state = state,
            .lease_id = state ? 12 : 0,
            .lease_reset_generation = state ? 7 : 0,
            .device_reset_generation = state > 1 ? 8 : 7};
        query(device, 0, "valid none, held, released, or invalidated response is accepted");
    }
    response = (struct tenstorrent_reset_lease_out){.capabilities = 3, .device_reset_generation = 7};
    query(device, 0, "query reports advertised bits without invoking strict reset");
    for (unsigned fault = 0; fault < 12; ++fault) {
        response = (struct tenstorrent_reset_lease_out){.capabilities = 1, .device_reset_generation = 7};
        switch (fault) {
            case 0:
                response.capabilities = 0;
                break;
            case 1:
                response.capabilities = 2;
                break;
            case 2:
                response.capabilities = 1 | 8;
                break;
            case 3:
                response.state = 4;
                break;
            case 4:
                response.reserved[0] = 1;
                break;
            case 5:
                response.reserved[1] = 1;
                break;
            case 6:
                response.lease_id = 12;
                break;
            case 7:
                response.lease_reset_generation = 7;
                break;
            case 8:
                response.state = 1;
                break;
            case 9:
                response.state = 2;
                break;
            case 10:
                response.state = 3;
                break;
            case 11:
                response.state = 1;
                response.lease_id = 12;
                response.lease_reset_generation = 6;
                break;
        }
        query(device, -EPROTO, "malformed capability/state/identity cannot become a typed result");
    }
    const int errors[] = {ENOTTY, EINVAL, EBUSY, ENODEV, ESTALE, EIO};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        kernel_error = errors[i];
        query(device, -errors[i], "kernel error survives without legacy fallback");
    }
    kernel_error = 0;
    mutations(device);
    unsigned prior_calls = calls;
    tt_reset_lease_info_t output;
    expect(
        tt_device_reset_lease_query(NULL, &output) == -EINVAL && tt_device_reset_lease_query(device, NULL) == -EINVAL &&
            calls == prior_calls,
        "invalid host arguments cannot reach a syscall");
    tt_device_t *second = NULL;
    expect(tt_device_open("/dev/tenstorrent/42", &second, O_APPEND) == 0, "second test owner opens independently");
    if (second == NULL) {
        tt_device_close(device);
        return 1;
    }
    expected_fd = 74;
    response = (struct tenstorrent_reset_lease_out){
        .capabilities = 1, .state = 3, .lease_id = 99, .lease_reset_generation = 4, .device_reset_generation = 8};
    query(second, 0, "second handle queries its own invalidated lease");
    expected_fd = 73;
    response.lease_id = 12;
    query(device, 0, "first handle is never replaced by a reopened owner");
    expect(
        tt_device_close(second) == 0 && tt_device_close(device) == 0 && opens == 2 && closes == 2,
        "all retained handles close once after their queries");
    printf("UMD lease query: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
