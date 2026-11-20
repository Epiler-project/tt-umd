// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>

#include "tt_device/blackhole_tensix_reset.hpp"
#include "umd/device/utils/semver.hpp"

namespace tt::umd {
namespace {

constexpr CoreCoord worker{1, 2, CoreType::TENSIX, CoordSystem::NOC0};
constexpr CoreCoord other{2, 2, CoreType::TENSIX, CoordSystem::NOC0};

// Only MMIO, power and firmware are substituted. The production caller owns
// the order of operations, invalidation and the physical worker check.
struct ResetDevice {
    FirmwareBundleVersion firmware{19, 5, 0, 0};
    bool leased = true;
    bool release_loses_lease = false;
    bool marker_writable = true;
    bool tile_resets = true;
    uint8_t failing_message = 0;
    uint32_t marker = 0x400;
    uint32_t risc_hold = 0;
    unsigned power_votes = 0;
    std::array<uint32_t, 8> reset_banks;
    std::vector<std::pair<uint32_t, uint32_t>> commands;

    ResetDevice() { reset_banks.fill(UINT32_MAX); }

    FirmwareBundleVersion firmware_version() const { return firmware; }

    bool has_exclusive_execution() const { return leased; }

    void check_worker(CoreCoord core) const {
        if (!(core == worker || core == other)) {
            throw std::runtime_error("invalid worker");
        }
    }

    void power_up() { ++power_votes; }

    uint32_t read_marker(CoreCoord core) {
        EXPECT_EQ(core, worker);
        return marker;
    }

    void write_marker(CoreCoord core, uint32_t value) {
        EXPECT_EQ(core, worker);
        EXPECT_EQ(value, 0x401u);
        if (marker_writable) {
            marker = value;
        }
    }

    DeviceCommandResult send(blackhole::ArcMessageType msg, uint32_t arg) {
        const auto code = static_cast<uint8_t>(msg);
        commands.emplace_back(code, arg);
        if ((code == 0xaf || code == 0x20) &&
            !std::all_of(reset_banks.begin(), reset_banks.end(), [](auto bank) { return bank == 0; })) {
            throw std::runtime_error("reset RISC banks before toggling tiles");
        }
        if (code == 0xaf && tile_resets) {
            marker &= ~1u;
        }
        if (code == 0x33 && arg == 0 && release_loses_lease) {
            leased = false;
        }
        return {0, {}, static_cast<uint8_t>(code == failing_message)};
    }

    void write_risc_bank(uint32_t i, uint32_t value) {
        if (value == UINT32_MAX && risc_hold != 0x47800) {
            throw std::runtime_error("RISCs released before soft reset");
        }
        reset_banks.at(i) = value;
    }

    void hold_riscs() { risc_hold = 0x47800; }
};

TEST(BlackholeTensixResetTest, BindsObservedMarkerToMatchingWorkerOwnerAndLatestEpoch) {
    ResetDevice dev;
    blackhole::TensixReset<ResetDevice> reset(dev);
    EXPECT_FALSE(reset.matches(worker, 0));
    const auto first = reset.run(worker);
    ASSERT_NE(first, 0u);
    EXPECT_TRUE(reset.matches(worker, first));
    EXPECT_FALSE(reset.matches(other, first));
    EXPECT_FALSE(reset.matches({1, 2, CoreType::ETH, CoordSystem::NOC0}, first));
    EXPECT_EQ(dev.marker, 0x400u);
    EXPECT_TRUE(
        std::all_of(dev.reset_banks.begin(), dev.reset_banks.end(), [](auto bank) { return bank == UINT32_MAX; }));
    const std::vector<std::pair<uint32_t, uint32_t>> expected{{0x33, 250}, {0xaf, 0}, {0x20, 0}, {0x33, 0}};
    EXPECT_EQ(dev.commands, expected);
    auto next = reset.run(worker);
    EXPECT_NE(next, first);
    EXPECT_FALSE(reset.matches(worker, first));
    dev.leased = false;
    EXPECT_FALSE(reset.matches(worker, next));
}

TEST(BlackholeTensixResetTest, DistinctDeviceCannotValidateTheOtherOwnersEpoch) {
    ResetDevice one, two;
    blackhole::TensixReset<ResetDevice> first(one), second(two);
    const auto a = first.run(worker);
    const auto b = second.run(worker);
    EXPECT_NE(a, b);
    EXPECT_FALSE(second.matches(worker, a));
    EXPECT_FALSE(first.matches(worker, b));
}

TEST(BlackholeTensixResetTest, RefusesMissingOwnershipAndInvalidWorkerBeforePowerOrWrites) {
    ResetDevice dev;
    blackhole::TensixReset<ResetDevice> reset(dev);
    dev.leased = false;
    EXPECT_THROW(reset.run(worker), std::runtime_error);
    dev.leased = true;
    EXPECT_THROW(reset.run({1, 2, CoreType::TENSIX, CoordSystem::LOGICAL}), std::runtime_error);
    EXPECT_EQ(dev.power_votes, 0u);
    EXPECT_TRUE(dev.commands.empty());
}

TEST(BlackholeTensixResetTest, RejectsDifferentFirmwareIncludingFourthComponentBeforeArmingMarker) {
    for (auto version : {FirmwareBundleVersion(19, 5, 0, 1), FirmwareBundleVersion(19, 4, 0, 0)}) {
        ResetDevice dev;
        dev.firmware = version;
        blackhole::TensixReset<ResetDevice> reset(dev);
        EXPECT_THROW(reset.run(worker), std::runtime_error);
        EXPECT_EQ(dev.power_votes, 0u);
        EXPECT_TRUE(dev.commands.empty());
    }
}

TEST(BlackholeTensixResetTest, RequiresBothPhysicalMarkerObservations) {
    ResetDevice dev;
    blackhole::TensixReset<ResetDevice> reset(dev);
    const auto old = reset.run(worker);
    dev.commands.clear();
    dev.marker_writable = false;
    EXPECT_THROW(reset.run(worker), std::runtime_error);
    EXPECT_TRUE(dev.commands.empty());
    EXPECT_FALSE(reset.matches(worker, old));
    dev.marker_writable = true;
    dev.tile_resets = false;
    EXPECT_THROW(reset.run(worker), std::runtime_error);
    EXPECT_FALSE(reset.matches(worker, old));
}

TEST(BlackholeTensixResetTest, FirmwareFailureStopsBeforeRiscReleaseAndRevokesPriorEpoch) {
    for (uint8_t cmd : {0x33, 0xaf, 0x20}) {
        ResetDevice dev;
        blackhole::TensixReset<ResetDevice> reset(dev);
        const auto old = reset.run(worker);
        dev.commands.clear();
        dev.failing_message = cmd;
        EXPECT_THROW(reset.run(worker), std::runtime_error);
        EXPECT_FALSE(reset.matches(worker, old));
        ASSERT_FALSE(dev.commands.empty());
        EXPECT_EQ(dev.commands.back().first, cmd);
        if (cmd != 0x33) {
            EXPECT_EQ(dev.reset_banks.back(), 0u);
        }
    }
}

TEST(BlackholeTensixResetTest, LeaseLossAfterLastCommandPreventsPublication) {
    ResetDevice dev;
    blackhole::TensixReset<ResetDevice> reset(dev);
    const auto old = reset.run(worker);
    dev.release_loses_lease = true;
    EXPECT_THROW(reset.run(worker), std::runtime_error);
    EXPECT_FALSE(reset.matches(worker, old));
}

}  // namespace
}  // namespace tt::umd
