// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "tt_device/wormhole_tensix_reset.hpp"

namespace tt::umd {
namespace {

constexpr CoreCoord worker{1, 1, CoreType::TENSIX, CoordSystem::NOC0};
constexpr CoreCoord other{2, 1, CoreType::TENSIX, CoordSystem::NOC0};

struct WormholeResetDevice {
    bool exclusive = true;
    bool lose_exclusivity_after_clear = false;
    uint32_t fail_latch_mask = 0;
    uint32_t soft_reset_reg = 0;
    unsigned power_votes = 0;
    std::vector<uint32_t> writes;

    bool has_exclusive_execution() const { return exclusive; }

    void check_worker(CoreCoord core) const {
        if (!(core == worker || core == other)) {
            throw std::runtime_error("invalid worker");
        }
    }

    void power_up() { ++power_votes; }

    uint32_t read_soft_reset(CoreCoord core) const {
        EXPECT_EQ(core, worker);
        return soft_reset_reg;
    }

    void write_soft_reset(CoreCoord core, uint32_t value) {
        EXPECT_EQ(core, worker);
        writes.push_back(value);
        if (value != fail_latch_mask) {
            soft_reset_reg = value;
        }
        if (writes.size() == 3 && lose_exclusivity_after_clear) {
            exclusive = false;
        }
    }
};

TEST(WormholeTensixResetTest, PulsesVectorMatrixResetUnderRiscHoldAndRestoresRiscOnlyMask) {
    WormholeResetDevice dev;
    wormhole::TensixReset<WormholeResetDevice> reset(dev);
    EXPECT_FALSE(reset.matches(worker, 0));

    const auto first = reset.run(worker);
    ASSERT_NE(first, 0u);
    EXPECT_TRUE(reset.matches(worker, first));
    EXPECT_FALSE(reset.matches(other, first));
    EXPECT_FALSE(reset.matches({1, 1, CoreType::ETH, CoordSystem::NOC0}, first));
    EXPECT_EQ(dev.power_votes, 1u);
    EXPECT_EQ(dev.soft_reset_reg, 0x47800u);
    EXPECT_EQ(dev.writes, (std::vector<uint32_t>{0x47800u, 0x47c00u, 0x47800u}));

    const auto second = reset.run(worker);
    EXPECT_NE(second, first);
    EXPECT_FALSE(reset.matches(worker, first));
    EXPECT_TRUE(reset.matches(worker, second));

    dev.exclusive = false;
    EXPECT_FALSE(reset.matches(worker, second));
}

TEST(WormholeTensixResetTest, RefusesMissingExclusivityAndInvalidWorkerBeforePowerOrWrites) {
    WormholeResetDevice dev;
    wormhole::TensixReset<WormholeResetDevice> reset(dev);
    dev.exclusive = false;
    EXPECT_THROW(reset.run(worker), std::runtime_error);
    dev.exclusive = true;
    EXPECT_THROW(reset.run({1, 1, CoreType::TENSIX, CoordSystem::LOGICAL}), std::runtime_error);
    EXPECT_EQ(dev.power_votes, 0u);
    EXPECT_TRUE(dev.writes.empty());
}

TEST(WormholeTensixResetTest, RequiresObservedSoftResetReadbackAtEachStageAndRevokesPriorEpoch) {
    for (uint32_t mask : {0x47800u, 0x47c00u}) {
        WormholeResetDevice dev;
        wormhole::TensixReset<WormholeResetDevice> reset(dev);
        const auto old = reset.run(worker);
        dev.writes.clear();
        dev.fail_latch_mask = mask;
        EXPECT_THROW(reset.run(worker), std::runtime_error);
        EXPECT_FALSE(reset.matches(worker, old));
    }
}

TEST(WormholeTensixResetTest, ExclusivityLossBeforePublicationRejectsEpoch) {
    WormholeResetDevice dev;
    wormhole::TensixReset<WormholeResetDevice> reset(dev);
    const auto old = reset.run(worker);
    dev.writes.clear();
    dev.lose_exclusivity_after_clear = true;
    EXPECT_THROW(reset.run(worker), std::runtime_error);
    EXPECT_FALSE(reset.matches(worker, old));
}

}  // namespace
}  // namespace tt::umd
