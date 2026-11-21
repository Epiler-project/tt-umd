// SPDX-FileCopyrightText: © 2024 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include "umd/device/tt_device/wormhole_tt_device.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <tt-logger/tt-logger.hpp>
#include <utility>
#include <vector>

#include "noc_access.hpp"
#include "tracy.hpp"
#include "tt_device/wormhole_tensix_reset.hpp"
#include "umd/device/arch/architecture_implementation.hpp"
#include "umd/device/arch/wormhole_implementation.hpp"
#include "umd/device/coordinates/coordinate_manager.hpp"
#include "umd/device/jtag/jtag_device.hpp"
#include "umd/device/pcie/pci_device.hpp"
#include "umd/device/soc_descriptor.hpp"
#include "umd/device/tt_device/firmware/device_firmware.hpp"
#include "umd/device/tt_device/hang_detection/hang_detector.hpp"
#include "umd/device/tt_device/hang_detection/wormhole_hang_detector.hpp"
#include "umd/device/tt_device/protocol/remote_interface.hpp"
#include "umd/device/tt_device/remote_communication.hpp"
#include "umd/device/tt_device/tt_device_error.hpp"
#include "umd/device/types/arch.hpp"
#include "umd/device/types/cluster_descriptor_types.hpp"
#include "umd/device/types/communication_protocol.hpp"
#include "umd/device/types/core_coordinates.hpp"
#include "umd/device/types/wormhole_eth.hpp"
#include "umd/device/types/xy_pair.hpp"
#include "umd/device/utils/error.hpp"
#include "utils.hpp"

namespace tt::umd {

struct WormholeTTDevice::ResetController {
    explicit ResetController(WormholeTTDevice& device) : device(device), reset(*this) {}

    bool has_exclusive_execution() const {
        auto* pci = device.get_pci_device();
        return pci != nullptr && pci->get_connection().has_exclusive_execution();
    }

    void check_worker(CoreCoord worker) const {
        const auto workers = device.get_soc_descriptor().get_cores(CoreType::TENSIX, CoordSystem::NOC0);
        UMD_ASSERT(
            std::find(workers.begin(), workers.end(), worker) != workers.end(),
            error::RuntimeError,
            "Tensix reset requires an active physical NOC0 Tensix worker.");
    }

    void power_up() { device.set_power_state(PowerState::BUSY, NocId::NOC0); }

    uint32_t read_soft_reset(CoreCoord worker) const {
        uint32_t value = 0;
        device.read_from_device_reg(&value, worker, wormhole::TENSIX_SOFT_RESET_ADDR, sizeof(value), NocId::NOC0);
        return value;
    }

    void write_soft_reset(CoreCoord worker, uint32_t value) {
        device.write_to_device_reg(&value, worker, wormhole::TENSIX_SOFT_RESET_ADDR, sizeof(value), NocId::NOC0);
    }

    WormholeTTDevice& device;
    wormhole::TensixReset<ResetController> reset;
};

WormholeTTDevice::WormholeTTDevice(std::unique_ptr<TTDeviceModel> model) :
    TTDevice(std::move(model)), reset_controller_(std::make_unique<ResetController>(*this)) {}

WormholeTTDevice::~WormholeTTDevice() = default;

uint64_t WormholeTTDevice::reset_tensix_tiles(CoreCoord worker) { return reset_controller_->reset.run(worker); }

bool WormholeTTDevice::has_tensix_reset(CoreCoord worker, uint64_t epoch) const {
    return reset_controller_->reset.matches(worker, epoch);
}

uint32_t WormholeTTDevice::get_clock() {
    // There is one return value from AICLK ARC message.
    DeviceCommandResult result = get_device_firmware()->send_device_command(
        wormhole::ARC_MSG_COMMON_PREFIX | static_cast<uint32_t>(wormhole::arc_message_type::GET_AICLK),
        {0xFFFF, 0xFFFF},
        timeout::ARC_MESSAGE_TIMEOUT,
        get_selected_noc_id());
    if (result.exit_code != 0) {
        UMD_THROW(error::RuntimeError, fmt::format("Failed to get AICLK value with exit code: {}", result.exit_code));
    }
    return result.return_values.at(0);
}

uint32_t WormholeTTDevice::get_min_clock_freq() { return get_architecture_implementation()->get_min_clock_freq(); }

void WormholeTTDevice::configure_iatu_region(size_t region, uint64_t target, size_t region_size) {
    uint32_t dest_bar_lo = target & 0xffffffff;
    uint32_t dest_bar_hi = (target >> 32) & 0xffffffff;
    std::uint32_t region_id_to_use = region;

    // TODO: stop doing this.  It's related to HUGEPAGE_CHANNEL_3_SIZE_LIMIT.
    if (region == 3) {
        region_id_to_use = 4;  // Hack use region 4 for channel 3..this ensures that we have a smaller chan 3 address
                               // space with the correct start offset
    }

    if (get_communication_device_type() == IODeviceType::JTAG) {
        UMD_THROW(error::RuntimeError, "configure_iatu_region is redundant for JTAG communication type.");
    }

    bar_write32(registers_.arc_csm_bar0_mailbox_offset + 0 * 4, region_id_to_use);
    bar_write32(registers_.arc_csm_bar0_mailbox_offset + 1 * 4, dest_bar_lo);
    bar_write32(registers_.arc_csm_bar0_mailbox_offset + 2 * 4, dest_bar_hi);
    bar_write32(registers_.arc_csm_bar0_mailbox_offset + 3 * 4, region_size);
    get_device_firmware()->send_device_command(
        wormhole::ARC_MSG_COMMON_PREFIX |
            static_cast<uint32_t>(wormhole::arc_message_type::SETUP_IATU_FOR_PEER_TO_PEER),
        {0, 0},
        timeout::ARC_MESSAGE_TIMEOUT,
        get_selected_noc_id());

    // Print what just happened.
    uint32_t peer_region_start = region_id_to_use * region_size;
    uint32_t peer_region_end = (region_id_to_use + 1) * region_size - 1;
    log_debug(
        LogUMD,
        "    [region id {}] NOC to PCI address range 0x{:x}-0x{:x} mapped to addr 0x{:x}",
        region,
        peer_region_start,
        peer_region_end,
        target);
}

void WormholeTTDevice::read_from_arc_apb(void *mem_ptr, uint64_t arc_addr_offset, size_t size) {
    if (arc_addr_offset > wormhole::ARC_APB_ADDRESS_RANGE) {
        UMD_THROW(error::RuntimeError, "Address is out of ARC APB address range.");
    }
    if (is_remote()) {
        read_from_device_reg(mem_ptr, get_arc_core(), registers_.arc_apb_noc_base_address + arc_addr_offset, size);
        return;
    }
    if (get_communication_device_type() == IODeviceType::JTAG) {
        get_device_protocol()->read_ctrl(
            mem_ptr,
            wormhole::ARC_CORES_NOC0[0],
            registers_.arc_apb_noc_base_address + arc_addr_offset,
            sizeof(uint32_t),
            NocId::DEFAULT_NOC);
        return;
    }
    auto result = bar_read32(registers_.arc_apb_bar0_offset + arc_addr_offset);
    *(reinterpret_cast<uint32_t *>(mem_ptr)) = result;
}

void WormholeTTDevice::write_to_arc_apb(const void *mem_ptr, uint64_t arc_addr_offset, size_t size) {
    if (arc_addr_offset > wormhole::ARC_APB_ADDRESS_RANGE) {
        UMD_THROW(error::RuntimeError, "Address is out of ARC APB address range.");
    }
    if (is_remote()) {
        write_to_device_reg(mem_ptr, get_arc_core(), registers_.arc_apb_noc_base_address + arc_addr_offset, size);
        return;
    }
    if (get_communication_device_type() == IODeviceType::JTAG) {
        get_device_protocol()->write_ctrl(
            mem_ptr,
            wormhole::ARC_CORES_NOC0[0],
            registers_.arc_apb_noc_base_address + arc_addr_offset,
            sizeof(uint32_t),
            NocId::DEFAULT_NOC);
        return;
    }
    bar_write32(registers_.arc_apb_bar0_offset + arc_addr_offset, *(reinterpret_cast<const uint32_t *>(mem_ptr)));
}

}  // namespace tt::umd
