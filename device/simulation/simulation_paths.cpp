// SPDX-FileCopyrightText: © 2025 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include "umd/device/simulation/simulation_chip.hpp"

namespace tt::umd {

std::string SimulationChip::get_soc_descriptor_path_from_simulator_path(const std::filesystem::path& simulator_path) {
    return (simulator_path.extension() == ".so") ? (simulator_path.parent_path() / "soc_descriptor.yaml")
                                                 : (simulator_path / "soc_descriptor.yaml");
}

std::string SimulationChip::get_cluster_descriptor_path_from_simulator_path(
    const std::filesystem::path& simulator_path) {
    return (simulator_path.extension() == ".so") ? (simulator_path.parent_path() / "cluster_descriptor.yaml")
                                                 : (simulator_path / "cluster_descriptor.yaml");
}

}  // namespace tt::umd
