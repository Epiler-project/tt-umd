add_executable(test_pcie_device test_pcie_device.cpp)
target_link_libraries(test_pcie_device PRIVATE test_common)
set_target_properties(
    test_pcie_device
    PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY
            ${CMAKE_BINARY_DIR}/test/umd/test_pcie_device
        OUTPUT_NAME
            test_pcie_device
)

# Exercise production reset and sender code without any physical device access.
# Do not link test_common: syscall wrapping must reach the static C library and
# sender object directly instead of calls already bound inside the UMD DSO.
add_executable(test_kmd_reset test_kmd_reset.cpp ../../device/pcie/pci_device_reset.cpp)
target_compile_features(test_kmd_reset PRIVATE cxx_std_17)
target_include_directories(test_kmd_reset PRIVATE
    ../../device ../../device/api ../../tt-kmd-lib/src)
target_link_libraries(test_kmd_reset PRIVATE
    gtest_main tt-kmd-lib::tt-kmd-lib fmt::fmt-header-only pthread)
target_link_options(test_kmd_reset PRIVATE
    "LINKER:--wrap=open,--wrap=__open_2,--wrap=ioctl,--wrap=close,--wrap=calloc,--wrap=free")
set_target_properties(test_kmd_reset PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test/umd/test_kmd_reset)

add_executable(test_pci_device_connection test_pci_device_connection.cpp)
target_compile_features(test_pci_device_connection PRIVATE cxx_std_17)
target_include_directories(test_pci_device_connection PRIVATE ../../tt-kmd-lib/src)
target_link_libraries(test_pci_device_connection PRIVATE test_common tt-kmd-lib::tt-kmd-lib ${CMAKE_DL_LIBS})
set_target_properties(test_pci_device_connection PROPERTIES
    ENABLE_EXPORTS ON CXX_VISIBILITY_PRESET default
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test/umd/test_pci_device_connection)
