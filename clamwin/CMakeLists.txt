cmake_minimum_required(VERSION 3.15)
project(amaru-clamwin VERSION 0.1.0 LANGUAGES C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(CLAMAV REQUIRED libclamav)

# Include directories
include_directories(
    ${CLAMAV_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Define sources
set(SOURCES
    src/clamav_scanner.cpp
    src/clamav_db_updater.cpp
    src/ffi_bridge.cpp
)

# Create shared library
add_library(amaru_clamwin SHARED ${SOURCES})

# Link against dependencies
target_link_libraries(amaru_clamwin
    ${CLAMAV_LIBRARIES}
)

# Set library properties
set_target_properties(amaru_clamwin PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    PUBLIC_HEADER "include/amaru_clamwin.h"
)

# Install targets
install(TARGETS amaru_clamwin
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
) 