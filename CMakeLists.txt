cmake_minimum_required(VERSION 3.20)
project(MiniProxifier VERSION 1.0.0 LANGUAGES CXX)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows platform check
if(NOT WIN32)
    message(FATAL_ERROR "This project only supports Windows platform")
endif()

# Qt auto tools
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Architecture detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_SUFFIX "x64")
    message(STATUS "Building for 64-bit architecture")
else()
    set(ARCH_SUFFIX "x86")
    message(STATUS "Building for 32-bit architecture")
endif()

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)
qt_standard_project_setup()

# Find Microsoft Detours (via vcpkg)
find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
find_library(DETOURS_LIBRARY detours REQUIRED)

message(STATUS "Detours include: ${DETOURS_INCLUDE_DIRS}")
message(STATUS "Detours library: ${DETOURS_LIBRARY}")

# Export architecture suffix for subprojects
set(ARCH_SUFFIX ${ARCH_SUFFIX} CACHE STRING "Architecture suffix" FORCE)

# Add subprojects
add_subdirectory(common)
add_subdirectory(hookdll)
add_subdirectory(launcher)

# Ensure hookdll is built before launcher
add_dependencies(MiniProxifier MiniProxifierHook)
