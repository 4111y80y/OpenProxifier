cmake_minimum_required(VERSION 3.20)

project(OpenProxifierCLI C)

set(CMAKE_C_STANDARD 11)

# Note: core library is added by parent CMakeLists.txt

# CLI executable
add_executable(OpenProxifierCLI main.c)

# Link with core library
target_link_libraries(OpenProxifierCLI PRIVATE ProxyEngineCore)

# Windows-specific
if(WIN32)
    target_compile_definitions(OpenProxifierCLI PRIVATE
        _WIN32_WINNT=0x0601
        WIN32_LEAN_AND_MEAN
    )
endif()

# Copy WinDivert files to output
set(WINDIVERT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../windivert")
add_custom_command(TARGET OpenProxifierCLI POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/x64/WinDivert.dll"
        "$<TARGET_FILE_DIR:OpenProxifierCLI>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/x64/WinDivert64.sys"
        "$<TARGET_FILE_DIR:OpenProxifierCLI>"
)
