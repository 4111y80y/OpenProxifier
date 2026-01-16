cmake_minimum_required(VERSION 3.20)

project(ProxyEngineCore C)

set(CMAKE_C_STANDARD 11)

# WinDivert paths
set(WINDIVERT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../windivert")
set(WINDIVERT_INCLUDE "${WINDIVERT_DIR}/include")
set(WINDIVERT_LIB "${WINDIVERT_DIR}/x64/WinDivert.lib")

# Source files
set(SOURCES
    ProxyEngine.c
    PacketProcessor.c
    LocalProxy.c
    ConnectionTracker.c
    RuleEngine.c
    Socks5.c
    ProcessTracker.c
    UdpRelay.c
)

set(HEADERS
    ProxyEngine.h
    PacketProcessor.h
    LocalProxy.h
    ConnectionTracker.h
    RuleEngine.h
    Socks5.h
    ProcessTracker.h
    UdpRelay.h
)

# Create static library
add_library(ProxyEngineCore STATIC ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(ProxyEngineCore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WINDIVERT_INCLUDE}
)

# Link libraries
target_link_libraries(ProxyEngineCore PUBLIC
    ${WINDIVERT_LIB}
    ws2_32
    iphlpapi
)

# Windows-specific
if(WIN32)
    target_compile_definitions(ProxyEngineCore PRIVATE
        _WIN32_WINNT=0x0601
        WIN32_LEAN_AND_MEAN
    )
endif()

# Copy WinDivert DLL and SYS to output directory
add_custom_command(TARGET ProxyEngineCore POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/x64/WinDivert.dll"
        "$<TARGET_FILE_DIR:ProxyEngineCore>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/x64/WinDivert64.sys"
        "$<TARGET_FILE_DIR:ProxyEngineCore>"
)
