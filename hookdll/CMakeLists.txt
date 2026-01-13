# Hook DLL project
add_library(MiniProxifierHook SHARED
    dllmain.cpp
    HookManager.cpp
    HookManager.h
    Socks5Client.cpp
    Socks5Client.h
    WinsockHooks.cpp
    WinsockHooks.h
    SocketState.h
)

# Link dependencies
target_link_libraries(MiniProxifierHook PRIVATE
    MiniProxifierCommon
    ${DETOURS_LIBRARY}
    ws2_32
    kernel32
)

target_include_directories(MiniProxifierHook PRIVATE
    ${DETOURS_INCLUDE_DIRS}
)

# Set DLL output name with architecture suffix
set_target_properties(MiniProxifierHook PROPERTIES
    OUTPUT_NAME "MiniProxifierHook_${ARCH_SUFFIX}"
    PREFIX ""
)

# Windows specific settings
target_compile_definitions(MiniProxifierHook PRIVATE
    HOOKDLL_EXPORTS
    _WINSOCK_DEPRECATED_NO_WARNINGS
)

# MSVC specific options
if(MSVC)
    target_compile_options(MiniProxifierHook PRIVATE /W4 /WX-)
endif()
