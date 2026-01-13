# common is an INTERFACE library (header-only)
add_library(MiniProxifierCommon INTERFACE)

target_include_directories(MiniProxifierCommon INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Set compile definitions
target_compile_definitions(MiniProxifierCommon INTERFACE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
