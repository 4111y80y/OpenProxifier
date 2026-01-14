set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)

add_executable(Antigravity WIN32
    main.cpp
    AntigravityWindow.h
    AntigravityWindow.cpp
)

target_link_libraries(Antigravity PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
)

# Copy to main binary directory
add_custom_command(TARGET Antigravity POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:Antigravity>
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>/Antigravity.exe
    COMMENT "Copying Antigravity to output directory..."
)

# Run windeployqt
add_custom_command(TARGET Antigravity POST_BUILD
    COMMAND Qt6::windeployqt --no-translations $<TARGET_FILE:Antigravity>
    COMMENT "Running windeployqt for Antigravity..."
)
