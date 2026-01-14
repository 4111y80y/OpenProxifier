set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)

add_executable(ProxyTestApp WIN32
    main.cpp
    TestAppWindow.h
    TestAppWindow.cpp
)

target_link_libraries(ProxyTestApp PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
)

# Copy to main binary directory
add_custom_command(TARGET ProxyTestApp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:ProxyTestApp>
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>/ProxyTestApp.exe
    COMMENT "Copying ProxyTestApp to output directory..."
)

# Run windeployqt
add_custom_command(TARGET ProxyTestApp POST_BUILD
    COMMAND Qt6::windeployqt --no-translations $<TARGET_FILE:ProxyTestApp>
    COMMENT "Running windeployqt for ProxyTestApp..."
)
