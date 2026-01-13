# Qt GUI launcher project
qt_add_executable(MiniProxifier
    main.cpp
    MainWindow.cpp
    MainWindow.h
    MainWindow.ui
    Injector.cpp
    Injector.h
)

# Link dependencies
target_link_libraries(MiniProxifier PRIVATE
    MiniProxifierCommon
    Qt6::Core
    Qt6::Widgets
    ws2_32
    kernel32
    psapi
)

# Set Windows GUI application
set_target_properties(MiniProxifier PROPERTIES
    WIN32_EXECUTABLE TRUE
    OUTPUT_NAME "MiniProxifier_${ARCH_SUFFIX}"
)

# Copy Hook DLL to output directory after build
add_custom_command(TARGET MiniProxifier POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:MiniProxifierHook>
        $<TARGET_FILE_DIR:MiniProxifier>
    COMMENT "Copying MiniProxifierHook DLL..."
)

# Qt deployment (windeployqt)
if(WIN32)
    # Find windeployqt
    get_target_property(_qmake_executable Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(_qt_bin_dir "${_qmake_executable}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${_qt_bin_dir}")

    if(WINDEPLOYQT_EXECUTABLE)
        add_custom_command(TARGET MiniProxifier POST_BUILD
            COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                --no-translations
                --no-system-d3d-compiler
                --no-opengl-sw
                "$<TARGET_FILE:MiniProxifier>"
            COMMENT "Running windeployqt..."
        )
    endif()
endif()
