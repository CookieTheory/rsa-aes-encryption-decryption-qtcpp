cmake_minimum_required(VERSION 3.16)

project(rsa-encryption-decryption-qtcpp VERSION 1.0 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(BUILD_SHARED_LIBS OFF)
find_package(OpenSSL REQUIRED)

option(CRT_LINKAGE_STATIC   "Link MSVC runtime statically"  0)
if(WIN32 AND CRT_LINKAGE_STATIC)
    #add_compile_options("/MT")
    if(POLICY CMP0091)
        cmake_policy(SET CMP0091 NEW)
    endif()
    set(OPENSSL_MSVC_STATIC_RT ON)
    set_property(TARGET ${CMAKE_PROJECT_NAME}
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Release>:Release>"
    )
endif()

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        cipher.h cipher.cpp
        basiccustomdialog.h
        basiccustomdialog.cpp
        basiccustomdialog.ui
        icon.qrc
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    if(APPLE)
        qt_add_executable(${CMAKE_PROJECT_NAME}
            MACOSX_BUNDLE
            MANUAL_FINALIZATION
            ${PROJECT_SOURCES}
        )
    elseif(WIN32)
        qt_add_executable(${CMAKE_PROJECT_NAME}
            WIN32
            MANUAL_FINALIZATION
            ${PROJECT_SOURCES}
        )
    else()
        qt_add_executable(${CMAKE_PROJECT_NAME}
            MANUAL_FINALIZATION
            ${PROJECT_SOURCES}
        )
    endif()
else()
    if(ANDROID)
        add_library(${CMAKE_PROJECT_NAME} SHARED
            ${PROJECT_SOURCES}
        )
    elseif(APPLE)
        add_executable(${CMAKE_PROJECT_NAME} ${PROJECT_SOURCES} MACOSX_BUNDLE)
    elseif(WIN32)
        add_executable(${CMAKE_PROJECT_NAME} ${PROJECT_SOURCES} WIN32)
    else()
        add_executable(${CMAKE_PROJECT_NAME} ${PROJECT_SOURCES})
    endif()
endif()

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Qt${QT_VERSION_MAJOR}::Widgets OpenSSL::SSL OpenSSL::Crypto)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.${CMAKE_PROJECT_NAME})
endif()
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS ${CMAKE_PROJECT_NAME}
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(rsa-encryption-decryption-qtcpp)
endif()
