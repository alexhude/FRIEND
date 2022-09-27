cmake_minimum_required(VERSION 3.3)
project(HintEditor Swift)

include(BundleUtilities)

set(CMAKE_Swift_LANGUAGE_VERSION 5)

# use latest macOS SDK
set(CMAKE_OSX_SYSROOT "macosx")

# set minimum deployment target
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.10")

set(
    HEADERS
    HintEditor-Bridging-Header.h
)

set(
    SOURCES
    AppDelegate.swift
    ViewController.swift
)

set(
    STORYBOARDS
    storyboards/Main.storyboard
)

# Create the app target
add_executable(
    ${PROJECT_NAME}
    MACOSX_BUNDLE
    ${HEADERS}
    ${SOURCES}
    ${STORYBOARDS}
)

# Find AEXML
find_library(
    FRAMEWORK_AEXML
    NAMES AEXML
    PATHS ${PROJECT_SOURCE_DIR}/../Dependencies
    REQUIRED
)

# Link the app to AEXML
target_link_libraries(
    ${PROJECT_NAME}
    ${FRAMEWORK_AEXML}
)

# Set app properties
set_property(
    TARGET
    ${PROJECT_NAME}
    PROPERTY XCODE_ATTRIBUTE_SWIFT_OBJC_BRIDGING_HEADER
    "HintEditor-Bridging-Header.h"
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    MACOSX_BUNDLE YES
    RESOURCE "${STORYBOARDS}"
    
    MACOSX_BUNDLE_INFO_PLIST "${PROJECT_SOURCE_DIR}/Info.plist"
    # Set the app's linker search path to the default location on iOS
    XCODE_ATTRIBUTE_LD_RUNPATH_SEARCH_PATHS "@executable_path/../Frameworks"
)

# Create Frameworks directory in app bundle
set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    XCODE_ATTRIBUTE_PRODUCT_NAME
    "${PROJECT_NAME}"
    XCODE_ATTRIBUTE_BUNDLE_IDENTIFIER
    "com.FriedApple.${PROJECT_NAME}"
)

# Copy the framework into the bundle
add_custom_command(
    TARGET
    ${PROJECT_NAME}
    POST_BUILD COMMAND ${CMAKE_COMMAND} -E make_directory
    ${PROJECT_BINARY_DIR}/$<CONFIG>${CMAKE_XCODE_EFFECTIVE_PLATFORMS}/${PROJECT_NAME}.app/Contents/Frameworks/
)

# Copy the framework into the bundle
add_custom_command(
    TARGET
    ${PROJECT_NAME}
    POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${PROJECT_SOURCE_DIR}/../Dependencies/
    ${PROJECT_BINARY_DIR}/$<CONFIG>${CMAKE_XCODE_EFFECTIVE_PLATFORMS}/${PROJECT_NAME}.app/Contents/Frameworks/
)
