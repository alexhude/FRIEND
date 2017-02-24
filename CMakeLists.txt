cmake_minimum_required(VERSION 2.8.12)

project(FRIEND C CXX)
include(ExternalProject)

if(APPLE)
    if(CMAKE_GENERATOR STREQUAL Xcode)
        # for Xcode set latest macOS SDK and 32bit architecture
        set(CMAKE_OSX_SYSROOT "macosx")
        set(CMAKE_OSX_ARCHITECTURES "$(ARCHS_STANDARD_32_BIT)")
    endif()
endif()

# idasdk
set(IdaSdk_DIR ${PROJECT_SOURCE_DIR}/idasdk)

# capstone
set(CAPSTONE_ROOT    "${CMAKE_BINARY_DIR}/third_party/capstone")
set(CAPSTONE_GIT_URL "https://github.com/aquynh/capstone")
set(CAPSTONE_GIT_TAG "")
set(CAPSTONE_PATCHES "${PROJECT_SOURCE_DIR}/Patches/capstone.diff")

# pugixml
set(PUGIXML_ROOT     "${CMAKE_BINARY_DIR}/third_party/pugixml")
set(PUGIXML_GIT_URL  "https://github.com/zeux/pugixml")
set(PUGIXML_GIT_TAG  "")

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package(Git REQUIRED)
find_package(IdaSdk REQUIRED)

if(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++11")
    set(CMAKE_SKIP_BUILD_RPATH TRUE)
    if(NOT COMPILE_64BIT)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
    endif()
elseif(WIN32)
    if(MSVC)
        foreach(cur_var CMAKE_C_FLAGS
                        CMAKE_C_FLAGS_DEBUG
        				CMAKE_C_FLAGS_RELEASE
        				CMAKE_C_FLAGS_MINSIZEREL
        				CMAKE_C_FLAGS_RELWITHDEBINFO
        				CMAKE_CXX_FLAGS
                        CMAKE_CXX_FLAGS_DEBUG
                        CMAKE_CXX_FLAGS_RELEASE
                        CMAKE_CXX_FLAGS_MINSIZEREL
                        CMAKE_CXX_FLAGS_RELWITHDEBINFO)
			string(REGEX REPLACE "/(LD|(M(T|D)))d?( +|$)" "/MD " new_var ${${cur_var}})
			string(REGEX REPLACE "(/|-)D *_DEBUG" "" new_var ${new_var})
			set(${cur_var} ${new_var} CACHE STRING "" FORCE)
        endforeach(cur_var)
    endif()
endif()

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DNDEBUG)
endif()

# build capstone
ExternalProject_Add(
    capstone
    PREFIX              "${CAPSTONE_ROOT}"
    INSTALL_DIR         "${CAPSTONE_ROOT}"
    GIT_REPOSITORY      "${CAPSTONE_GIT_URL}"
    GIT_TAG             "${CAPSTONE_GIT_TAG}"
    PATCH_COMMAND       ${GIT_EXECUTABLE} reset --hard && ${GIT_EXECUTABLE} apply --ignore-whitespace --whitespace=nowarn ${CAPSTONE_PATCHES}
    CMAKE_ARGS          -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                        -DCAPSTONE_BUILD_SHARED=OFF
                        -DCAPSTONE_BUILD_TESTS=OFF
                        -DCAPSTONE_MIPS_SUPPORT=OFF
                        -DCAPSTONE_PPC_SUPPORT=OFF
                        -DCAPSTONE_SPARC_SUPPORT=OFF
                        -DCAPSTONE_SYSZ_SUPPORT=OFF
                        -DCAPSTONE_XCORE_SUPPORT=OFF
                        -DCAPSTONE_X86_SUPPORT=OFF
                        -DCMAKE_OSX_SYSROOT:STRING=${CMAKE_OSX_SYSROOT}
                        -DCMAKE_OSX_ARCHITECTURES:STRING=${CMAKE_OSX_ARCHITECTURES}
                        -DCMAKE_C_FLAGS:STRING=${CMAKE_C_FLAGS}
                        -DCMAKE_C_FLAGS_DEBUG:STRING=${CMAKE_C_FLAGS_DEBUG}
                        -DCMAKE_C_FLAGS_RELEASE:STRING=${CMAKE_C_FLAGS_RELEASE}
                        -DCMAKE_C_FLAGS_MINSIZEREL:STRING=${CMAKE_C_FLAGS_MINSIZEREL}
                        -DCMAKE_C_FLAGS_RELWITHDEBINFO:STRING=${CMAKE_C_FLAGS_RELWITHDEBINFO}
                        -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
                        -DCMAKE_CXX_FLAGS_DEBUG:STRING=${DCMAKE_CXX_FLAGS_DEBUG}
                        -DCMAKE_CXX_FLAGS_RELEASE:STRING=${DCMAKE_CXX_FLAGS_RELEASE}
                        -DCMAKE_CXX_FLAGS_MINSIZEREL:STRING=${DCMAKE_CXX_FLAGS_MINSIZEREL}
                        -DCMAKE_CXX_FLAGS_RELWITHDEBINFO:STRING=${DCMAKE_CXX_FLAGS_RELWITHDEBINFO}
)

# build pugixml
ExternalProject_Add(
    pugixml
    PREFIX              "${PUGIXML_ROOT}"
    INSTALL_DIR         "${PUGIXML_ROOT}"
    GIT_REPOSITORY      "${PUGIXML_GIT_URL}"
    GIT_TAG             "${PUGIXML_GIT_TAG}"
    CMAKE_ARGS          -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                        -DCMAKE_OSX_SYSROOT:STRING=${CMAKE_OSX_SYSROOT}
                        -DCMAKE_OSX_ARCHITECTURES:STRING=${CMAKE_OSX_ARCHITECTURES}
                        -DCMAKE_C_FLAGS:STRING=${CMAKE_C_FLAGS}
                        -DCMAKE_C_FLAGS_DEBUG:STRING=${CMAKE_C_FLAGS_DEBUG}
                        -DCMAKE_C_FLAGS_RELEASE:STRING=${CMAKE_C_FLAGS_RELEASE}
                        -DCMAKE_C_FLAGS_MINSIZEREL:STRING=${CMAKE_C_FLAGS_MINSIZEREL}
                        -DCMAKE_C_FLAGS_RELWITHDEBINFO:STRING=${CMAKE_C_FLAGS_RELWITHDEBINFO}
                        -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
                        -DCMAKE_CXX_FLAGS_DEBUG:STRING=${DCMAKE_CXX_FLAGS_DEBUG}
                        -DCMAKE_CXX_FLAGS_RELEASE:STRING=${DCMAKE_CXX_FLAGS_RELEASE}
                        -DCMAKE_CXX_FLAGS_MINSIZEREL:STRING=${DCMAKE_CXX_FLAGS_MINSIZEREL}
                        -DCMAKE_CXX_FLAGS_RELWITHDEBINFO:STRING=${DCMAKE_CXX_FLAGS_RELWITHDEBINFO}
)

add_library(capstone_static STATIC IMPORTED)
set_target_properties(
    capstone_static PROPERTIES IMPORTED_LOCATION
    ${CAPSTONE_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(capstone_static capstone)

add_library(pugixml_static STATIC IMPORTED)
set_target_properties(
    pugixml_static PROPERTIES IMPORTED_LOCATION
    ${PUGIXML_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}pugixml${CMAKE_STATIC_LIBRARY_SUFFIX}
)
add_dependencies(pugixml_static pugixml)

include_directories(
    ${PROJECT_SOURCE_DIR}
    ${IdaSdk_INCLUDE_DIRS}
    ${CAPSTONE_ROOT}/include/capstone/
    ${PUGIXML_ROOT}/include/
)

# add_subdirectory(tools)

if(NOT COMPILE_64BIT)
    add_ida_plugin(FRIEND EA64
                   FRIEND/AArch64Extender.cpp
                   FRIEND/Documentation.cpp
                   FRIEND/FRIEND.cpp
                   FRIEND/Settings.cpp)

    target_link_libraries(FRIEND${_plx} pugixml_static capstone_static)
    target_link_libraries(FRIEND${_plx64} pugixml_static capstone_static)
endif()
