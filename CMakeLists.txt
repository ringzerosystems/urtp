cmake_minimum_required(VERSION 3.28)

project(urtp
    VERSION 0.9.0
    DESCRIPTION "High-throughput, sub-millisecond latency RTP media proxy built for modern Linux"
    HOMEPAGE_URL "https://github.com/Heoruwulf/urtp"
    LANGUAGES C
)

# Enforce modern C23 standard with GNU extensions (-std=gnu23)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Export compile commands for language servers and tooling (clangd, etc.)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(URTP_BUILD_TESTS "Build urtp test suite" ON)
option(URTP_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(URTP_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(URTP_ENABLE_WERROR "Treat compiler warnings as errors" ON)

# Version header generation
set(URTP_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
set(URTP_VERSION_HEADER "${URTP_GENERATED_INCLUDE_DIR}/urtp/version.h")

# Execute during configuration so headers exist immediately for tools and targets
execute_process(
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_VERSION=${PROJECT_VERSION}
        -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/generate_version.cmake
)

# Build-time custom target to keep version.h synchronized with git status on every build
add_custom_target(urtp_version
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_VERSION=${PROJECT_VERSION}
        -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/generate_version.cmake
    BYPRODUCTS "${URTP_VERSION_HEADER}"
    COMMENT "Generating version.h"
)

# Compiler warnings interface target
add_library(urtp_warnings INTERFACE)
target_compile_options(urtp_warnings INTERFACE
    $<$<C_COMPILER_ID:Clang,AppleClang>:
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wstrict-prototypes
        -Wpointer-arith
        -Wcast-qual
        -Wcast-align
        -Wwrite-strings
        -Wredundant-decls
        -Wmissing-prototypes
        -Wnested-externs
        -Wformat=2
        $<$<BOOL:${URTP_ENABLE_WERROR}>:-Werror>
    >
    $<$<C_COMPILER_ID:GNU>:
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wstrict-prototypes
        -Wpointer-arith
        -Wcast-qual
        -Wcast-align
        -Wwrite-strings
        -Wredundant-decls
        -Wmissing-prototypes
        -Wnested-externs
        -Wformat=2
        -Wno-format-truncation
        $<$<BOOL:${URTP_ENABLE_WERROR}>:-Werror>
    >
)

# Sanitizers
if(URTP_ENABLE_ASAN)
    target_compile_options(urtp_warnings INTERFACE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(urtp_warnings INTERFACE -fsanitize=address)
endif()

if(URTP_ENABLE_UBSAN)
    target_compile_options(urtp_warnings INTERFACE -fsanitize=undefined)
    target_link_options(urtp_warnings INTERFACE -fsanitize=undefined)
endif()

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURING REQUIRED IMPORTED_TARGET liburing)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Crypto dependency: libsrtp2
pkg_check_modules(LIBSRTP2 QUIET IMPORTED_TARGET libsrtp2)

if(TARGET PkgConfig::LIBSRTP2)
    add_library(srtp_target INTERFACE)
    target_link_libraries(srtp_target INTERFACE PkgConfig::LIBSRTP2)
else()
    include(FetchContent)
    set(LIBSRTP_TEST_APPS OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        libsrtp2
        GIT_REPOSITORY https://github.com/cisco/libsrtp.git
        GIT_TAG        v2.6.0
    )
    FetchContent_MakeAvailable(libsrtp2)
    add_library(srtp_target INTERFACE)
    target_link_libraries(srtp_target INTERFACE srtp2)
endif()

# Media transcoding dependencies: libopus and ffmpeg
if(DEFINED ENV{HOME})
    set(ENV{PKG_CONFIG_PATH} "$ENV{HOME}/.local/lib/x86_64-linux-gnu/pkgconfig:$ENV{HOME}/.local/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    list(APPEND CMAKE_PREFIX_PATH "$ENV{HOME}/.local")
endif()

pkg_check_modules(LIBOPUS REQUIRED IMPORTED_TARGET opus)
pkg_check_modules(AVCODEC REQUIRED IMPORTED_TARGET libavcodec)
pkg_check_modules(AVUTIL REQUIRED IMPORTED_TARGET libavutil)
pkg_check_modules(SWRESAMPLE REQUIRED IMPORTED_TARGET libswresample)

# Core library (unidirectional functional domain: core/)
add_library(urtp_core STATIC
    src/core/memory.c
    src/core/metrics.c
    src/core/watchdog.c
)
add_library(urtp::core ALIAS urtp_core)

target_include_directories(urtp_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/core>
        $<BUILD_INTERFACE:${URTP_GENERATED_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(urtp_core
    PUBLIC
        urtp_warnings
        Threads::Threads
)

add_dependencies(urtp_core urtp_version)

# Crypto library (unidirectional functional domain: crypto/)
add_library(urtp_crypto STATIC
    src/crypto/base64.c
    src/crypto/sdes.c
    src/crypto/srtp_session.c
    src/crypto/dtls.c
)
add_library(urtp::crypto ALIAS urtp_crypto)

target_include_directories(urtp_crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(urtp_crypto
    PUBLIC
        urtp_core
        srtp_target
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Ring library (unidirectional functional domain: ring/)
add_library(urtp_ring STATIC
    src/ring/ring.c
    src/ring/timer.c
)
add_library(urtp::ring ALIAS urtp_ring)

target_include_directories(urtp_ring
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(urtp_ring
    PUBLIC
        urtp_core
        PkgConfig::LIBURING
)

# Media library (unidirectional functional domain: media/)
add_library(urtp_media STATIC
    src/media/transcode.c
    src/media/jitter.c
)
add_library(urtp::media ALIAS urtp_media)

target_include_directories(urtp_media
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/media>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(urtp_media
    PUBLIC
        urtp_core
        urtp_warnings
        PkgConfig::LIBOPUS
        PkgConfig::AVCODEC
        PkgConfig::AVUTIL
        PkgConfig::SWRESAMPLE
)

# Net library (unidirectional functional domain: net/)
add_library(urtp_net STATIC
    src/net/udp.c
    src/net/session.c
    src/net/stun.c
    src/net/pcap.c
)
add_library(urtp::net ALIAS urtp_net)

target_include_directories(urtp_net
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(urtp_net
    PUBLIC
        urtp_core
        urtp_crypto
        urtp_ring
        urtp_media
)

# Control library (unidirectional functional domain: control/)
add_library(urtp_control STATIC
    src/control/bencode.c
    src/control/sdp.c
    src/control/ng_call.c
    src/control/ng_negotiate.c
    src/control/ng_cmd.c
    src/control/ng_msg.c
    src/control/control.c
)
add_library(urtp::control ALIAS urtp_control)

target_include_directories(urtp_control
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(urtp_control
    PUBLIC
        urtp_core
        urtp_crypto
        urtp_ring
        urtp_net
        urtp_media
)

# Main urtp daemon executable
add_executable(urtp
    src/server.c
    src/main.c
)

add_dependencies(urtp urtp_version)

target_link_libraries(urtp
    PRIVATE
        urtp_control
        urtp_net
        urtp_media
        urtp_ring
        urtp_crypto
        urtp_core
        PkgConfig::LIBURING
)

# Installation
include(GNUInstallDirs)
install(TARGETS urtp
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES "${URTP_VERSION_HEADER}"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/urtp
    OPTIONAL
)

# Testing with Unity and CTest
include(CTest)

if(BUILD_TESTING AND URTP_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        unity
        GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
        GIT_TAG        v2.6.1
    )
    FetchContent_MakeAvailable(unity)

    add_subdirectory(tests)
endif()
