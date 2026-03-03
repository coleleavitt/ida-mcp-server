cmake_minimum_required(VERSION 3.20)
project(ida_mcp_server VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# =============================================================================
# IDA SDK Configuration
# =============================================================================
# Priority: CMake cache > environment variable > default
# Override via: cmake -DIDASDK_DIR=/path/to/sdk or IDASDK_DIR=/path/to/sdk cmake ..

# IDA SDK directory
if(NOT DEFINED IDASDK_DIR)
    if(DEFINED ENV{IDASDK_DIR})
        set(IDASDK_DIR "$ENV{IDASDK_DIR}" CACHE PATH "IDA SDK directory")
    else()
        set(IDASDK_DIR "$ENV{HOME}/Downloads/Software/IDAPro/idasdk93" CACHE PATH "IDA SDK directory (default)")
    endif()
endif()

# IDA installation directory
if(NOT DEFINED IDA_INSTALL_DIR)
    if(DEFINED ENV{IDA_INSTALL_DIR})
        set(IDA_INSTALL_DIR "$ENV{IDA_INSTALL_DIR}" CACHE PATH "IDA installation directory")
    else()
        set(IDA_INSTALL_DIR "$ENV{HOME}/Downloads/Software/IDAPro/ida-pro-9.33" CACHE PATH "IDA installation directory (default)")
    endif()
endif()

# Validate SDK directory exists
if(NOT EXISTS "${IDASDK_DIR}/include")
    message(WARNING "IDA SDK not found at ${IDASDK_DIR}. Set IDASDK_DIR to your SDK path.")
endif()

# =============================================================================
# Build Options
# =============================================================================

# Hex-Rays decompiler support (optional - set OFF if you don't have Hex-Rays license)
option(WITH_HEXRAYS "Build with Hex-Rays decompiler support" OFF)

# =============================================================================
# Include Directories
# =============================================================================
include_directories(
        ${PROJECT_SOURCE_DIR}/include
)

# =============================================================================
# Dependencies
# =============================================================================
find_package(Boost 1.75 REQUIRED COMPONENTS system thread)
find_package(nlohmann_json 3.0 REQUIRED)

# =============================================================================
# Platform Detection and Compiler Flags
# =============================================================================
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(IDA_PLATFORM "__LINUX__")
    set(IDA_LIB_SUBDIR "x64_linux_gcc_64")
    set(IDA_PLATFORM_LIBS pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(IDA_PLATFORM "__MAC__")
    set(IDA_LIB_SUBDIR "x64_mac_clang_64")
    set(IDA_PLATFORM_LIBS pthread)  # macOS doesn't need -ldl
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(IDA_PLATFORM "__NT__")
    set(IDA_LIB_SUBDIR "x64_win_vc_64")
    set(IDA_PLATFORM_LIBS "")
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -fPIC)
endif()

# Platform definitions required by IDA SDK
add_definitions(-D${IDA_PLATFORM} -D__X64__)
if(WITH_HEXRAYS)
    add_definitions(-DHAS_HEXRAYS)
endif()

# =============================================================================
# Link Directories
# =============================================================================
link_directories(
        ${IDASDK_DIR}/lib/${IDA_LIB_SUBDIR}
        ${IDA_INSTALL_DIR}
)

# =============================================================================
# Source Files
# =============================================================================
set(HTTP_SOURCES
        src/http/server.cpp
        src/http/auth.cpp
)

set(MCP_SOURCES
        src/mcp/protocol.cpp
        src/mcp/server.cpp
)

# Core tools (always built)
set(TOOLS_SOURCES
        src/tools/tools.cpp
        src/tools/database.cpp
        src/tools/segments.cpp
        src/tools/functions.cpp
        src/tools/xrefs.cpp
        src/tools/strings.cpp
        src/tools/search.cpp
        src/tools/instructions.cpp
        src/tools/navigation.cpp
        src/tools/comments.cpp
        src/tools/names.cpp
        src/tools/frames.cpp
        src/tools/types.cpp
        src/tools/callers.cpp
        src/tools/demangling.cpp
        src/tools/fixups.cpp
        src/tools/imports.cpp
        src/tools/exports.cpp
        src/tools/memory.cpp
        src/tools/metadata.cpp
        src/tools/offsets.cpp
        src/tools/problems.cpp
        src/tools/read_bytes.cpp
        src/tools/switches.cpp
        src/tools/symbols.cpp
        src/tools/auto_analysis.cpp
        src/tools/debugger.cpp
        src/tools/entry_points.cpp
        src/tools/exec_scripts.cpp
        src/tools/function_context.cpp
        src/tools/indirect_branches.cpp
        src/tools/control_flow.cpp
        src/tools/patching.cpp
        src/tools/undo.cpp
        src/tools/bookmarks.cpp
        src/tools/reg_search.cpp
        src/tools/bin_search.cpp
        src/tools/jumptables.cpp
        src/tools/decl_compiler.cpp
        src/tools/snippets.cpp
        src/tools/wide_values.cpp
        src/tools/metadata_backup.cpp
        src/tools/dirtree_tools.cpp
        src/tools/import_entry.cpp
)

# Hex-Rays dependent tools (conditionally built)
# Note: These files use #ifdef HAS_HEXRAYS internally, but we still need to compile them
set(HEXRAYS_TOOLS_SOURCES
        src/tools/hexrays.cpp
        src/tools/decompile_all.cpp
        src/tools/microcode.cpp
)

# Combine all sources
list(APPEND TOOLS_SOURCES ${HEXRAYS_TOOLS_SOURCES})

# =============================================================================
# Target Definition
# =============================================================================
add_library(ida_mcp_server SHARED
        src/main.cpp
        ${HTTP_SOURCES}
        ${MCP_SOURCES}
        ${TOOLS_SOURCES}
)

# Set plugin output name (IDA expects specific naming conventions)
set_target_properties(ida_mcp_server PROPERTIES
        OUTPUT_NAME "ida_mcp_server"
        PREFIX ""  # No 'lib' prefix
)

# Platform-specific suffix
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(ida_mcp_server PROPERTIES SUFFIX ".so")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(ida_mcp_server PROPERTIES SUFFIX ".dylib")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(ida_mcp_server PROPERTIES SUFFIX ".dll")
endif()

# IDA SDK includes as SYSTEM to suppress warnings from SDK headers
target_include_directories(ida_mcp_server SYSTEM PRIVATE
        ${IDASDK_DIR}/include
        ${IDASDK_DIR}/idalib
)

# Link libraries
target_link_libraries(ida_mcp_server
        PRIVATE
        Boost::system
        Boost::thread
        nlohmann_json::nlohmann_json
        ida  # IDA SDK library
        ${IDA_PLATFORM_LIBS}
)

# =============================================================================
# Installation
# =============================================================================
install(TARGETS ida_mcp_server
        LIBRARY DESTINATION "${IDA_INSTALL_DIR}/plugins"
)

# =============================================================================
# Configuration Summary
# =============================================================================
message(STATUS "")
message(STATUS "=== IDA MCP Server Configuration ===")
message(STATUS "IDA SDK directory:    ${IDASDK_DIR}")
message(STATUS "IDA installation:     ${IDA_INSTALL_DIR}")
message(STATUS "Platform:             ${CMAKE_SYSTEM_NAME} (${IDA_PLATFORM})")
message(STATUS "Build type:           ${CMAKE_BUILD_TYPE}")
message(STATUS "Hex-Rays support:     ${WITH_HEXRAYS}")
message(STATUS "=====================================")
message(STATUS "")
