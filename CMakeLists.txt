cmake_minimum_required(VERSION 3.20)
project(ida_mcp_server VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# IDA SDK 9.3 paths (based on 9.2 SDK with 9.3 stubs)
set(IDASDK_DIR "$ENV{HOME}/Downloads/Software/IDAPro/idasdk93" CACHE PATH "IDA SDK directory")
set(IDA_INSTALL_DIR "$ENV{HOME}/Downloads/Software/IDAPro/ida-pro-9.33" CACHE PATH "IDA installation directory")

# Include directories - project headers only (SDK added as SYSTEM below)
include_directories(
        ${PROJECT_SOURCE_DIR}/include
)

# Find required packages
find_package(Boost 1.75 REQUIRED COMPONENTS system thread)
find_package(nlohmann_json 3.0 REQUIRED)

# Compiler flags
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -fPIC)
    # IDA SDK requires these
    add_definitions(-D__LINUX__ -D__X64__ -DHAS_HEXRAYS)
endif ()

# Link directories for IDA SDK
link_directories(
        ${IDASDK_DIR}/lib/x64_linux_gcc_64
        ${IDA_INSTALL_DIR}
)

# Source files
set(HTTP_SOURCES
        src/http/server.cpp
        src/http/auth.cpp
)

set(MCP_SOURCES
        src/mcp/protocol.cpp
        src/mcp/server.cpp
)

set(TOOLS_SOURCES
        src/tools/tools.cpp
        src/tools/database.cpp
        src/tools/segments.cpp
        src/tools/functions.cpp
        src/tools/xrefs.cpp
        src/tools/hexrays.cpp
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
)

# Plugin shared library
add_library(ida_mcp_server SHARED
        src/main.cpp
        ${HTTP_SOURCES}
        ${MCP_SOURCES}
        ${TOOLS_SOURCES}
)

# Set plugin output name (IDA expects .so on Linux)
set_target_properties(ida_mcp_server PROPERTIES
        OUTPUT_NAME "ida_mcp_server"
        PREFIX ""  # No 'lib' prefix
        SUFFIX ".so"  # Force .so extension on Linux
)

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
        # IDA SDK libraries
        ida
        pthread
        dl
)

# Installation - install to IDA plugins directory
install(TARGETS ida_mcp_server
        LIBRARY DESTINATION "${IDA_INSTALL_DIR}/plugins"
)

# Print configuration
message(STATUS "IDA SDK directory: ${IDASDK_DIR}")
message(STATUS "IDA installation: ${IDA_INSTALL_DIR}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
