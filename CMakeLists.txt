cmake_minimum_required(VERSION 3.20)
project(MalwareTelemetryEngine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include header files directory
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/privilege.cpp
    src/process_collector.cpp
    src/memory_scanner.cpp
    src/network_mapper.cpp
    src/json_serializer.cpp
)

set(HEADERS
    include/telemetry_model.hpp
    include/privilege.hpp
    include/process_collector.hpp
    include/memory_scanner.hpp
    include/network_mapper.hpp
    include/json_serializer.hpp
)

# Executable target
add_executable(telemetry_engine ${SOURCES} ${HEADERS})

# Windows system libraries
target_link_libraries(telemetry_engine PRIVATE
    ws2_32
    iphlpapi
    psapi
    advapi32
)

# Compiler flags
if(MSVC)
    target_compile_options(telemetry_engine PRIVATE /W4 /O2 /permissive-)
else()
    target_compile_options(telemetry_engine PRIVATE -Wall -Wextra -O2)
endif()
