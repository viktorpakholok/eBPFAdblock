cmake_minimum_required(VERSION 3.16)
project(eBPFAdblock C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Set BPF target correctly
set(CMAKE_C_FLAGS_BPF -O2 -g -target bpf)  # <-- Fix: remove quotes

# Find required libraries
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

include_directories(/usr/include/)

# Ensure the bpf directory exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bpf)

# Compile BPF programs
add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/bpf/map_creator.bpf.o
        COMMAND clang ${CMAKE_C_FLAGS_BPF} -c ${CMAKE_SOURCE_DIR}/bpf/map_creator.bpf.c -o ${CMAKE_BINARY_DIR}/bpf/map_creator.bpf.o
        COMMAND echo "Built: map_creator.bpf.o"
        DEPENDS ${CMAKE_SOURCE_DIR}/bpf/map_creator.bpf.c
        VERBATIM
)

add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/bpf/map_tracer.bpf.o
        COMMAND clang ${CMAKE_C_FLAGS_BPF} -c ${CMAKE_SOURCE_DIR}/bpf/map_tracer.bpf.c -o ${CMAKE_BINARY_DIR}/bpf/map_tracer.bpf.o
        COMMAND echo "Built: map_tracer.bpf.o"
        DEPENDS ${CMAKE_SOURCE_DIR}/bpf/map_tracer.bpf.c
        VERBATIM
)

# Ensure BPF programs are always built
add_custom_target(
        bpf_build ALL
        DEPENDS ${CMAKE_BINARY_DIR}/bpf/map_creator.bpf.o ${CMAKE_BINARY_DIR}/bpf/map_tracer.bpf.o
)

# Compile user-space programs
add_executable(map_interactor userspace/map_interactor.c)
target_link_libraries(map_interactor ${LIBBPF_LIBRARIES})
add_dependencies(map_interactor bpf_build)  # Ensure BPF programs are built first

add_executable(map_logger userspace/map_logger.c)
target_link_libraries(map_logger ${LIBBPF_LIBRARIES})
add_dependencies(map_logger bpf_build)  # Ensure BPF programs are built first
