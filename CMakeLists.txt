# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

cmake_minimum_required(VERSION 3.12)

project(hexend VERSION 1.0)

# ==== PROJECT SETUP ====
set(CMAKE_C_FLAGS
	"${CMAKE_C_FLAGS} -Wall -Wpedantic")
set(PROJECT_NAME_VERSION "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")

set(SRC_FILES hexend.c)
list(TRANSFORM SRC_FILES PREPEND "${PROJECT_SOURCE_DIR}/src/")

configure_file(include/version.h.in include/version.h)

# ==== BUILD ====
add_executable(hexend ${SRC_FILES})

target_include_directories(hexend PUBLIC
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_BINARY_DIR}/include
	)

# ==== INSTALL ====
install(TARGETS hexend
        CONFIGURATIONS Debug
        RUNTIME DESTINATION bin)
install(TARGETS hexend
        CONFIGURATIONS Release
        RUNTIME DESTINATION bin)


# ==== UNINSTALL ====
add_custom_target(uninstall
	COMMAND
	xargs rm < install_manifest.txt
	)


# ==== TEST ====
add_custom_target(test
	COMMAND
	unshare -r -n ${PROJECT_SOURCE_DIR}/test/test.sh ${PROJECT_BINARY_DIR}/hexend $(t)
	DEPENDS ${PROJECT_BINARY_DIR}/hexend
	)

# ==== RELEASE TAR FILE ====
add_custom_target(dist
	COMMAND
	mkdir "-p" "${PROJECT_NAME_VERSION}"
	COMMAND
	cp
	"-r"
	"../CMakeLists.txt"
	"../LICENSE"
	"../README.md"
	"../.gitignore"
	"../include"
	"../src"
	"${PROJECT_NAME_VERSION}"
	COMMAND
	tar
	"-cvzf"
	"${PROJECT_NAME_VERSION}.tar.gz"
	"${PROJECT_NAME_VERSION}/"
	)

# ==== CLEAN ====
set_directory_properties(
	PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
	"${PROJECT_BINARY_DIR}/${PROJECT_NAME_VERSION}.tar.gz"
	)
