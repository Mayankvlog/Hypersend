# This file controls Flutter-level build steps. It should not be edited.
cmake_minimum_required(VERSION 3.10)

set(EPHEMERAL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ephemeral")

# Configuration provided via flutter tool.
include(${EPHEMERAL_DIR}/generated_config.cmake)

# TODO: Move the rest of this into files in ephemeral. See
# https://github.com/flutter/flutter/issues/57146.

# Serves the same purpose as list(TRANSFORM ... PREPEND ...),
# which isn't available in 3.10.
function(list_prepend LIST_NAME PREFIX)
    set(NEW_LIST "")
    foreach(element ${${LIST_NAME}})
        list(APPEND NEW_LIST "${PREFIX}${element}")
    endforeach(element)
    set(${LIST_NAME} "${NEW_LIST}" PARENT_SCOPE)
endfunction()

# === Flutter Library ===
# System-level dependencies.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
# Check for required GTK and dependencies
pkg_check_modules(GTK QUIET IMPORTED_TARGET gtk+-3.0)
pkg_check_modules(GLIB QUIET IMPORTED_TARGET glib-2.0)
pkg_check_modules(GIO QUIET IMPORTED_TARGET gio-2.0)

# Store results in variables for use in linking
set(GTK_FOUND ${GTK_FOUND})
set(GLIB_FOUND ${GLIB_FOUND})
set(GIO_FOUND ${GIO_FOUND})
    # Only need one fallback for all package checks
else()
    # Fallback when pkg-config is not available (common on Windows)
    message(STATUS "pkg-config not available - using direct package detection")
    
    # Try to find GTK3 directly
    find_path(GTK_INCLUDE_DIR gtk/gtk.h
        PATHS
            /usr/include/gtk-3.0
            /usr/local/include/gtk-3.0
            /usr/include/gtk-3.0/gtk
            /usr/local/include/gtk-3.0/gtk
    )
    find_library(GTK_LIBRARY
        NAMES gtk-3 gtk3 gtk
        PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    )
    
    # Try to find GLib2 directly
    find_path(GLIB_INCLUDE_DIR glib.h
        PATHS
            /usr/include/glib-2.0
            /usr/local/include/glib-2.0
    )
    find_library(GLIB_LIBRARY
        NAMES glib-2.0 glib2
        PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    )
    
    # Try to find GIO directly
    find_path(GIO_INCLUDE_DIR gio/gio.h
        PATHS
            /usr/include/glib-2.0
            /usr/local/include/glib-2.0
    )
    find_library(GIO_LIBRARY
        NAMES gio-2.0 gio2
        PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    )
    
    # Verify packages were found
    if(NOT GTK_LIBRARY OR NOT GLIB_LIBRARY OR NOT GIO_LIBRARY)
        message(FATAL_ERROR "Required GTK/GLIB packages not found. Install libgtk-3-dev, libglib2.0-dev, libgio2.0-dev")
    endif()
else()
    # Fallback when pkg-config is not available (common on Windows)
    message(STATUS "pkg-config not found - using direct package detection")
    
    # Try to find GTK3 directly
    find_path(GTK_INCLUDE_DIR gtk/gtk.h
        PATHS
            /usr/include/gtk-3.0
            /usr/local/include/gtk-3.0
            /usr/include/gtk-3.0/gtk
            /usr/local/include/gtk-3.0/gtk
    )
    find_library(GTK_LIBRARY
        NAMES gtk-3 gtk3 gtk
        PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    )
    
    # Try to find GLib2 directly
    find_path(GLIB_INCLUDE_DIR glib.h
        PATHS
            /usr/include/glib-2.0
            /usr/local/include/glib-2.0
    )
    find_library(GLIB_LIBRARY
        NAMES glib-2.0 glib2
        PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    )
    
    # Try to find GIO directly
    find_path(GIO_INCLUDE_DIR gio/gio.h
        PATHS
            /usr/include/glib-2.0
            /usr/local/include/glib-2.0
    )
    find_library(GIO_LIBRARY
        NAMES gio-2.0 gio2
        PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    )
    
    # Verify all packages were found
    if(NOT GTK_LIBRARY OR NOT GLIB_LIBRARY OR NOT GIO_LIBRARY)
        message(FATAL_ERROR "Required GTK/GLIB packages not found. Install libgtk-3-dev, libglib2.0-dev, libgio2.0-dev")
    endif()
    
    # Create imported targets manually
    if(GTK_INCLUDE_DIR AND GTK_LIBRARY)
        add_library(GTK::GTK INTERFACE IMPORTED)
        set_target_properties(GTK::GTK PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${GTK_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "${GTK_LIBRARY}"
        )
    endif()
    
    if(GLIB_INCLUDE_DIR AND GLIB_LIBRARY)
        add_library(GTK::GLIB INTERFACE IMPORTED)
        set_target_properties(GTK::GLIB PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${GLIB_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "${GLIB_LIBRARY}"
        )
    endif()
    
    if(GIO_INCLUDE_DIR AND GIO_LIBRARY)
        add_library(GTK::GIO INTERFACE IMPORTED)
        set_target_properties(GTK::GIO PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${GIO_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "${GIO_LIBRARY}"
        )
    endif()
endif()

set(FLUTTER_LIBRARY "${EPHEMERAL_DIR}/libflutter_linux_gtk.so")

# Published to parent scope for install step.
set(FLUTTER_LIBRARY ${FLUTTER_LIBRARY} PARENT_SCOPE)
set(FLUTTER_ICU_DATA_FILE "${EPHEMERAL_DIR}/icudtl.dat" PARENT_SCOPE)
set(PROJECT_BUILD_DIR "${PROJECT_DIR}/build/" PARENT_SCOPE)
set(AOT_LIBRARY "${PROJECT_DIR}/build/lib/libapp.so" PARENT_SCOPE)

list(APPEND FLUTTER_LIBRARY_HEADERS
  "fl_basic_message_channel.h"
  "fl_binary_codec.h"
  "fl_binary_messenger.h"
  "fl_dart_project.h"
  "fl_engine.h"
  "fl_json_message_codec.h"
  "fl_json_method_codec.h"
  "fl_message_codec.h"
  "fl_method_call.h"
  "fl_method_channel.h"
  "fl_method_codec.h"
  "fl_method_response.h"
  "fl_plugin_registrar.h"
  "fl_plugin_registry.h"
  "fl_standard_message_codec.h"
  "fl_standard_method_codec.h"
  "fl_string_codec.h"
  "fl_value.h"
  "fl_view.h"
  "flutter_linux.h"
)
list_prepend(FLUTTER_LIBRARY_HEADERS "${EPHEMERAL_DIR}/flutter_linux/")
add_library(flutter INTERFACE)
target_include_directories(flutter INTERFACE
  "${EPHEMERAL_DIR}"
)
target_link_libraries(flutter INTERFACE "${FLUTTER_LIBRARY}")
# ENHANCED: Link libraries conditionally based on what was found
# Link packages based on availability
if(PkgConfig_FOUND)
    target_link_libraries(flutter INTERFACE
      PkgConfig::GTK
      PkgConfig::GLIB
      PkgConfig::GIO
    )
    # Use pre-stored results from individual checks
    if(GTK_FOUND AND GTK_LIBRARY)
        target_link_libraries(flutter INTERFACE GTK::GTK)
    endif()
    if(GLIB_FOUND AND GLIB_LIBRARY)
        target_link_libraries(flutter INTERFACE GTK::GLIB)
    endif()
    if(GIO_FOUND AND GIO_LIBRARY)
        target_link_libraries(flutter INTERFACE GTK::GIO)
    endif()
endif()
add_dependencies(flutter flutter_assemble)

# === Flutter tool backend ===
# _phony_ is a non-existent file to force this command to run every time,
# since currently there's no way to get a full input/output list from the
# flutter tool.
add_custom_command(
  OUTPUT ${FLUTTER_LIBRARY} ${FLUTTER_LIBRARY_HEADERS}
    ${CMAKE_CURRENT_BINARY_DIR}/_phony_
  COMMAND ${CMAKE_COMMAND} -E env
    ${FLUTTER_TOOL_ENVIRONMENT}
    "${FLUTTER_ROOT}/packages/flutter_tools/bin/tool_backend.sh"
      ${FLUTTER_TARGET_PLATFORM} ${CMAKE_BUILD_TYPE}
  VERBATIM
)
add_custom_target(flutter_assemble DEPENDS
  "${FLUTTER_LIBRARY}"
  ${FLUTTER_LIBRARY_HEADERS}
)