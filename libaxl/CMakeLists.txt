cmake_minimum_required (VERSION 2.6)
project (axl NONE)

include_directories("${PROJECT_SOURCE_DIR}")

add_definitions(-DENABLE_AXL_LOG)

set(SOURCE_FILES axl.c axl_decl.c axl_decl.h axl_doc.c axl_doc.h axl_dtd.c axl_dtd.h axl_error.c axl_error.h axl_factory.c axl_factory.h axl.h axl_hash.c axl_hash.h axl_list.c axl_list.h axl_log.c axl_log.h axl_node.c axl_node.h axl_stack.c axl_stack.h axl_stream.c axl_stream.h)

add_library(axl STATIC ${SOURCE_FILES})

install(TARGETS axl DESTINATION .)
