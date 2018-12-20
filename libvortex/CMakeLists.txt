cmake_minimum_required (VERSION 2.6)
project (vortex C)

include_directories("${PROJECT_SOURCE_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/sasl")
include_directories("${PROJECT_SOURCE_DIR}/tls")
include_directories("${PROJECT_SOURCE_DIR}/../libaxl")

add_definitions(-DENABLE_VORTEX_LOG)
add_definitions(-DPACKAGE_TOP_DIR="${PROJECT_SOURCE_DIR}")
add_definitions(-DVORTEX_HAVE_TLSv10_ENABLED) # openssl 1.0

set(SOURCE_FILES vortex.c vortex_channel.c vortex-channel.dtd.h vortex_channel.h vortex_channel_pool.c vortex_channel_pool.h vortex_connection.c vortex_connection.h vortex_connection_private.h vortex_ctx.c vortex_ctx.h vortex_ctx_private.h vortex_dtds.c vortex_dtds.h vortex_dtds_private.h vortex_errno.c vortex_errno.h vortex_frame_factory.c vortex_frame_factory.h vortex_greetings.c vortex_greetings.h vortex.h vortex_handlers.c vortex_handlers.h vortex_hash.c vortex_hash.h vortex_hash_private.h vortex_io.c vortex_io.h vortex_listener.c vortex-listener-conf.dtd.h vortex_listener.h vortex_payload_feeder.c vortex_payload_feeder.h vortex_payload_feeder_private.h vortex_profiles.c vortex_profiles.h vortex_queue.c vortex_queue.h vortex_reader.c vortex_reader.h vortex_sequencer.c vortex_sequencer.h vortex_support.c vortex_support.h vortex_thread.c vortex_thread.h vortex_thread_pool.c vortex_thread_pool.h vortex_types.h sasl/vortex_sasl.c sasl/vortex-sasl.dtd.h sasl/vortex_sasl.h tls/vortex_tls.c tls/vortex-tls.dtd.h tls/vortex_tls.h)

add_library(vortex STATIC ${SOURCE_FILES})

install(TARGETS vortex DESTINATION .)
