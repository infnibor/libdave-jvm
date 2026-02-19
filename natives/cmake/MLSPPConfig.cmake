set(MLSPP_ROOT_DIR "${CMAKE_SOURCE_DIR}/mlspp")
message(STATUS "MLSPP_ROOT_DIR: ${MLSPP_ROOT_DIR}")

set(MLSPP_INCLUDE_DIR "${MLSPP_ROOT_DIR}/include")
set(MLSPP_LIBRARIES MLSPP::mlspp)
set(MLSPP_FOUND YES)

if(NOT TARGET MLSPP::mlspp)
    add_library(MLSPP::mlspp ALIAS mlspp)
endif()