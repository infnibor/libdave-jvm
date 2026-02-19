get_filename_component(_nlohmann_json_include_dir "${CMAKE_CURRENT_LIST_DIR}/include" ABSOLUTE)

add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
set_target_properties(nlohmann_json::nlohmann_json PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${_nlohmann_json_include_dir}"
)

set(nlohmann_json_FOUND TRUE)
