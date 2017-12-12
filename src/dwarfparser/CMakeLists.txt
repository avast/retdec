
set(DWARFPARSER_SOURCES
	dwarf_base.cpp
	dwarf_cu.cpp
	dwarf_file.cpp
	dwarf_functions.cpp
	dwarf_linenumbers.cpp
	dwarf_locations.cpp
	dwarf_resources.cpp
	dwarf_types.cpp
	dwarf_utils.cpp
	dwarf_vars.cpp
)

add_library(dwarfparser STATIC ${DWARFPARSER_SOURCES})
target_link_libraries(dwarfparser fileformat tl-cpputils libdwarf)
target_include_directories(dwarfparser PUBLIC ${PROJECT_SOURCE_DIR}/include/)
