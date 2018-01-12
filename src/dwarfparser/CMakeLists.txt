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

add_library(retdec-dwarfparser STATIC ${DWARFPARSER_SOURCES})
target_link_libraries(retdec-dwarfparser retdec-fileformat retdec-utils libdwarf)
target_include_directories(retdec-dwarfparser PUBLIC ${PROJECT_SOURCE_DIR}/include/)
