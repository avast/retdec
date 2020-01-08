
add_library(retdec-yaracpp STATIC
	types/yara_match.cpp
	types/yara_meta.cpp
	types/yara_rule.cpp
	yara_detector/yara_detector.cpp
)
target_include_directories(retdec-yaracpp PUBLIC ${PROJECT_SOURCE_DIR}/include/)
target_link_libraries(retdec-yaracpp libyara)
