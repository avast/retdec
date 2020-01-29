
add_executable(retdec-retdectool
    retdec.cpp
)
target_link_libraries(retdec-retdectool retdec-retdec)

# Due to the implementation of the plugin system in LLVM, we have to link our
# libraries into retdec as a whole.
if(MSVC)
	# -WHOLEARCHIVE needs path to the target, but when we use the target like that,
	# its properties (associated includes, etc.) are not propagated. Therefore, we
	# state 'bin2llvmir' twice in target_link_libraries(), first as a target to get
	# its properties, second as path to library to link it as a whole.
	target_link_libraries(retdec-retdectool retdec-bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec-bin2llvmir>)
	set_property(TARGET retdec-retdectool APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE")
elseif(APPLE)
	target_link_libraries(retdec-retdectool -Wl,-force_load retdec-bin2llvmir)
else() # Linux
	target_link_libraries(retdec-retdectool -Wl,--whole-archive retdec-bin2llvmir -Wl,--no-whole-archive)
endif()

# Allow the 32b version of bin2llvmir on Windows handle addresses larger than 2
# GB (up to 4 GB).
if(MSVC AND CMAKE_SIZEOF_VOID_P MATCHES "4")
	set_property(TARGET retdec-retdec APPEND_STRING PROPERTY LINK_FLAGS " /LARGEADDRESSAWARE")
endif()

set_target_properties(retdec-retdectool PROPERTIES OUTPUT_NAME "retdec")
install(TARGETS retdec-retdectool RUNTIME DESTINATION bin)
