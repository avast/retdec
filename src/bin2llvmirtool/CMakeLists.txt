set(BIN2LLVMIRTOOL_SOURCES
	bin2llvmir.cpp
)

add_executable(retdec-bin2llvmirtool ${BIN2LLVMIRTOOL_SOURCES})

# Due to the implementation of the plugin system in LLVM, we have to link our
# libraries into bin2llvmirtool as a whole.
if(MSVC)
	# -WHOLEARCHIVE needs path to the target, but when we use the target like that,
	# its properties (associated includes, etc.) are not propagated. Therefore, we
	# state 'bin2llvmir' twice in target_link_libraries(), first as a target to get
	# its properties, second as path to library to link it as a whole.
	target_link_libraries(retdec-bin2llvmirtool retdec-bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec-bin2llvmir>)
	set_property(TARGET retdec-bin2llvmirtool APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE")
elseif(APPLE)
	target_link_libraries(retdec-bin2llvmirtool -Wl,-force_load retdec-bin2llvmir)
else() # Linux
	target_link_libraries(retdec-bin2llvmirtool -Wl,--whole-archive retdec-bin2llvmir -Wl,--no-whole-archive)
endif()

# Allow the 32b version of bin2llvmir on Windows handle addresses larger than 2
# GB (up to 4 GB).
if(MSVC AND CMAKE_SIZEOF_VOID_P MATCHES "4")
	set_property(TARGET retdec-bin2llvmirtool APPEND_STRING PROPERTY LINK_FLAGS " /LARGEADDRESSAWARE")
endif()

set_target_properties(retdec-bin2llvmirtool PROPERTIES OUTPUT_NAME "retdec-bin2llvmir")
install(TARGETS retdec-bin2llvmirtool RUNTIME DESTINATION bin)
