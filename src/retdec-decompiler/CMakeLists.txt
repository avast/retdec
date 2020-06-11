
add_executable(retdec-decompiler
retdec-decompiler.cpp
)

target_compile_features(retdec-decompiler PUBLIC cxx_std_17)

target_link_libraries(retdec-decompiler
	retdec::ar-extractor
	retdec::macho-extractor
	retdec::unpackertool
	retdec::retdec
)

# Due to the implementation of the plugin system in LLVM, we have to link our
# libraries into retdec as a whole.
if(MSVC)
	# -WHOLEARCHIVE needs path to the target, but when we use the target like
	# that, its properties (associated includes, etc.) are not propagated.
	# Therefore, we state 'bin2llvmir|llvmir2hll' twice in target_link_libraries(),
	# first as a target to get its properties, second as path to library to
	# link it as a whole.
	target_link_libraries(retdec-decompiler
		retdec::bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::bin2llvmir>
		retdec::llvmir2hll -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::llvmir2hll>
	)
	target_link_options(retdec-decompiler PUBLIC "/FORCE:MULTIPLE")
	# Increase the stack size of the created binaries on MS Windows because the
	# default value is too small. The default Linux value is 8388608 (8 MB).
	target_link_options(retdec-decompiler PUBLIC "/STACK:16777216")
	# Allow the 32b version of bin2llvmir on Windows handle addresses larger
	# than 2 GB (up to 4 GB).
	if(CMAKE_SIZEOF_VOID_P MATCHES "4")
		target_link_options(retdec-decompiler PUBLIC "/LARGEADDRESSAWARE")
	endif()
elseif(APPLE)
	target_link_libraries(retdec-decompiler
		-Wl,-force_load retdec::bin2llvmir
		-Wl,-force_load retdec::llvmir2hll
	)
else() # Linux
	target_link_libraries(retdec-decompiler
		-Wl,--whole-archive retdec::bin2llvmir -Wl,--no-whole-archive
		-Wl,--whole-archive retdec::llvmir2hll -Wl,--no-whole-archive
	)
endif()

set_target_properties(retdec-decompiler
	PROPERTIES OUTPUT_NAME "retdec-decompiler"
)

install(TARGETS retdec-decompiler
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
