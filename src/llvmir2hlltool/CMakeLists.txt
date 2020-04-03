
add_executable(llvmir2hlltool
	llvmir2hll.cpp
)

target_compile_features(llvmir2hlltool PUBLIC cxx_std_17)

# Due to the implementation of the plugin system in LLVM, we have to link our
# libraries into bin2llvmirtool as a whole.
if(MSVC)
	# -WHOLEARCHIVE needs path to the target, but when we use the target like
	# that, its properties (associated includes, etc.) are not propagated.
	# Therefore, we state 'llvmir2hll' twice in target_link_libraries(),
	# first as a target to get its properties, second as path to library to
	# link it as a whole.
	target_link_libraries(llvmir2hlltool
		retdec::llvmir2hll -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::llvmir2hll>
	)
	# Increase the stack size of the created binaries on MS Windows because the
	# default value is too small. The default Linux value is 8388608 (8 MB).
	set_property(TARGET llvmir2hlltool
		APPEND_STRING PROPERTY LINK_FLAGS " /STACK:16777216"
	)
	# Allow the 32b version of llvmir2hll on Windows handle addresses larger
	# than 2 GB (up to 4 GB).
	if(CMAKE_SIZEOF_VOID_P MATCHES "4")
		set_property(TARGET llvmir2hlltool
			APPEND_STRING PROPERTY LINK_FLAGS " /LARGEADDRESSAWARE"
		)
	endif()
elseif(APPLE)
	target_link_libraries(llvmir2hlltool
		-Wl,-force_load retdec::llvmir2hll
	)
else() # Linux/MSYS2
	target_link_libraries(llvmir2hlltool
		-Wl,--whole-archive retdec::llvmir2hll -Wl,--no-whole-archive
	)
endif()

set_target_properties(llvmir2hlltool
	PROPERTIES
		OUTPUT_NAME "retdec-llvmir2hll"
)

install(TARGETS llvmir2hlltool
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
