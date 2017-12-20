
set(LLVMIR2HLLTOOL_SOURCES
	llvmir2hll.cpp
)

add_executable(llvmir2hlltool ${LLVMIR2HLLTOOL_SOURCES})

# Due to the implementation of the plugin system in LLVM, we have to link our
# libraries into bin2llvmirtool as a whole.
if(MSVC)
	# -WHOLEARCHIVE needs path to the target, but when we use the target like that,
	# its properties (associated includes, etc.) are not propagated. Therefore, we
	# state 'llvmir2hll' twice in target_link_libraries(), first as a target to get
	# its properties, second as path to library to link it as a whole.
	target_link_libraries(llvmir2hlltool llvmir2hll -WHOLEARCHIVE:$<TARGET_FILE_NAME:llvmir2hll>)
elseif(APPLE)
	target_link_libraries(llvmir2hlltool -Wl,-force_load llvmir2hll)
else() # Linux/MSYS2
	target_link_libraries(llvmir2hlltool -Wl,--whole-archive llvmir2hll -Wl,--no-whole-archive)
endif()

# Increase the stack size of the created binaries on MS Windows because the
# default value is too small. The default Linux value is 8388608 (8 MB).
if(MSVC)
	set_target_properties(llvmir2hlltool PROPERTIES LINK_FLAGS "/STACK:16777216")
endif()

set_target_properties(llvmir2hlltool PROPERTIES OUTPUT_NAME "llvmir2hll")
install(TARGETS llvmir2hlltool RUNTIME DESTINATION bin)
