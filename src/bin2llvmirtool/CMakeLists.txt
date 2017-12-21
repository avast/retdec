
set(BIN2LLVMIRTOOL_SOURCES
	bin2llvmir.cpp
)

add_executable(bin2llvmirtool ${BIN2LLVMIRTOOL_SOURCES})

# Due to the implementation of the plugin system in LLVM, we have to link our
# libraries into bin2llvmirtool as a whole.
if(MSVC)
	# -WHOLEARCHIVE needs path to the target, but when we use the target like that,
	# its properties (associated includes, etc.) are not propagated. Therefore, we
	# state 'bin2llvmir' twice in target_link_libraries(), first as a target to get
	# its properties, second as path to library to link it as a whole.
	target_link_libraries(bin2llvmirtool bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:bin2llvmir>)
	set_target_properties(bin2llvmirtool PROPERTIES LINK_FLAGS "/FORCE:MULTIPLE")
elseif(APPLE)
	target_link_libraries(bin2llvmirtool -Wl,-force_load bin2llvmir)
else() # Linux/MSYS2
	target_link_libraries(bin2llvmirtool -Wl,--whole-archive bin2llvmir -Wl,--no-whole-archive)
endif()

set_target_properties(bin2llvmirtool PROPERTIES OUTPUT_NAME "bin2llvmir")
install(TARGETS bin2llvmirtool RUNTIME DESTINATION bin)
