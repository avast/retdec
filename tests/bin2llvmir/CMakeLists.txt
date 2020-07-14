
add_executable(tests-bin2llvmir
	analyses/reaching_definitions_tests.cpp
	optimizations/asm_inst_remover/asm_inst_remover_tests.cpp
	optimizations/idioms_libgcc/idioms_libgcc_tests.cpp
	optimizations/inst_opt/inst_opt_pass_tests.cpp
	optimizations/inst_opt/inst_opt_tests.cpp
	optimizations/param_return/param_return_tests.cpp
	optimizations/stack_pointer_ops/stack_pointer_ops_tests.cpp
	optimizations/unreachable_funcs/unreachable_funcs_tests.cpp
	optimizations/value_protect/value_protect_test.cpp
	optimizations/writer_dsm/writer_dsm_tests.cpp
	optimizations/x86_addr_spaces/x86_addr_spaces_pass_test.cpp
	optimizations/x86_addr_spaces/x86_addr_spaces_test.cpp
	optimizations/x87_fpu/x87_fpu_test.cpp
	providers/asm_instruction_tests.cpp
	providers/config_tests.cpp
	providers/debugformat_tests.cpp
	providers/demangler_tests.cpp
	providers/fileimage_tests.cpp
	providers/lti_tests.cpp
	providers/names.cpp
	utils/ctypes2llvm_type_tests.cpp
	utils/instcombine_tests.cpp
	utils/ir_modifier_tests.cpp
	utils/llvm_tests.cpp
	utils/simplifycfg_tests.cpp)

target_include_directories(tests-bin2llvmir
	PRIVATE
		${RETDEC_TESTS_DIR}
)

target_link_libraries(tests-bin2llvmir
	retdec::bin2llvmir
	retdec::utils
	retdec::deps::gmock_main
)

set_target_properties(tests-bin2llvmir
	PROPERTIES
		OUTPUT_NAME "retdec-tests-bin2llvmir"
)

install(TARGETS tests-bin2llvmir
	RUNTIME DESTINATION ${RETDEC_INSTALL_TESTS_DIR}
)
