set(RETDEC_TESTS_BIN2LLVMIR_SOURCES
	analyses/reaching_definitions_tests.cpp
	analyses/uses_analysis_tests.cpp
	analyses/var_depend_analysis_tests.cpp
	optimizations/asm_inst_remover/asm_inst_remover_tests.cpp
	optimizations/dsm_generator/dsm_generator_tests.cpp
	optimizations/globals/dead_global_assign_tests.cpp
	optimizations/globals/global_to_local.cpp
	optimizations/idioms_libgcc/idioms_libgcc_tests.cpp
	optimizations/inst_opt/inst_opt_pass_tests.cpp
	optimizations/inst_opt/inst_opt_tests.cpp
	optimizations/param_return/param_return_tests.cpp
	optimizations/phi2seq/phi2seq_tests.cpp
	optimizations/stack_pointer_ops/stack_pointer_ops_tests.cpp
	optimizations/unreachable_funcs/unreachable_funcs_tests.cpp
	providers/asm_instruction_tests.cpp
	providers/config_tests.cpp
	providers/debugformat_tests.cpp
	providers/demangler_tests.cpp
	providers/fileimage_tests.cpp
	providers/lti_tests.cpp
	utils/instcombine_tests.cpp
	utils/ir_modifier_tests.cpp
	utils/llvm_tests.cpp
	utils/simplifycfg_tests.cpp
)

add_executable(retdec-tests-bin2llvmir ${RETDEC_TESTS_BIN2LLVMIR_SOURCES})
target_link_libraries(retdec-tests-bin2llvmir retdec-bin2llvmir retdec-utils gmock_main)
target_include_directories(retdec-tests-bin2llvmir PUBLIC ${PROJECT_SOURCE_DIR}/tests/)
install(TARGETS retdec-tests-bin2llvmir RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
