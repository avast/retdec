set(BIN2LLVMIR_TESTS_SOURCES
	analyses/reaching_definitions_tests.cpp
	analyses/uses_analysis_tests.cpp
	analyses/var_depend_analysis_tests.cpp
	optimizations/asm_inst_remover/asm_inst_remover_tests.cpp
	optimizations/dsm_generator/dsm_generator_tests.cpp
	optimizations/globals/dead_global_assign_tests.cpp
	optimizations/globals/global_to_local.cpp
	optimizations/idioms_libgcc/idioms_libgcc_tests.cpp
	optimizations/inst_opt/inst_opt_tests.cpp
	optimizations/never_returning_funcs/never_returning_funcs_tests.cpp
	optimizations/param_return/param_return_tests.cpp
	optimizations/phi2seq/phi2seq_tests.cpp
	optimizations/stack_pointer_ops/stack_pointer_ops_tests.cpp
	optimizations/type_conversions/type_conversions_tests.cpp
	optimizations/unreachable_funcs/unreachable_funcs_tests.cpp
	optimizations/volatilize/volatilize_tests.cpp
	providers/asm_instruction_tests.cpp
	providers/config_tests.cpp
	providers/debugformat_tests.cpp
	providers/demangler_tests.cpp
	providers/fileimage_tests.cpp
	providers/lti_tests.cpp
	utils/instcombine_tests.cpp
	utils/instruction_tests.cpp
	utils/ir_modifier_tests.cpp
	utils/simplifycfg_tests.cpp
	utils/type_tests.cpp
)

add_executable(bin2llvmir-tests ${BIN2LLVMIR_TESTS_SOURCES})
target_link_libraries(bin2llvmir-tests bin2llvmir retdec-utils gmock_main)
target_include_directories(bin2llvmir-tests PUBLIC ${PROJECT_SOURCE_DIR}/tests/)
install(TARGETS bin2llvmir-tests RUNTIME DESTINATION bin/unit-tests)
