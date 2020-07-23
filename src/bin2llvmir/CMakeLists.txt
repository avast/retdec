
add_library(bin2llvmir STATIC
	analyses/ctor_dtor.cpp
	analyses/indirectly_called_funcs_analysis.cpp
	analyses/reachable_funcs_analysis.cpp
	analyses/reaching_definitions.cpp
	analyses/symbolic_tree.cpp
	optimizations/asm_inst_remover/asm_inst_remover.cpp
	optimizations/class_hierarchy/hierarchy.cpp
	optimizations/class_hierarchy/hierarchy_analysis.cpp
	optimizations/cond_branch_opt/cond_branch_opt.cpp
	optimizations/constants/constants.cpp
	optimizations/decoder/arm.cpp
	optimizations/decoder/arm64.cpp
	optimizations/decoder/bbs.cpp
	optimizations/decoder/decoder_ranges.cpp
	optimizations/decoder/decoder_init.cpp
	optimizations/decoder/decoder.cpp
	optimizations/decoder/functions.cpp
	optimizations/decoder/ir_modifications.cpp
	optimizations/decoder/jump_targets.cpp
	optimizations/decoder/mips.cpp
	optimizations/decoder/patterns.cpp
	optimizations/decoder/powerpc.cpp
	optimizations/decoder/x86.cpp
	optimizations/dump_module/dump_module.cpp
	optimizations/idioms/idioms.cpp
	optimizations/idioms/idioms_abstract.cpp
	optimizations/idioms/idioms_analysis.cpp
	optimizations/idioms/idioms_borland.cpp
	optimizations/idioms/idioms_common.cpp
	optimizations/idioms/idioms_gcc.cpp
	optimizations/idioms/idioms_intel.cpp
	optimizations/idioms/idioms_llvm.cpp
	optimizations/idioms/idioms_magicdivmod.cpp
	optimizations/idioms/idioms_owatcom.cpp
	optimizations/idioms/idioms_vstudio.cpp
	optimizations/idioms_libgcc/idioms_libgcc.cpp
	optimizations/inst_opt/inst_opt_pass.cpp
	optimizations/inst_opt/inst_opt.cpp
	optimizations/inst_opt_rda/inst_opt_rda_pass.cpp
	optimizations/inst_opt_rda/inst_opt_rda.cpp
	optimizations/main_detection/main_detection.cpp
	optimizations/param_return/collector/collector.cpp
	optimizations/param_return/collector/pic32.cpp
	optimizations/param_return/filter/filter.cpp
	optimizations/param_return/filter/ms_x64.cpp
	optimizations/param_return/param_return.cpp
	optimizations/param_return/data_entries.cpp
	optimizations/phi_remover/phi_remover.cpp
	optimizations/provider_init/provider_init.cpp
	optimizations/register_localization/register_localization.cpp
	optimizations/x86_addr_spaces/x86_addr_spaces_pass.cpp
	optimizations/x86_addr_spaces/x86_addr_spaces.cpp
	optimizations/x87_fpu/x87_fpu.cpp
	optimizations/select_functions/select_functions.cpp
	optimizations/simple_types/simple_types.cpp
	optimizations/stack/stack.cpp
	optimizations/stack_pointer_ops/stack_pointer_ops.cpp
	optimizations/value_protect/value_protect.cpp
	optimizations/writer_bc/writer_bc.cpp
	optimizations/writer_config/writer_config.cpp
	optimizations/writer_dsm/writer_dsm.cpp
	optimizations/writer_ll/writer_ll.cpp
	optimizations/syscalls/arm.cpp
	optimizations/syscalls/arm64.cpp
	optimizations/syscalls/mips.cpp
	optimizations/syscalls/syscalls.cpp
	optimizations/syscalls/x86.cpp
	optimizations/unreachable_funcs/unreachable_funcs.cpp
	providers/abi/abi.cpp
	providers/abi/arm.cpp
	providers/abi/arm64.cpp
	providers/abi/mips.cpp
	providers/abi/mips64.cpp
	providers/abi/ms_x64.cpp
	providers/abi/pic32.cpp
	providers/abi/powerpc.cpp
	providers/abi/powerpc64.cpp
	providers/abi/x64.cpp
	providers/abi/x86.cpp
	providers/calling_convention/calling_convention.cpp
	providers/calling_convention/arm/arm_conv.cpp
	providers/calling_convention/arm64/arm64_conv.cpp
	providers/calling_convention/mips/mips_conv.cpp
	providers/calling_convention/mips/mips_psp.cpp
	providers/calling_convention/mips64/mips64_conv.cpp
	providers/calling_convention/pic32/pic32_conv.cpp
	providers/calling_convention/powerpc/powerpc_conv.cpp
	providers/calling_convention/powerpc64/powerpc64_conv.cpp
	providers/calling_convention/x64/x64_conv.cpp
	providers/calling_convention/x64/x64_microsoft.cpp
	providers/calling_convention/x64/x64_systemv.cpp
	providers/calling_convention/x86/x86_cdecl.cpp
	providers/calling_convention/x86/x86_conv.cpp
	providers/calling_convention/x86/x86_fastcall.cpp
	providers/calling_convention/x86/x86_pascal.cpp
	providers/calling_convention/x86/x86_thiscall.cpp
	providers/calling_convention/x86/x86_watcom.cpp
	providers/asm_instruction.cpp
	providers/config.cpp
	providers/debugformat.cpp
	providers/demangler.cpp
	providers/fileimage.cpp
	providers/lti.cpp
	providers/names.cpp
	utils/capstone.cpp
	utils/ctypes2llvm.cpp
	utils/debug.cpp
	utils/ir_modifier.cpp
	utils/llvm.cpp
)
add_library(retdec::bin2llvmir ALIAS bin2llvmir)

target_compile_features(bin2llvmir PUBLIC cxx_std_17)

target_include_directories(bin2llvmir
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
	PRIVATE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/eigen>
)

target_link_libraries(bin2llvmir
	PUBLIC
		retdec::rtti-finder
		retdec::capstone2llvmir
		retdec::debugformat
		retdec::demangler
		retdec::stacofin
		retdec::cpdetect
		retdec::loader
		retdec::fileformat
		retdec::config
		retdec::ctypesparser
		retdec::common
		retdec::utils
		retdec::deps::llvm
)

set_target_properties(bin2llvmir
	PROPERTIES
		OUTPUT_NAME "retdec-bin2llvmir"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/bin2llvmir
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS bin2llvmir
	EXPORT bin2llvmir-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT bin2llvmir-targets
	FILE "retdec-bin2llvmir-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-bin2llvmir-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-bin2llvmir-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-bin2llvmir-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
