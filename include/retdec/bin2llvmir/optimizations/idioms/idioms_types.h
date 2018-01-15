/**
* @file include/retdec/bin2llvmir/optimizations/idioms/idioms_types.h
* @brief Instruction idioms analysis types
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_TYPES_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_TYPES_H

namespace retdec {
namespace bin2llvmir {

/**
* @brief Compiler type
*/
enum CC_compiler {
	CC_ANY = 0, //unrecognized compiler
	CC_Borland,
	CC_GCC,
	CC_Intel,
	CC_LLVM,
	CC_OWatcom,
	CC_VStudio
};
/**
* @brief Target architecture
*/
enum CC_arch {
	ARCH_ANY = 0, //unknown architecture
	ARCH_MIPS,
	ARCH_POWERPC,
	ARCH_ARM,
	ARCH_THUMB,
	ARCH_x86
};

} // namespace bin2llvmir
} // namespace retdec

#endif
