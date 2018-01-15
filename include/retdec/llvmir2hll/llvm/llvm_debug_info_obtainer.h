/**
* @file include/retdec/llvmir2hll/llvm/llvm_debug_info_obtainer.h
* @brief Obtainer of debug information from an LLVM module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVM_DEBUG_INFO_OBTAINER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVM_DEBUG_INFO_OBTAINER_H

#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;

/**
* @brief Obtainer of debug information from an LLVM module.
*
* Debug information originates from DWARF/PDB data stored in/alongside the
* decompiled binary. An LLVM module represents this information in the form of
* metadata. For more information on the used format of these metadata, see
* LLVMMetadataObtainer.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class LLVMDebugInfoObtainer: private retdec::utils::NonCopyable {
public:
	static void obtainVarNames(ShPtr<Module> module);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
