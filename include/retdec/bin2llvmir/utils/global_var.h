/**
 * @file include/retdec/bin2llvmir/utils/global_var.h
 * @brief LLVM global variable utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_GLOBAL_VAR_H
#define RETDEC_BIN2LLVMIR_UTILS_GLOBAL_VAR_H

#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/utils/defs.h"
#include "retdec/debugformat/debugformat.h"
#include "retdec/loader/loader.h"

namespace retdec {
namespace bin2llvmir {

bool getGlobalInfoFromCryptoPatterns(
		llvm::Module* module,
		Config* config,
		retdec::utils::Address addr,
		std::string& name,
		std::string& description,
		llvm::Type*& type);

llvm::GlobalVariable* getGlobalVariable(
		llvm::Module* module,
		Config* config,
		FileImage* objf,
		DebugFormat* dbgf,
		retdec::utils::Address addr,
		bool strict = false,
		std::string name = "global_var");

} // namespace bin2llvmir
} // namespace retdec

#endif
