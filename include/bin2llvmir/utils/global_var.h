/**
 * @file include/bin2llvmir/utils/global_var.h
 * @brief LLVM global variable utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_UTILS_GLOBAL_VAR_H
#define BIN2LLVMIR_UTILS_GLOBAL_VAR_H

#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>

#include "tl-cpputils/address.h"
#include "bin2llvmir/providers/config.h"
#include "bin2llvmir/providers/fileimage.h"
#include "bin2llvmir/utils/defs.h"
#include "debugformat/debugformat.h"
#include "loader/loader.h"

namespace bin2llvmir {

bool getGlobalInfoFromCryptoPatterns(
		llvm::Module* module,
		Config* config,
		tl_cpputils::Address addr,
		std::string& name,
		std::string& description,
		llvm::Type*& type);

llvm::GlobalVariable* getGlobalVariable(
		llvm::Module* module,
		Config* config,
		FileImage* objf,
		DebugFormat* dbgf,
		tl_cpputils::Address addr,
		bool strict = false,
		std::string name = "global_var");

} // namespace bin2llvmir

#endif
