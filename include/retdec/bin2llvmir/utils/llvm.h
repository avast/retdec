/**
 * @file include/retdec/bin2llvmir/utils/llvm.h
 * @brief LLVM Utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 *
 * Useful LLVM-related things that are missing in LLVM itself.
 * All (Values, Types, Instructions, etc.) in one module.
 * Keep this as small as possible. Use LLVM when possible.
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_LLVM_H
#define RETDEC_BIN2LLVMIR_UTILS_LLVM_H

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>

namespace retdec {
namespace bin2llvmir {
namespace llvm_utils {

//
//==============================================================================
// Values
//==============================================================================
//

llvm::Value* skipCasts(llvm::Value* val);

//
//==============================================================================
// Types
//==============================================================================
//

llvm::IntegerType* getCharType(llvm::LLVMContext& ctx);
llvm::PointerType* getCharPointerType(llvm::LLVMContext& ctx);

bool isCharType(const llvm::Type* t);
bool isCharPointerType(const llvm::Type* t);
bool isStringArrayType(const llvm::Type* t);
bool isStringArrayPointeType(const llvm::Type* t);

llvm::Type* stringToLlvmType(llvm::LLVMContext& ctx, const std::string& str);
llvm::Type* stringToLlvmTypeDefault(llvm::Module* m, const std::string& str);

std::vector<llvm::Type*> parseFormatString(
		llvm::Module* module,
		const std::string& format,
		llvm::Function* calledFnc = nullptr);

} // namespace llvm_utils
} // namespace bin2llvmir
} // namespace retdec

#endif
