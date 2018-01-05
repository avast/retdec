/**
 * @file include/retdec/bin2llvmir/utils/type.h
 * @brief LLVM type utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_TYPE_H
#define RETDEC_BIN2LLVMIR_UTILS_TYPE_H

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/utils/defs.h"

namespace retdec {
namespace bin2llvmir {

const unsigned DEFAULT_ADDR_SPACE = 0;

llvm::Type* stringToLlvmType(llvm::LLVMContext& ctx, const std::string& str);
llvm::Type* stringToLlvmTypeDefault(llvm::Module* m, const std::string& str);

llvm::Value* convertValueToType(
		llvm::Value* val,
		llvm::Type* type,
		llvm::Instruction* before);

llvm::Value* convertValueToTypeAfter(
		llvm::Value* val,
		llvm::Type* type,
		llvm::Instruction* after);

llvm::Constant* convertConstantToType(
		llvm::Constant* val,
		llvm::Type* type);

llvm::Value* changeObjectType(
		Config* config,
		FileImage* objf,
		llvm::Module* module,
		llvm::Value* val,
		llvm::Type* toType,
		llvm::Constant* init = nullptr,
		UnorderedInstSet* instToErase = nullptr,
		bool dbg = false,
		bool wideString = false);

bool isBoolType(const llvm::Type* t);
bool isStringArrayType(const llvm::Type* t);
bool isStringArrayPointeType(const llvm::Type* t);
bool isCharType(const llvm::Type* t);
bool isCharPointerType(const llvm::Type* t);
bool isVoidPointerType(const llvm::Type* t);

unsigned getDefaultTypeBitSize(llvm::Module* module);
unsigned getDefaultTypeByteSize(llvm::Module* module);
llvm::IntegerType* getDefaultType(llvm::Module* module);
llvm::PointerType* getDefaultPointerType(llvm::Module* module);
llvm::IntegerType* getCharType(llvm::LLVMContext& ctx);
llvm::IntegerType* getCharType(llvm::LLVMContext* ctx);
llvm::PointerType* getCharPointerType(llvm::LLVMContext& ctx);
llvm::PointerType* getCharPointerType(llvm::LLVMContext* ctx);
llvm::PointerType* getVoidPointerType(llvm::LLVMContext& ctx);
llvm::PointerType* getVoidPointerType(llvm::LLVMContext* ctx);

size_t getTypeByteSizeInBinary(llvm::Module* module, llvm::Type* type);
size_t getTypeBitSizeInBinary(llvm::Module* module, llvm::Type* type);

std::vector<llvm::Type*> parseFormatString(
		llvm::Module* module,
		const std::string& format,
		llvm::Function* calledFnc = nullptr);

} // namespace bin2llvmir
} // namespace retdec

#endif
