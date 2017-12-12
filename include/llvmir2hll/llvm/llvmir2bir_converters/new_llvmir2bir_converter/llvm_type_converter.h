/**
* @file include/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_type_converter.h
* @brief A converter from LLVM type to type in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_TYPE_CONVERTER_H
#define LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_TYPE_CONVERTER_H

#include <unordered_map>

#include "llvmir2hll/support/smart_ptr.h"
#include "tl-cpputils/non_copyable.h"

namespace llvm {

class ArrayType;
class FunctionType;
class IntegerType;
class PointerType;
class StructType;
class Type;

} // namespace llvm

namespace llvmir2hll {

class ArrayType;
class FunctionType;
class PointerType;
class StructType;
class Type;

/**
* @brief A converter from LLVM type to type in BIR.
*/
class LLVMTypeConverter final: private tl_cpputils::NonCopyable {
public:
	LLVMTypeConverter();

	bool isBool(const llvm::IntegerType *type) const;

	ShPtr<Type> convert(const llvm::Type *type);
	ShPtr<PointerType> convert(const llvm::PointerType *type);
	ShPtr<ArrayType> convert(const llvm::ArrayType *type);
	ShPtr<StructType> convert(const llvm::StructType *type);
	ShPtr<FunctionType> convert(const llvm::FunctionType *type);

private:
	/// Mapping of an LLVM type into an already converted type in BIR.
	std::unordered_map<const llvm::Type *, ShPtr<Type>> mapLLVMTypeToType;
};

} // namespace llvmir2hll

#endif
