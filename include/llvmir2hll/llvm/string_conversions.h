/**
* @file include/llvmir2hll/llvm/string_conversions.h
* @brief Conversions of strings stored in LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_LLVM_STRING_CONVERSIONS_H
#define LLVMIR2HLL_LLVM_STRING_CONVERSIONS_H

#include <string>

#include "llvmir2hll/support/smart_ptr.h"

namespace llvm {

class ConstantArray;
class ConstantDataArray;
class GlobalVariable;

} // namespace llvm

namespace llvmir2hll {

class ConstString;

/// @name Querying
/// @{
bool is8BitStringLiteral(const llvm::ConstantArray *ca);
bool stores8BitStringLiteral(const llvm::GlobalVariable *v);
/// @}

/// @name Conversions
/// @{
ShPtr<ConstString> toConstString(llvm::ConstantArray *ca);
ShPtr<ConstString> toConstString(llvm::ConstantDataArray *cda);
ShPtr<ConstString> getInitializerAsConstString(llvm::GlobalVariable *v);
/// @}

} // namespace llvmir2hll

#endif
