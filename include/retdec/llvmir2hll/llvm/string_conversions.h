/**
* @file include/retdec/llvmir2hll/llvm/string_conversions.h
* @brief Conversions of strings stored in LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_STRING_CONVERSIONS_H
#define RETDEC_LLVMIR2HLL_LLVM_STRING_CONVERSIONS_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace llvm {

class ConstantArray;
class ConstantDataArray;
class GlobalVariable;

} // namespace llvm

namespace retdec {
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
} // namespace retdec

#endif
