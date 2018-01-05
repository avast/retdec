/**
* @file src/llvmir2hll/llvm/llvmir2bir_converter.cpp
* @brief Implementation of LLVMIR2BIRConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new converter.
*
* @param[in] basePass Pass that instantiates a concrete converter.
*
* @par Preconditions
*  - @a basePass is non-null
*/
LLVMIR2BIRConverter::LLVMIR2BIRConverter(llvm::Pass *basePass):
	basePass(basePass), optionStrictFPUSemantics(false) {
		PRECONDITION_NON_NULL(basePass);
	}

/**
* @brief Destructor.
*/
LLVMIR2BIRConverter::~LLVMIR2BIRConverter() {}

/**
* @brief Enables/disables the use of strict FPU semantics.
*
* @param[in] strict If @c true, enables the use of strict FPU semantics. If @c
*                   false, disables the use of strict FPU semantics.
*/
void LLVMIR2BIRConverter::setOptionStrictFPUSemantics(bool strict) {
	optionStrictFPUSemantics = strict;
}

} // namespace llvmir2hll
} // namespace retdec
