/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter_factory.h
* @brief Factory that creates instances of classes derived from
*        LLVMIR2BIRConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_FACTORY_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_FACTORY_H

#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace llvm {

class Pass;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

/**
* @brief Factory that creates instances of classes derived from LLVMIR2BIRConverter.
*/
using LLVMIR2BIRConverterFactory = Singleton<
	Factory<
		// Type of the base class.
		LLVMIR2BIRConverter,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<LLVMIR2BIRConverter> (*)(llvm::Pass *basePass)
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
