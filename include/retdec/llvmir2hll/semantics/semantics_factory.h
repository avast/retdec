/**
* @file include/retdec/llvmir2hll/semantics/semantics_factory.h
* @brief Factory that creates instances of classes derived from Semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_FACTORY_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_FACTORY_H

#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Factory that creates instances of classes derived from Semantics.
*/
using SemanticsFactory = Singleton<
	Factory<
		// Type of the base class.
		Semantics,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<Semantics> (*)()
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
