/**
* @file include/llvmir2hll/semantics/semantics_factory.h
* @brief Factory that creates instances of classes derived from Semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_FACTORY_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_FACTORY_H

#include "llvmir2hll/semantics/semantics.h"
#include "llvmir2hll/support/factory.h"
#include "llvmir2hll/support/singleton.h"
#include "llvmir2hll/support/smart_ptr.h"

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

#endif
