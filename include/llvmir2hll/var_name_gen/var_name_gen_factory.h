/**
* @file include/llvmir2hll/var_name_gen/var_name_gen_factory.h
* @brief Factory that creates instances of classes derived from VarNameGen.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef LLVMIR2HLL_VAR_NAME_GEN_VAR_NAME_GEN_FACTORY_H
#define LLVMIR2HLL_VAR_NAME_GEN_VAR_NAME_GEN_FACTORY_H

#include <string>

#include "llvmir2hll/support/factory.h"
#include "llvmir2hll/support/singleton.h"
#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/var_name_gen/var_name_gen.h"

namespace llvmir2hll {

/**
* @brief Factory that creates instances of classes derived from VarNameGen.
*/
using VarNameGenFactory = Singleton<
	Factory<
		// Type of the base class.
		VarNameGen,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		UPtr<VarNameGen> (*)(std::string)
	>
>;

} // namespace llvmir2hll

#endif
