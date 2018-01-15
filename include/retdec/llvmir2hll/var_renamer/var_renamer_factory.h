/**
* @file include/retdec/llvmir2hll/var_renamer/var_renamer_factory.h
* @brief Factory that creates instances of classes derived from VarRenamer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMER_FACTORY_H
#define RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMER_FACTORY_H

#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gen.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Factory that creates instances of classes derived from VarRenamer.
*/
using VarRenamerFactory = Singleton<
	Factory<
		// Type of the base class.
		VarRenamer,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<VarRenamer> (*)(ShPtr<VarNameGen>, bool)
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
