/**
* @file include/llvmir2hll/validator/validator_factory.h
* @brief Factory that creates instances of classes derived from Validator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef LLVMIR2HLL_VALIDATOR_VALIDATOR_FACTORY_H
#define LLVMIR2HLL_VALIDATOR_VALIDATOR_FACTORY_H

#include <string>

#include "llvmir2hll/support/factory.h"
#include "llvmir2hll/support/singleton.h"
#include "llvmir2hll/support/smart_ptr.h"

namespace llvmir2hll {

class Validator;

/**
* @brief Factory that creates instances of classes derived from Validator.
*/
using ValidatorFactory = Singleton<
	Factory<
		// Type of the base class.
		Validator,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<Validator> (*)()
	>
>;

} // namespace llvmir2hll

#endif
