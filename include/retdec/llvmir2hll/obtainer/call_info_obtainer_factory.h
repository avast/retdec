/**
* @file include/retdec/llvmir2hll/obtainer/call_info_obtainer_factory.h
* @brief Factory that creates instances of classes derived from
*        CallInfoObtainer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef RETDEC_LLVMIR2HLL_OBTAINER_CALL_INFO_OBTAINER_FACTORY_H
#define RETDEC_LLVMIR2HLL_OBTAINER_CALL_INFO_OBTAINER_FACTORY_H

#include <string>

#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class CallInfoObtainer;

/**
* @brief Factory that creates instances of classes derived from CallInfoObtainer.
*/
using CallInfoObtainerFactory = Singleton<
	Factory<
		// Type of the base class.
		CallInfoObtainer,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<CallInfoObtainer> (*)()
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
