/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_writer_factory.h
* @brief Factory that creates instances of classes derived from CFGWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_WRITER_FACTORY_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_WRITER_FACTORY_H

#include <ostream>
#include <string>

#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class CFG;
class CFGWriter;

/**
* @brief Factory that creates instances of classes derived from CFGWriter.
*/
using CFGWriterFactory = Singleton<
	Factory<
		// Type of the base class.
		CFGWriter,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<CFGWriter> (*)(ShPtr<CFG>, std::ostream &)
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
