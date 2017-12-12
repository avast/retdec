/**
* @file include/llvmir2hll/graphs/cg/cg_writer_factory.h
* @brief Factory that creates instances of classes derived from CGWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef LLVMIR2HLL_GRAPHS_CG_CG_WRITER_FACTORY_H
#define LLVMIR2HLL_GRAPHS_CG_CG_WRITER_FACTORY_H

#include <ostream>
#include <string>

#include "llvmir2hll/support/factory.h"
#include "llvmir2hll/support/singleton.h"
#include "llvmir2hll/support/smart_ptr.h"

namespace llvmir2hll {

class CG;
class CGWriter;

/**
* @brief Factory that creates instances of classes derived from CGWriter.
*/
using CGWriterFactory = Singleton<
	Factory<
		// Type of the base class.
		CGWriter,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<CGWriter> (*)(ShPtr<CG>, std::ostream &)
	>
>;

} // namespace llvmir2hll

#endif
