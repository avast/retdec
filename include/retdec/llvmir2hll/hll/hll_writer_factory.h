/**
* @file include/retdec/llvmir2hll/hll/hll_writer_factory.h
* @brief Factory that creates instances of classes derived from HLLWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_HLL_WRITER_FACTORY_H
#define RETDEC_LLVMIR2HLL_HLL_HLL_WRITER_FACTORY_H

#include <string>

#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Module;
class HLLWriter;

/**
* @brief Factory that creates instances of classes derived from HLLWriter.
*/
using HLLWriterFactory = Singleton<
	Factory<
		// Type of the base class.
		HLLWriter,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<HLLWriter> (*)(llvm::raw_ostream &)
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
