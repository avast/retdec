/**
* @file src/llvmir2hll/graphs/cfg/cfg_writer.cpp
* @brief Implementation of CFGWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "llvmir2hll/graphs/cfg/cfg_writer.h"
#include "llvmir2hll/support/debug.h"
#include "tl-cpputils/conversion.h"

using tl_cpputils::toString;

namespace llvmir2hll {

/**
* @brief Constructs a new writer.
*
* @param[in] cfg CFG to be emitted.
* @param[in] out Output stream where the CFG is emitted.
*/
CFGWriter::CFGWriter(ShPtr<CFG> cfg, std::ostream &out):
	cfg(cfg), out(out) {}

/**
* @brief Destructs the writer.
*/
CFGWriter::~CFGWriter() {}

} // namespace llvmir2hll
