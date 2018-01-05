/**
* @file src/llvmir2hll/graphs/cfg/cfg_writer.cpp
* @brief Implementation of CFGWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cfg/cfg_writer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/conversion.h"

using retdec::utils::toString;

namespace retdec {
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
} // namespace retdec
