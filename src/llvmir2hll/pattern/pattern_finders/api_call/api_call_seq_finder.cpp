/**
* @file src/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finder.cpp
* @brief Implementation of APICallSeqFinder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finder.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs the base class.
*
* @param[in] va The used analysis of values.
* @param[in] cio The used call info obtainer.
*
* @par Preconditions
*  - @a va and @a cio are non-null
*  - @a va is in a valid state
*  - @a cio has been initialized
*/
APICallSeqFinder::APICallSeqFinder(ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio): va(va), cio(cio) {
	PRECONDITION_NON_NULL(va);
	PRECONDITION_NON_NULL(cio);
	PRECONDITION(va->isInValidState(), "it is not in a valid state");
	PRECONDITION(cio->isInitialized(), "it is not initialized");
}

/**
* @brief Destructs the base class.
*/
APICallSeqFinder::~APICallSeqFinder() {}

} // namespace llvmir2hll
} // namespace retdec
