/**
* @file include/retdec/llvmir2hll/pattern/pattern_finders/api_call_seq_pattern_finder.h
* @brief Finds sequences of interesting API calls in a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_SEQ_PATTERN_FINDER_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_SEQ_PATTERN_FINDER_H

#include <string>

#include "retdec/llvmir2hll/pattern/pattern_finder.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Finds sequences of interesting API calls in a module.
*
* This finder finds sequences of calls in a module that are considered
* interesting. For a list of such calls, see initAPICallInfoSeqMap().
*
* Instances of this class have reference object semantics. Use create() to
* create instances.
*/
class APICallSeqPatternFinder: public PatternFinder {
public:
	virtual ~APICallSeqPatternFinder() override;

	virtual const std::string getId() const override;
	virtual Patterns findPatterns(ShPtr<Module> module) override;

	static ShPtr<PatternFinder> create(ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);

	// TODO Add possibility of setting API_CALL_INFO_SEQ_MAP.

private:
	APICallSeqPatternFinder(ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);

private:
	/// Patterns to be returned.
	Patterns foundPatterns;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
