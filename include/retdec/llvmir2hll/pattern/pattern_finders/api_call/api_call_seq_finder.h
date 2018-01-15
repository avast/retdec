/**
* @file include/retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finder.h
* @brief A base class for all API calls finders.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_SEQ_FINDER_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_API_CALL_SEQ_FINDER_H

#include <vector>

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class CallExpr;
class CallInfoObtainer;
class Module;
class Pattern;
class Statement;
class ValueAnalysis;

/**
* @brief A base class for all API calls finders.
*
* Concrete API calls finders should inherit from this class.
*
* Instances of this class have reference object semantics.
*/
class APICallSeqFinder: private retdec::utils::NonCopyable {
public:
	/// List of patterns.
	using Patterns = std::vector<ShPtr<Pattern>>;

public:
	virtual ~APICallSeqFinder();

	/**
	* @brief Tries to find the given sequence of API calls, starting at @a
	*        stmt.
	*
	* @param[in] info A description of an API call sequence.
	* @param[in] call A function call.
	* @param[in] stmt The statement in which @a call appears.
	* @param[in] func The function in which @a stmt appears.
	* @param[in] module The module in which @a func appears.
	*
	* The used way of finding the pattern depends on concrete finders.
	*
	* @par Preconditions
	*  - @a call, @a stmt, @a func, and @a module are non-null
	*/
	virtual Patterns findPatterns(const APICallInfoSeq &info,
		ShPtr<CallExpr> call, ShPtr<Statement> stmt, ShPtr<Function> func,
		ShPtr<Module> module) = 0;

protected:
	APICallSeqFinder(ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio);

protected:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// The used call info obtainer.
	ShPtr<CallInfoObtainer> cio;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
