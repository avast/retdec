/**
* @file include/retdec/llvmir2hll/pattern/pattern_finders/api_call_pattern_finder.h
* @brief Finds interesting API calls in a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_PATTERN_FINDER_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDERS_API_CALL_PATTERN_FINDER_H

#include <string>

#include "retdec/llvmir2hll/pattern/pattern_finder.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Finds interesting API calls in a module.
*
* This finder finds calls in a module that are considered interesting. For a
* list of such calls, see the implementation of getAPICallFuncNames() in
* the .cpp file.
*
* TODO Include only calls to declared functions, or also to defined ones?
*      For example, if there is a ShellExecute() function defined in the
*      module, should we also include calls to it even though it may have
*      different behavior than ShellExecute() from WinAPI?
*
* TODO Move the names of interesting functions into semantics?
*
* Instances of this class have reference object semantics. Use create() to
* create instances.
*/
class APICallPatternFinder: public PatternFinder {
public:
	virtual ~APICallPatternFinder() override;

	virtual const std::string getId() const override;
	virtual Patterns findPatterns(ShPtr<Module> module) override;

	static ShPtr<PatternFinder> create(ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);

private:
	APICallPatternFinder(ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
