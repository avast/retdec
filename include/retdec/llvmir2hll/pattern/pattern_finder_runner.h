/**
* @file include/retdec/llvmir2hll/pattern/pattern_finder_runner.h
* @brief A base class for all runners of pattern finders.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDER_RUNNER_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDER_RUNNER_H

#include <vector>

#include "retdec/llvmir2hll/pattern/pattern_finder.h"

namespace retdec {
namespace llvmir2hll {

class Module;

/**
* @brief A base class for all runners of pattern finders.
*
* A concrete runner should
*  - implement all the pure virtual functions
*
* Instances of this class have reference object semantics. The class implements
* the NVI ("non-virtual interface") pattern.
*/
class PatternFinderRunner {
public:
	/// A container storing pattern finders.
	using PatternFinders = std::vector<ShPtr<PatternFinder>>;

public:
	PatternFinderRunner();
	virtual ~PatternFinderRunner();

	void run(const PatternFinders &pfs, ShPtr<Module> module);
	void run(ShPtr<PatternFinder> pf, ShPtr<Module> module);

protected:
	/**
	* @brief Performs actions before pattern finder @a pf runs.
	*/
	virtual void doActionsBeforePatternFinderRuns(ShPtr<PatternFinder> pf) = 0;

	/**
	* @brief Performs actions after pattern finder @a pf has run.
	*
	* @param[in] pf Pattern finder that has run.
	* @param[in] foundPatterns The result of @c pf->findPatterns(module).
	*/
	virtual void doActionsAfterPatternFinderHasRun(ShPtr<PatternFinder> pf,
		const PatternFinder::Patterns &foundPatterns) = 0;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
