/**
* @file src/llvmir2hll/pattern/pattern_finder_runner.cpp
* @brief Implementation of PatternFinderRunner.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/pattern/pattern_finder_runner.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a runner of pattern finders.
*/
PatternFinderRunner::PatternFinderRunner() {}

/**
* @brief Destructs the finder.
*/
PatternFinderRunner::~PatternFinderRunner() {}

/**
* @brief Runs all the given pattern finders in @a pfs on @a module.
*
* @param[in] pfs Pattern finders to be run.
* @param[in] module The module that is passed to the finders in @a pfs.
*
* More specifically, it calls <tt>run(pf, module)</tt> on every pattern finder
* @c pf in @a pfs.
*
* @par Preconditions
*  - @a module is non-null
*/
void PatternFinderRunner::run(const PatternFinders &pfs, ShPtr<Module> module) {
	for (const auto &pf : pfs) {
		run(pf, module);
	}
}

/**
* @brief Runs the given pattern finder @a pf on @a module.
*
* @param[in] pf Pattern finder to be run.
* @param[in] module The module that is passed to @c pf->findPatterns().
*
* More specifically, the following actions are done.
*  (1) Calls doActionsBeforePatternFinderRuns() with @c pf.
*  (2) Calls @c pf->findPatterns() and stores the result.
*  (3) Calls doActionsAfterPatternFinderHasRun() with @c pf and the result
*      from (2).
*
* @par Preconditions
*  - @a module is non-null
*/
void PatternFinderRunner::run(ShPtr<PatternFinder> pf, ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	doActionsBeforePatternFinderRuns(pf);
	PatternFinder::Patterns patterns(pf->findPatterns(module));
	doActionsAfterPatternFinderHasRun(pf, patterns);
}

} // namespace llvmir2hll
} // namespace retdec
