/**
* @file include/retdec/llvmir2hll/pattern/pattern_finder_runners/cli_pattern_finder_runner.h
* @brief Runner of pattern finders for the command line interface.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDER_RUNNERS_CLI_PATTERN_FINDER_RUNNER_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDER_RUNNERS_CLI_PATTERN_FINDER_RUNNER_H

#include <vector>

#include "retdec/llvmir2hll/pattern/pattern_finder_runner.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Runner of pattern finders for the command line interface (CLI).
*
* It prints information on the command line.
*
* Instances of this class have reference object semantics.
*/
class CLIPatternFinderRunner: public PatternFinderRunner {
public:
	CLIPatternFinderRunner(llvm::raw_ostream &os);
	virtual ~CLIPatternFinderRunner() override;

private:
	virtual void doActionsBeforePatternFinderRuns(ShPtr<PatternFinder> pf) override;
	virtual void doActionsAfterPatternFinderHasRun(ShPtr<PatternFinder> pf,
		const PatternFinder::Patterns &foundPatterns) override;

	void printPatternInfo(const ShPtr<Pattern> &p);

private:
	/// Output stream, into which the patterns will be emitted.
	llvm::raw_ostream &os;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
