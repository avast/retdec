/**
* @file src/llvmir2hll/pattern/pattern_finder_runners/cli_pattern_finder_runner.cpp
* @brief Implementation of CLIPatternFinderRunner.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_runners/cli_pattern_finder_runner.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvm-support/diagnostics.h"

using namespace retdec::llvm_support;

namespace retdec {
namespace llvmir2hll {

namespace {

/// Indentation to be emitted before information about a pattern.
const std::string PATTERN_INFO_INDENT = "      ";

} // anonymous namespace

/**
* @brief Constructs a runner of pattern finders.
*
* @param[out] os Output stream, into which the patterns will be emited.
*/
CLIPatternFinderRunner::CLIPatternFinderRunner(llvm::raw_ostream &os):
	os(os) {}

/**
* @brief Destructs the finder.
*/
CLIPatternFinderRunner::~CLIPatternFinderRunner() {}

/**
* @brief Prints a sub-phase saying that the given finder is run.
*
* The ID of the finder is included in the output.
*/
void CLIPatternFinderRunner::doActionsBeforePatternFinderRuns(
		ShPtr<PatternFinder> pf) {
	printSubPhase("running " + pf->getId() + "PatternFinder", os);
}

/**
* @brief Prints the found patterns of the given finder.
*/
void CLIPatternFinderRunner::doActionsAfterPatternFinderHasRun(
		ShPtr<PatternFinder> pf, const PatternFinder::Patterns &foundPatterns) {
	for (const auto &pattern : foundPatterns) {
		printPatternInfo(pattern);
	}
}

/**
* @brief Prints information about the given pattern.
*/
void CLIPatternFinderRunner::printPatternInfo(const ShPtr<Pattern> &p) {
	os << PATTERN_INFO_INDENT << "Found pattern:" << "\n";
	p->print(os, PATTERN_INFO_INDENT + "  ");
}

} // namespace llvmir2hll
} // namespace retdec
