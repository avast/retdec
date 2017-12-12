/**
* @file include/llvmir2hll/optimizer/optimizer_manager.h
* @brief A manager managing optimizations.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_OPTIMIZER_OPTIMIZER_MANAGER_H
#define LLVMIR2HLL_OPTIMIZER_OPTIMIZER_MANAGER_H

#include "llvmir2hll/optimizer/optimizer.h"
#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/types.h"
#include "llvm-support/diagnostics.h"
#include "tl-cpputils/non_copyable.h"

namespace llvmir2hll {

class ArithmExprEvaluator;
class CallInfoObtainer;
class HLLWriter;
class Module;
class ValueAnalysis;

/**
* @brief A manager managing optimizations.
*
* Instances of this class have reference object semantics. This class is not
* meant to be subclassed.
*/
class OptimizerManager final: private tl_cpputils::NonCopyable {
public:
	OptimizerManager(const StringSet &enabledOpts, const StringSet &disabledOpts,
		ShPtr<HLLWriter> hllWriter, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio, ShPtr<ArithmExprEvaluator> arithmExprEvaluator,
		bool enableAggressiveOpts, bool enableDebug = false);
	~OptimizerManager();

	void optimize(ShPtr<Module> m);

private:
	void printOptimization(const std::string &optName) const;
	bool optShouldBeRun(const std::string &optName) const;
	void runOptimizerProvidedItShouldBeRun(ShPtr<Optimizer> optimizer);
	bool shouldSecondCopyPropagationBeRun() const;

	template<typename Optimization, typename... Args>
	void run(ShPtr<Module> m, Args &&... args);

	template<typename Optimization, typename... Args>
	void runUnlessRunInFrontend(ShPtr<Module> m, Args &&... args);

	template<typename Optimization>
	bool hasRunInFrontend();

private:
	/// No other optimization than these will be run.
	const StringSet enabledOpts;

	/// Optimizations that won't be run.
	const StringSet disabledOpts;

	/// Used HLL writer.
	ShPtr<HLLWriter> hllWriter;

	/// Used value analysis.
	ShPtr<ValueAnalysis> va;

	/// Used call info obtainer.
	ShPtr<CallInfoObtainer> cio;

	/// Used evaluator of arithmetical expressions.
	ShPtr<ArithmExprEvaluator> arithmExprEvaluator;

	/// Enable aggressive optimizations?
	bool enableAggressiveOpts;

	/// Enable emission of debug messages?
	bool enableDebug;

	/// Should we recover from out-of-memory errors during optimizations?
	bool recoverFromOutOfMemory;

	/// Set of frontend-end optimizations that were run.
	StringSet frontendRunOpts;

	/// List of our optimizations that were run.
	StringSet backendRunOpts;
};

} // namespace llvmir2hll

#endif
