/**
* @file include/retdec/llvmir2hll/optimizer/optimizer_manager.h
* @brief A manager managing optimizations.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZER_MANAGER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZER_MANAGER_H

#include "retdec/llvmir2hll/optimizer/optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
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
class OptimizerManager final: private retdec::utils::NonCopyable {
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

	/// List of our optimizations that were run.
	StringSet backendRunOpts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
