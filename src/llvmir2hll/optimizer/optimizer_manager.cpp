/**
* @file src/llvmir2hll/optimizer/optimizer_manager.cpp
* @brief Implementation of OptimizerManager.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/hll/hll_writer.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizer_manager.h"
#include "retdec/llvmir2hll/optimizer/optimizers/aggressive_deref_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/aggressive_global_to_local_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/auxiliary_variables_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/bit_op_to_log_op_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/bit_shift_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/break_continue_return_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/c_array_arg_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/c_cast_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/copy_propagation_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/dead_code_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/dead_local_assign_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/deref_address_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/deref_to_array_index_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/empty_array_to_string_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/empty_stmt_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_before_loop_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_structure_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_to_switch_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/llvm_intrinsics_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/loop_last_continue_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/no_init_var_def_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/pre_while_true_loop_conv_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/remove_all_casts_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/remove_useless_casts_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/self_assign_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simple_copy_propagation_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/unused_global_var_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/var_def_for_loop_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/var_def_stmt_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/void_return_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/while_true_to_for_loop_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/while_true_to_ufor_loop_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/while_true_to_while_cond_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"
#include "retdec/utils/string.h"
#include "retdec/utils/system.h"

using namespace retdec::llvm_support;
using namespace std::string_literals;

using retdec::utils::hasItem;
using retdec::utils::sleep;
using retdec::utils::startsWith;

namespace retdec {
namespace llvmir2hll {
namespace {

/// Suffix of all optimizers.
const std::string OPT_SUFFIX = "Optimizer";

/// Prefix of aggressive optimizations.
const std::string AGGRESSIVE_OPTS_PREFIX = "Aggressive";

/**
* @brief Trims the optional suffix "Optimizer" from all optimization names in
*        @a opts.
*/
StringSet trimOptimizerSuffix(const StringSet &opts) {
	StringSet result;
	for (const auto &opt : opts) {
		// Does the string contain the suffix?
		if (opt.size() > OPT_SUFFIX.size() &&
				opt.substr(opt.size() - OPT_SUFFIX.size()) == OPT_SUFFIX) {
			// It does, so trim it.
			result.insert(opt.substr(0, opt.size() - OPT_SUFFIX.size()));
		} else {
			// It doesn't.
			result.insert(opt);
		}
	}
	return result;
}

} // anonymous namespace

/**
* @brief Constructs a new optimizer manager.
*
* @param[in] enabledOpts Names of optimizations. No other optimizations than
*                        these will be run.
* @param[in] disabledOpts Names of optimizations. These optimizations will not
*                         be run.
* @param[in] hllWriter HLL writer.
* @param[in] va Value analysis.
* @param[in] cio Call info obtainer.
* @param[in] arithmExprEvaluator Used evaluator of arithmetical expressions.
* @param[in] enableAggressiveOpts Enables aggressive optimizations.
* @param[in] enableDebug Enables emission of debug messages.
*
* To perform the actual optimizations, call optimize(). To get a list of
* available optimizations and their names, see our wiki.
* The names are class names of optimizers (like CopyPropagationOptimizer). You
* may or may not include the "Optimizer" suffix.
*
* If @a enabledOpts is empty, all optimizations are run. If @a disabledOpts is
* empty, also all optimizations are run. If an optimization is in both @a
* enabledOpts and @a disabledOpts, it is not run.
*
* Aggressive optimizations are run only if @a enableAggressiveOpts is @c true, or
* they are specified in @a enabledOpts.
*
* @a hllWriter, @a va, and @a cio are needed in some optimizations, so they
* have to be provided.
*
* @par Preconditions
*  - @a hllWriter, @a va, @a cio, and @a arithmExprEvaluator are non-null
*/
OptimizerManager::OptimizerManager(const StringSet &enabledOpts,
	const StringSet &disabledOpts, ShPtr<HLLWriter> hllWriter,
	ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio,
	ShPtr<ArithmExprEvaluator> arithmExprEvaluator,
	bool enableAggressiveOpts, bool enableDebug):
		enabledOpts(trimOptimizerSuffix(enabledOpts)),
		disabledOpts(trimOptimizerSuffix(disabledOpts)),
		hllWriter(hllWriter), va(va), cio(cio),
		arithmExprEvaluator(arithmExprEvaluator),
		enableAggressiveOpts(enableAggressiveOpts), enableDebug(enableDebug),
		recoverFromOutOfMemory(true), backendRunOpts() {
			PRECONDITION_NON_NULL(hllWriter);
			PRECONDITION_NON_NULL(va);
			PRECONDITION_NON_NULL(cio);
			PRECONDITION_NON_NULL(arithmExprEvaluator);
		}

/**
* @brief Destructs the manager.
*/
OptimizerManager::~OptimizerManager() {}

/**
* @brief Runs the optimizations over @a m.
*/
void OptimizerManager::optimize(ShPtr<Module> m) {
	// All optimizations should be run in order from the one that eliminates
	// most statements/expressions to the one that eliminates least number of
	// statements/expressions.
	//
	// Of course, if some optimization depend on another one, the order is
	// clear.

	//
	// Perform initial, HLL-dependent optimizations.
	//
	if (hllWriter->getId() == "py") {
		// Optimizations for Python'.
		run<RemoveAllCastsOptimizer>(m);
	}

	//
	// Perform HLL-independent optimizations.
	//
	if (!enableDebug) {
		// Since we will not emit debug comments, empty statements are useless,
		// so we can remove them.
		run<EmptyStmtOptimizer>(m);
	}

	run<RemoveUselessCastsOptimizer>(m);

	// The first part of removal of non-compound statements. The other part
	// should be run after structure optimizations because they may introduce
	// constructs that can be optimized.
	run<AggressiveDerefOptimizer>(m);
	run<AggressiveGlobalToLocalOptimizer>(m);

	// Data-flow optimizations.
	// The following optimizations should be run before CopyPropagation to
	// speed it up.
	run<UnusedGlobalVarOptimizer>(m);
	run<DeadLocalAssignOptimizer>(m, va);
	run<SimpleCopyPropagationOptimizer>(m, va, cio);
	run<CopyPropagationOptimizer>(m, va, cio);
	// AuxiliaryVariablesOptimizer should be run after CopyPropagationOptimizer.
	run<AuxiliaryVariablesOptimizer>(m, va, cio);

	// SimplifyArithmExprOptimizer should be run before loop optimizations.
	run<SimplifyArithmExprOptimizer>(m, arithmExprEvaluator);

	// Structure optimizations.
	// IfStructureOptimizer should be run before loop optimizations because
	// it may make induction variables easier to find.
	run<IfStructureOptimizer>(m);
	// LoopLastContinueOptimizer should be run after IfStructureOptimizer
	// because IfBeforeLoopOptimizer may introduce continue statements to the
	// end of loops.
	run<LoopLastContinueOptimizer>(m);
	// PreWhileTrueLoopConvOptimizer should be run before other `while True`
	// loop optimizers.
	run<PreWhileTrueLoopConvOptimizer>(m, va);
	// WhileTrueToForLoopOptimizer should be run before
	// WhileTrueToWhileCondOptimizer.
	run<WhileTrueToForLoopOptimizer>(m, va, arithmExprEvaluator);
	// TODO The WhileTrueToUForLoopOptimizer does nothing at the moment, so it
	//      makes no sense to run it.
	#if 0
	// WhileTrueToUForLoopOptimizer should be run after
	// WhileTrueToForLoopOptimizer (WhileTrueToForLoopOptimizer may produce
	// better results). Also, run it only for C because the Python HLL writer
	// does not support emission of universal for loops.
	if (hllWriter->getId() == "c") {
		run<WhileTrueToUForLoopOptimizer>(m, va);
	}
	#endif
	run<WhileTrueToWhileCondOptimizer>(m);
	run<IfBeforeLoopOptimizer>(m, va);

	// The second part of removal of non-compound statements.
	run<LLVMIntrinsicsOptimizer>(m);
	run<VoidReturnOptimizer>(m);
	run<BreakContinueReturnOptimizer>(m);

	// Expression optimizations.
	run<BitShiftOptimizer>(m);
	run<DerefAddressOptimizer>(m);
	run<EmptyArrayToStringOptimizer>(m);
	run<BitOpToLogOpOptimizer>(m, va);
	run<SimplifyArithmExprOptimizer>(m, arithmExprEvaluator);

	// Data-flow optimizations.
	// Run the CopyPropagationOptimizer once more to produce more readable
	// output. However, do this only if an optimization different than
	// CopyPropagation was run; otherwise, it makes no sense to run it again.
	if (shouldSecondCopyPropagationBeRun()) {
		run<UnusedGlobalVarOptimizer>(m);
		run<DeadLocalAssignOptimizer>(m, va);
		run<SimpleCopyPropagationOptimizer>(m, va, cio);
		run<CopyPropagationOptimizer>(m, va, cio);
	}

	// This is best to be run after DeadLocalAssignOptimizer and
	// CopyPropagationOptimizer because it can get rid of statements like `v =
	// v`, where v is a variable.
	run<SelfAssignOptimizer>(m);

	// VarDefForLoopOptimizer and VarDefStmtOptimizer are utilized also if the
	// output is Python because in this way, we may emit addresses of
	// variables, which would be impossible if this optimization is not done.
	// Indeed, recall that in Python, we do not emit definitions without an
	// initializer, so if we didn't move the definitions to the usages, there
	// wouldn't be initializers.
	run<VarDefForLoopOptimizer>(m);
	run<VarDefStmtOptimizer>(m, va);

	// SimplifyArithmExprOptimizer should be run at the end to produce the most
	// readable output.
	run<SimplifyArithmExprOptimizer>(m, arithmExprEvaluator);

	// DeadCodeOptimizer should be run at the end because it is better when
	// SimplifyArithmExprOptimizer optimizes expressions in conditions and then
	// DeadCodeOptimizer is called. The same holds for
	// DerefToArrayIndexOptimizer and IfToSwitchOptimizer.
	run<DeadCodeOptimizer>(m, arithmExprEvaluator);
	run<DerefToArrayIndexOptimizer>(m);
	run<IfToSwitchOptimizer>(m, va);

	//
	// Perform final, HLL-dependent optimizations.
	//
	if (hllWriter->getId() == "c") {
		// Optimizations for C.
		run<CCastOptimizer>(m);
		run<CArrayArgOptimizer>(m);
	} else if (hllWriter->getId() == "py") {
		// Optimizations for Python'.
		run<NoInitVarDefOptimizer>(m);
	}
}

/**
* @brief Returns @c true if the optimization with @a optId should be run, @c
*        false otherwise.
*/
bool OptimizerManager::optShouldBeRun(const std::string &optId) const {
	if (hasItem(disabledOpts, optId)) {
		// The optimization is disabled.
		return false;
	}

	if (hasItem(enabledOpts, optId)) {
		// The optimization is enabled.
		return true;
	}

	if (enabledOpts.empty() && startsWith(optId, AGGRESSIVE_OPTS_PREFIX)) {
		// It is an aggressive optimization.
		return enableAggressiveOpts;
	}

	return enabledOpts.empty();
}

/**
* @brief Runs the given optimizer provided that it should be run.
*/
void OptimizerManager::runOptimizerProvidedItShouldBeRun(ShPtr<Optimizer> optimizer) {
	const std::string OPT_ID = optimizer->getId();
	if (!optShouldBeRun(OPT_ID)) {
		return;
	}

	printOptimization(OPT_ID);

	if (recoverFromOutOfMemory) {
		// Some optimizations, most notable CopyPropagation, may run out of
		// memory on huge inputs. We try to recover from such situations by
		// catching std::bad_alloc, waiting a little bit, and then continuing.
		// This is a last-resort solution; a better fix would be to lower the
		// memory requirements of the optimizations, or to generate smaller
		// code in the first place.
		try {
			optimizer->optimize();
		} catch (const std::bad_alloc &) {
			printWarningMessage("out of memory; trying to recover");
			sleep(1);
		}
	} else {
		// Just run the optimizer and let std::bad_alloc propagate.
		optimizer->optimize();
	}

	backendRunOpts.insert(OPT_ID);
}

/**
* @brief Prints debug information about the currently run optimization with @a
*        optId.
*
* If @c enableDebug is @c false, this function does nothing.
*/
void OptimizerManager::printOptimization(const std::string &optId) const {
	if (enableDebug) {
		printSubPhase("running "s + optId + OPT_SUFFIX);
	}
}

/**
* @brief Returns @c true if a second pass of CopyPropagation should be run,
*        @c false otherwise.
*/
bool OptimizerManager::shouldSecondCopyPropagationBeRun() const {
	// TODO What if the name of the optimization changes? Should this ID be
	//      taken from somewhere else?
	const std::string COPY_PROP_ID = "CopyPropagation";

	// The second pass of CopyPropagation should be run only if
	//  (1) CopyPropagation is enabled;
	if (!optShouldBeRun(COPY_PROP_ID)) {
		// It is disabled.
		return false;
	}
	//  (2) if CopyPropagation was run, then check that at least one different
	//      optimization was run.
	if (hasItem(backendRunOpts, COPY_PROP_ID)) {
		return backendRunOpts.size() > 1;
	}
	return true;
}

/**
* @brief Runs the given optimization (specified in the template parameter) over
*        @a m with the given arguments.
*
* @tparam Optimization Optimization to be performed.
*
* @param[in] m Module to be optimized.
* @param[in] args Arguments to be passed to the optimization.
*
* If the optimization is in @c disabledOpts, it is not run. If @c enabledOpts
* is non-empty and it doesn't contain the optimization, it is also not run.
*
* If @c enableDebug is @c true, debug messages are emitted.
*/
template<typename Optimization, typename... Args>
void OptimizerManager::run(ShPtr<Module> m, Args &&... args) {
	auto optimizer = std::make_shared<Optimization>(m,
		std::forward<Args>(args)...);
	runOptimizerProvidedItShouldBeRun(optimizer);
}

} // namespace llvmir2hll
} // namespace retdec
