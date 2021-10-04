/**
* \file include/retdec/llvmir2hll/llvmir2hll.h
* \brief Define \c LlvmIr2Hll LLVM pass.
* \copyright (c) 2020 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/Triple.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/MC/SubtargetFeature.h>
#include <llvm/Pass.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Target/TargetMachine.h>

#include "retdec/config/config.h"
#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis.h"
#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis_factory.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/config/configs/json_config.h"
#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator_factory.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_writer.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_writer_factory.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/graphs/cg/cg_writer.h"
#include "retdec/llvmir2hll/graphs/cg/cg_writer_factory.h"
#include "retdec/llvmir2hll/hll/hll_writer.h"
#include "retdec/llvmir2hll/hll/hll_writer_factory.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/llvm/llvm_debug_info_obtainer.h"
#include "retdec/llvmir2hll/llvm/llvm_intrinsic_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer_factory.h"
#include "retdec/llvmir2hll/optimizer/optimizer_manager.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_factory.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_runner.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_runners/cli_pattern_finder_runner.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_runners/no_action_pattern_finder_runner.h"
#include "retdec/llvmir2hll/semantics/semantics/compound_semantics_builder.h"
#include "retdec/llvmir2hll/semantics/semantics/default_semantics.h"
#include "retdec/llvmir2hll/semantics/semantics_factory.h"
#include "retdec/llvmir2hll/support/const_symbol_converter.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expr_types_fixer.h"
#include "retdec/llvmir2hll/support/library_funcs_remover.h"
#include "retdec/llvmir2hll/support/unreachable_code_in_cfg_remover.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/string.h"
#include "retdec/llvmir2hll/validator/validator.h"
#include "retdec/llvmir2hll/validator/validator_factory.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gen_factory.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer_factory.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/memory.h"
#include "retdec/utils/string.h"

#ifndef RETDEC_LLVMIR2HLL_LLVMIR2HLL_H
#define RETDEC_LLVMIR2HLL_LLVMIR2HLL_H

namespace retdec {
namespace llvmir2hll {

/**
* @brief This class is the main chunk of code that converts an LLVM
*        module to the specified high-level language (HLL).
*
* The decompilation is composed of the following steps:
* 1) LLVM instantiates Decompiler with the output stream, where the target
*    code will be emitted.
* 2) The function runOnModule() is called, which decompiles the given
*    LLVM IR into BIR (backend IR).
* 3) The resulting IR is then converted into the requested HLL at the end of
*    runOnModule().
*
* The HLL is specified in `-target-hll` when running llvmir2hll. Debug comments
* can be enabled by using the `-emit-debug-comments` parameter. For more
* information, run llvmir2hll with `-help`.
*/
class LlvmIr2Hll: public llvm::ModulePass
{
public:
	static char ID;
	LlvmIr2Hll(retdec::config::Config* c = nullptr);
	virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;
	virtual bool runOnModule(llvm::Module &m) override;

	void setConfig(retdec::config::Config* c);
	void setOutputString(std::string* outString);

private:
	bool initialize(llvm::Module &m);
	void createSemantics();
	void createSemanticsFromParameter();
	void createSemanticsFromLLVMIR();
	bool loadConfig();
	void saveConfig();
	bool convertLLVMIRToBIR();
	void removeLibraryFuncs();
	void removeCodeUnreachableInCFG();
	void fixSignedUnsignedTypes();
	void convertLLVMIntrinsicFunctions();
	void obtainDebugInfo();
	void initAliasAnalysis();
	void runOptimizations();
	void renameVariables();
	void convertConstantsToSymbolicNames();
	void validateResultingModule();
	void findPatterns();
	void emitCFGs();
	void emitCG();
	void emitTargetHLLCode();
	void finalize();
	void cleanup();

	llvmir2hll::StringSet parseListOfOpts(
			const std::string &opts) const;
	llvmir2hll::StringVector getIdsOfPatternFindersToBeRun() const;
	llvmir2hll::PatternFinderRunner::PatternFinders instantiatePatternFinders(
		const llvmir2hll::StringVector &pfsIds);
	ShPtr<llvmir2hll::PatternFinderRunner> instantiatePatternFinderRunner() const;

private:
	/// The input LLVM module.
	llvm::Module *llvmModule = nullptr;

	/// The resulting module in BIR.
	ShPtr<llvmir2hll::Module> resModule;

	/// The used semantics.
	ShPtr<llvmir2hll::Semantics> semantics;

	/// The used config.
	config::Config* globalConfig = nullptr;
	ShPtr<llvmir2hll::Config> config;

	/// The used HLL writer.
	ShPtr<llvmir2hll::HLLWriter> hllWriter;

	/// The used alias analysis.
	ShPtr<llvmir2hll::AliasAnalysis> aliasAnalysis;

	/// The used obtainer of information about function and function calls.
	ShPtr<llvmir2hll::CallInfoObtainer> cio;

	/// The used evaluator of arithmetical expressions.
	ShPtr<llvmir2hll::ArithmExprEvaluator> arithmExprEvaluator;

	/// The used generator of variable names.
	ShPtr<llvmir2hll::VarNameGen> varNameGen;

	/// The used renamer of variables.
	ShPtr<llvmir2hll::VarRenamer> varRenamer;

	/// Output file stream.
	std::unique_ptr<llvm::ToolOutputFile> outFile;

	/// Output string stream.
	std::unique_ptr<llvm::raw_string_ostream> outStringStream;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
