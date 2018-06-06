/**
* @file src/llvmir2hlltool/llvmir2hll.cpp
* @brief Convertor of LLVM IR into the specified target high-level language.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation of this tool is based on llvm/tools/llc/llc.cpp.
*/

#include <algorithm>
#include <fstream>
#include <memory>

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
#include <llvm/Support/PluginLoader.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetSubtargetInfo.h>

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
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter_factory.h"
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
#include "retdec/llvmir2hll/support/funcs_with_prefix_remover.h"
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
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/memory.h"
#include "retdec/utils/string.h"

using namespace llvm;

using retdec::llvmir2hll::ShPtr;
using retdec::utils::hasItem;
using retdec::utils::joinStrings;
using retdec::utils::limitSystemMemory;
using retdec::utils::limitSystemMemoryToHalfOfTotalSystemMemory;
using retdec::utils::split;
using retdec::utils::strToNum;

namespace {

//
// Parameters.
//

cl::opt<std::string> TargetHLL("target-hll",
	cl::desc("Name of the target HLL (set to 'help' to list all the supported HLLs)."),
	cl::init("!bad!"));

// We cannot use just -debug because it has been already registered :(.
cl::opt<bool> Debug("enable-debug",
	cl::desc("Enables the emission of debugging messages, like information about the current phase."),
	cl::init(false));

cl::opt<std::string> Semantics("semantics",
	cl::desc("The used semantics in the form 'sem1,sem2,...'."
		" When not given, the semantics is created based on the data in the input LLVM IR."
		" If you want to use no semantics, set this to 'none'."),
	cl::init(""));

cl::opt<std::string> ConfigPath("config-path",
	cl::desc("Path to the configuration file."),
	cl::init(""));

cl::opt<bool> EmitDebugComments("emit-debug-comments",
	cl::desc("Emits debugging comments in the generated code."),
	cl::init(false));

cl::opt<std::string> EnabledOpts("enabled-opts",
	cl::desc("A comma separated list of optimizations to be enabled, i.e. only they will run."),
	cl::init(""));

cl::opt<std::string> DisabledOpts("disabled-opts",
	cl::desc("A comma separated list of optimizations to be disabled, i.e. they will not run."),
	cl::init(""));

cl::opt<bool> NoOpts("no-opts",
	cl::desc("Disables all optimizations."),
	cl::init(false));

cl::opt<bool> AggressiveOpts("aggressive-opts",
	cl::desc("Enables aggressive optimizations."),
	cl::init(false));

cl::opt<bool> NoVarRenaming("no-var-renaming",
	cl::desc("Disables renaming of variables."),
	cl::init(false));

cl::opt<bool> NoSymbolicNames("no-symbolic-names",
	cl::desc("Disables conversion of constants into symbolic names."),
	cl::init(false));

cl::opt<bool> KeepAllBrackets("keep-all-brackets",
	cl::desc("All brackets in the generated code will be kept."),
	cl::init(false));

cl::opt<bool> KeepLibraryFunctions("keep-library-funcs",
	cl::desc("Functions from standard libraries will be kept, not turned into declarations."),
	cl::init(false));

cl::opt<bool> NoTimeVaryingInfo("no-time-varying-info",
	cl::desc("Do not emit time-varying information, like dates."),
	cl::init(false));

cl::opt<bool> NoCompoundOperators("no-compound-operators",
	cl::desc("Do not emit compound operators (like +=) instead of assignments."),
	cl::init(false));

cl::opt<bool> ValidateModule("validate-module",
	cl::desc("Validates the resulting module before generating the target code."),
	cl::init(false));

cl::opt<std::string> FindPatterns("find-patterns",
	cl::desc("If set, runs the selected comma-separated pattern finders "
		"(set to 'all' to run all of them)."),
	cl::init(""));

cl::opt<std::string> AliasAnalysis("alias-analysis",
	cl::desc("Name of the used alias analysis "
		"(the default is 'simple'; set to 'help' to list all the supported analyses)."),
	cl::init("simple"));

cl::opt<std::string> VarNameGen("var-name-gen",
	cl::desc("Name of the used generator of variable names "
		"(the default is 'fruit'; set to 'help' to list all the supported generators)."),
	cl::init("fruit"));

cl::opt<std::string> VarNameGenPrefix("var-name-gen-prefix",
	cl::desc("Prefix for all variable names returned by the used generator of variable names "
		"(the default is '')."),
	cl::init(""));

cl::opt<std::string> VarRenamer("var-renamer",
	cl::desc("Name of the used renamer of variable names "
		"(the default is 'readable'; set to 'help' to list all the supported renamers)."),
	cl::init("readable"));

cl::opt<std::string> LLVMIR2BIRConverter("llvmir2bir-converter",
	cl::desc("Name of the used convereter of LLVM IR to BIR "
		"(the default is 'orig'; set to 'help' to list all the supported renamers)."),
	cl::init("orig"));

cl::opt<bool> EmitCFGs("emit-cfgs",
	cl::desc("Enables the emission of control-flow graphs (CFGs) for each "
		"function (creates a separate file for each function in the resulting module)."),
	cl::init(false));

cl::opt<std::string> CFGWriter("cfg-writer",
	cl::desc("Name of the used CFG writer (set to 'help' to list all "
		"the supported writers, the default is 'dot')."),
	cl::init("dot"));

cl::opt<bool> EmitCG("emit-cg",
	cl::desc("Emits a call graph (CG) for the decompiled module."),
	cl::init(false));

cl::opt<std::string> CGWriter("cg-writer",
	cl::desc("Name of the used CG writer (set to 'help' to list all "
		"the supported writers, the default is 'dot')."),
	cl::init("dot"));

cl::opt<std::string> CallInfoObtainer("call-info-obtainer",
	cl::desc("Name of the used obtainer of information about function calls (set to "
		"'help' to list all the supported obtainers, the default is 'optim')."),
	cl::init("optim"));

cl::opt<std::string> ArithmExprEvaluator("arithm-expr-evaluator",
	cl::desc("Name of the used evaluator of arithmetical expressions (set to "
		"'help' to list all the supported evaluators, the default is 'c')."),
	cl::init("c"));

cl::opt<std::string> ForcedModuleName("force-module-name",
	cl::desc("If nonempty, overwrites the module name that was detected/generated by the front-end. "
		"This includes the identifier of the input LLVM IR module as well as module names in debug information."),
	cl::init(""));

cl::opt<bool> StrictFPUSemantics("strict-fpu-semantics",
	cl::desc("Forces strict FPU semantics to be used. "
		"This option may result into more correct code, although slightly less readable."),
	cl::init(false));

// Does not work with std::size_t or std::uint64_t (passing -max-memory=100
// fails with "Cannot find option named '100'!"), so we have to use unsigned
// long long, which should be 64b.
cl::opt<unsigned long long> MaxMemoryLimit("max-memory",
	cl::desc("Limit maximal memory to the given number of bytes (0 means no limit)."),
	cl::init(0));

static cl::opt<bool>
MaxMemoryLimitHalfRAM("max-memory-half-ram",
	cl::desc("Limit maximal memory to half of system RAM."),
	cl::init(false));

cl::opt<std::string> InputFilename(cl::Positional,
	cl::desc("<input bitcode>"),
	cl::init("-"));

cl::opt<std::string> OutputFilename("o",
	cl::desc("Output filename"),
	cl::value_desc("filename"));

/**
* @brief Returns a list of all supported objects by the given factory.
*
* @tparam FactoryType Type of the factory in whose objects we are interested in.
*
* The list is comma separated and has no beginning or trailing whitespace.
*/
template<typename FactoryType>
std::string getListOfSupportedObjects() {
	return joinStrings(FactoryType::getInstance().getRegisteredObjects());
}

/**
* @brief Prints an error message concerning the situation when an unsupported
*        object has been selected from the given factory.
*
* @param[in] typeOfObjectsSingular A human-readable description of the type of
*                                  objects the factory provides. In the
*                                  singular form, e.g. "HLL writer".
* @param[in] typeOfObjectsPlural A human-readable description of the type of
*                                objects the factory provides. In the plural
*                                form, e.g. "HLL writers".
*
* @tparam FactoryType Type of the factory in whose objects we are interested in.
*/
template<typename FactoryType>
void printErrorUnsupportedObject(const std::string &typeOfObjectsSingular,
		const std::string &typeOfObjectsPlural) {
	std::string supportedObjects(getListOfSupportedObjects<FactoryType>());
	if (!supportedObjects.empty()) {
		retdec::llvm_support::printErrorMessage("Invalid name of the ",
			typeOfObjectsSingular, " (supported names are: ", supportedObjects,
			").");
	} else {
		retdec::llvm_support::printErrorMessage("There are no available ",
			typeOfObjectsPlural, ". Please, recompile the backend and try it"
			" again.");
	}
}

} // anonymous namespace

namespace llvmir2hlltool {

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
class Decompiler: public ModulePass {
public:
	explicit Decompiler(raw_pwrite_stream &out);

	virtual const char *getPassName() const override { return "Decompiler"; }
	virtual bool runOnModule(Module &m) override;

public:
	/// Class identification.
	static char ID;

private:
	virtual void getAnalysisUsage(AnalysisUsage &au) const override {
		au.addRequired<LoopInfoWrapperPass>();
		au.addRequired<ScalarEvolutionWrapperPass>();
		au.setPreservesAll();
	}

	bool initialize(Module &m);
	bool limitMaximalMemoryIfRequested();
	void createSemantics();
	void createSemanticsFromParameter();
	void createSemanticsFromLLVMIR();
	bool loadConfig();
	void saveConfig();
	void convertLLVMIRToBIR();
	void removeLibraryFuncs();
	void removeCodeUnreachableInCFG();
	void removeFuncsPrefixedWith(const retdec::llvmir2hll::StringSet &prefixes);
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

	retdec::llvmir2hll::StringSet parseListOfOpts(const std::string &opts) const;
	std::string getTypeOfRunOptimizations() const;
	retdec::llvmir2hll::StringVector getIdsOfPatternFindersToBeRun() const;
	retdec::llvmir2hll::PatternFinderRunner::PatternFinders instantiatePatternFinders(
		const retdec::llvmir2hll::StringVector &pfsIds);
	ShPtr<retdec::llvmir2hll::PatternFinderRunner> instantiatePatternFinderRunner() const;
	retdec::llvmir2hll::StringSet getPrefixesOfFuncsToBeRemoved() const;

private:
	/// Output stream into which the generated code will be emitted.
	raw_pwrite_stream &out;

	/// The input LLVM module.
	Module *llvmModule;

	/// The resulting module in BIR.
	ShPtr<retdec::llvmir2hll::Module> resModule;

	/// The used semantics.
	ShPtr<retdec::llvmir2hll::Semantics> semantics;

	/// The used config.
	ShPtr<retdec::llvmir2hll::Config> config;

	/// The used HLL writer.
	ShPtr<retdec::llvmir2hll::HLLWriter> hllWriter;

	/// The used alias analysis.
	ShPtr<retdec::llvmir2hll::AliasAnalysis> aliasAnalysis;

	/// The used obtainer of information about function and function calls.
	ShPtr<retdec::llvmir2hll::CallInfoObtainer> cio;

	/// The used evaluator of arithmetical expressions.
	ShPtr<retdec::llvmir2hll::ArithmExprEvaluator> arithmExprEvaluator;

	/// The used generator of variable names.
	ShPtr<retdec::llvmir2hll::VarNameGen> varNameGen;

	/// The used renamer of variables.
	ShPtr<retdec::llvmir2hll::VarRenamer> varRenamer;

	/// The used convereter of LLVM IR to BIR.
	ShPtr<retdec::llvmir2hll::LLVMIR2BIRConverter> llvm2BIRConverter;
};

// Static variables and constants initialization.
char Decompiler::ID = 0;

/**
* @brief Constructs a new decompiler.
*
* @param[in] out Output stream into which the generated HLL code will be
*                emitted.
*/
Decompiler::Decompiler(raw_pwrite_stream &out):
	ModulePass(ID), out(out), llvmModule(nullptr), resModule(), semantics(),
	hllWriter(), aliasAnalysis(), cio(), arithmExprEvaluator(),
	varNameGen(), varRenamer(), llvm2BIRConverter() {}

bool Decompiler::runOnModule(Module &m) {
	if (Debug) retdec::llvm_support::printPhase("initialization");

	bool decompilationShouldContinue = initialize(m);
	if (!decompilationShouldContinue) {
		return false;
	}

	if (Debug) retdec::llvm_support::printPhase("conversion of LLVM IR into BIR");
	convertLLVMIRToBIR();

	retdec::llvmir2hll::StringSet funcPrefixes(getPrefixesOfFuncsToBeRemoved());
	if (Debug) retdec::llvm_support::printPhase("removing functions prefixed with [" + joinStrings(funcPrefixes) + "]");
	removeFuncsPrefixedWith(funcPrefixes);

	if (!KeepLibraryFunctions) {
		if (Debug) retdec::llvm_support::printPhase("removing functions from standard libraries");
		removeLibraryFuncs();
	}

	// The following phase needs to be done right after the conversion because
	// there may be code that is not reachable in a CFG. This happens because
	// the conversion of LLVM IR to BIR is not perfect, so it may introduce
	// unreachable code. This causes problems later during optimizations
	// because the code exists in BIR, but not in a CFG.
	if (Debug) retdec::llvm_support::printPhase("removing code that is not reachable in a CFG");
	removeCodeUnreachableInCFG();

	if (Debug) retdec::llvm_support::printPhase("signed/unsigned types fixing");
	fixSignedUnsignedTypes();

	if (Debug) retdec::llvm_support::printPhase("converting LLVM intrinsic functions to standard functions");
	convertLLVMIntrinsicFunctions();

	if (resModule->isDebugInfoAvailable()) {
		if (Debug) retdec::llvm_support::printPhase("obtaining debug information");
		obtainDebugInfo();
	}

	if (!NoOpts) {
		if (Debug) retdec::llvm_support::printPhase("alias analysis [" + aliasAnalysis->getId() + "]");
		initAliasAnalysis();

		if (Debug) retdec::llvm_support::printPhase("optimizations [" + getTypeOfRunOptimizations() + "]");
		runOptimizations();
	}

	if (!NoVarRenaming) {
		if (Debug) retdec::llvm_support::printPhase("variable renaming [" + varRenamer->getId() + "]");
		renameVariables();
	}

	if (!NoSymbolicNames) {
		if (Debug) retdec::llvm_support::printPhase("converting constants to symbolic names");
		convertConstantsToSymbolicNames();
	}

	if (ValidateModule) {
		if (Debug) retdec::llvm_support::printPhase("module validation");
		validateResultingModule();
	}

	if (!FindPatterns.empty()) {
		if (Debug) retdec::llvm_support::printPhase("finding patterns");
		findPatterns();
	}

	if (EmitCFGs) {
		if (Debug) retdec::llvm_support::printPhase("emission of control-flow graphs");
		emitCFGs();
	}

	if (EmitCG) {
		if (Debug) retdec::llvm_support::printPhase("emission of a call graph");
		emitCG();
	}

	if (Debug) retdec::llvm_support::printPhase("emission of the target code [" + hllWriter->getId() + "]");
	emitTargetHLLCode();

	if (Debug) retdec::llvm_support::printPhase("finalization");
	finalize();

	if (Debug) retdec::llvm_support::printPhase("cleanup");
	cleanup();

	return false;
}

/**
* @brief Initializes all the needed private variables.
*
* @return @c true if the decompilation should continue (the initialization went
*         OK), @c false otherwise.
*/
bool Decompiler::initialize(Module &m) {
	llvmModule = &m;

	// Maximal memory limitation.
	bool memoryLimitationSucceeded = limitMaximalMemoryIfRequested();
	if (!memoryLimitationSucceeded) {
		return false;
	}

	// Instantiate the requested HLL writer and make sure it exists. We need to
	// explicitly specify template parameters because raw_pwrite_stream has
	// a private copy constructor, so it needs to be passed by reference.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used HLL writer [" + TargetHLL + "]");
	hllWriter = retdec::llvmir2hll::HLLWriterFactory::getInstance().createObject<
		raw_pwrite_stream &>(TargetHLL, out);
	if (!hllWriter) {
		printErrorUnsupportedObject<retdec::llvmir2hll::HLLWriterFactory>(
			"target HLL", "target HLLs");
		return false;
	}

	// Instantiate the requested alias analysis and make sure it exists.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used alias analysis [" + AliasAnalysis + "]");
	aliasAnalysis = retdec::llvmir2hll::AliasAnalysisFactory::getInstance().createObject(
		AliasAnalysis);
	if (!aliasAnalysis) {
		printErrorUnsupportedObject<retdec::llvmir2hll::AliasAnalysisFactory>(
			"alias analysis", "alias analyses");
		return false;
	}

	// Instantiate the requested obtainer of information about function
	// calls and make sure it exists.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used call info obtainer [" + CallInfoObtainer + "]");
	cio = retdec::llvmir2hll::CallInfoObtainerFactory::getInstance().createObject(
		CallInfoObtainer);
	if (!cio) {
		printErrorUnsupportedObject<retdec::llvmir2hll::CallInfoObtainerFactory>(
			"call info obtainer", "call info obtainers");
		return false;
	}

	// Instantiate the requested evaluator of arithmetical expressions and make
	// sure it exists.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used evaluator of arithmetical expressions [" +
		ArithmExprEvaluator + "]");
	arithmExprEvaluator = retdec::llvmir2hll::ArithmExprEvaluatorFactory::getInstance().createObject(
		ArithmExprEvaluator);
	if (!arithmExprEvaluator) {
		printErrorUnsupportedObject<retdec::llvmir2hll::ArithmExprEvaluatorFactory>(
			"evaluator of arithmetical expressions", "evaluators of arithmetical expressions");
		return false;
	}

	// Instantiate the requested variable names generator and make sure it
	// exists.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used variable names generator [" + VarNameGen + "]");
	varNameGen = retdec::llvmir2hll::VarNameGenFactory::getInstance().createObject(
		VarNameGen, VarNameGenPrefix);
	if (!varNameGen) {
		printErrorUnsupportedObject<retdec::llvmir2hll::VarNameGenFactory>(
			"variable names generator", "variable names generators");
		return false;
	}

	// Instantiate the requested variable renamer and make sure it exists.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used variable renamer [" + VarRenamer + "]");
	varRenamer = retdec::llvmir2hll::VarRenamerFactory::getInstance().createObject(
		VarRenamer, varNameGen, true);
	if (!varRenamer) {
		printErrorUnsupportedObject<retdec::llvmir2hll::VarRenamerFactory>(
			"renamer of variables", "renamers of variables");
		return false;
	}

	// Instantiate the requested converter of LLVM IR to BIR and make sure it
	// exists.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used LLVM IR to BIR converter [" + LLVMIR2BIRConverter + "]");
	llvm2BIRConverter = retdec::llvmir2hll::LLVMIR2BIRConverterFactory::getInstance().createObject(
		LLVMIR2BIRConverter, this);
	if (!llvm2BIRConverter) {
		printErrorUnsupportedObject<retdec::llvmir2hll::LLVMIR2BIRConverterFactory>(
			"converter of LLVM IR to BIR", "converters of LLVM IR to BIR");
		return false;
	}
	// Options
	llvm2BIRConverter->setOptionStrictFPUSemantics(StrictFPUSemantics);

	createSemantics();

	bool configLoaded = loadConfig();
	if (!configLoaded) {
		return false;
	}

	// Everything went OK.
	return true;
}

/**
* @brief Limits the maximal memory of the tool based on the command-line
*        parameters.
*/
bool Decompiler::limitMaximalMemoryIfRequested() {
	if (MaxMemoryLimitHalfRAM) {
		auto limitationSucceeded = limitSystemMemoryToHalfOfTotalSystemMemory();
		if (!limitationSucceeded) {
			retdec::llvm_support::printErrorMessage(
				"Failed to limit maximal memory to half of system RAM."
			);
			return false;
		}
	} else if (MaxMemoryLimit > 0) {
		auto limitationSucceeded = limitSystemMemory(MaxMemoryLimit);
		if (!limitationSucceeded) {
			retdec::llvm_support::printErrorMessage(
				"Failed to limit maximal memory to " + std::to_string(MaxMemoryLimit) + "."
			);
		}
	}

	return true;
}

/**
* @brief Creates the used semantics.
*/
void Decompiler::createSemantics() {
	if (!Semantics.empty()) {
		// The user has requested some concrete semantics, so use it.
		createSemanticsFromParameter();
	} else {
		// The user didn't request any semantics, so create it based on the
		// data in the input LLVM IR.
		createSemanticsFromLLVMIR();
	}
}

/**
* @brief Creates the used semantics as requested by the user.
*/
void Decompiler::createSemanticsFromParameter() {
	if (Semantics.empty() || Semantics == "-") {
		// Do no use any semantics.
		if (Debug) retdec::llvm_support::printSubPhase("creating the used semantics [none]");
		semantics = retdec::llvmir2hll::DefaultSemantics::create();
	} else {
		// Use the given semantics.
		if (Debug) retdec::llvm_support::printSubPhase("creating the used semantics [" + Semantics + "]");
		semantics = retdec::llvmir2hll::CompoundSemanticsBuilder::build(split(Semantics, ','));
	}
}

/**
* @brief Creates the used semantics based on the data in the input LLVM IR.
*/
void Decompiler::createSemanticsFromLLVMIR() {
	// Create a list of the semantics to be used.
	// TODO Use some data from the input LLVM IR, like the used compiler.
	std::string usedSemantics("libc,gcc-general,win-api");

	// Use the list to create the semantics.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used semantics [" + usedSemantics + "]");
	semantics = retdec::llvmir2hll::CompoundSemanticsBuilder::build(split(usedSemantics, ','));
}

/**
* @brief Loads a config for the module.
*
* @return @a true if the config was loaded successfully, @c false otherwise.
*/
bool Decompiler::loadConfig() {
	// Currently, we always use the JSON config.
	if (ConfigPath.empty()) {
		if (Debug) retdec::llvm_support::printSubPhase("creating a new config");
		config = retdec::llvmir2hll::JSONConfig::empty();
		return true;
	}

	if (Debug) retdec::llvm_support::printSubPhase("loading the input config");
	try {
		config = retdec::llvmir2hll::JSONConfig::fromFile(ConfigPath);
		return true;
	} catch (const retdec::llvmir2hll::ConfigError &ex) {
		retdec::llvm_support::printErrorMessage(
			"Loading of the config failed: " + ex.getMessage() + "."
		);
		return false;
	}
}

/**
* @brief Saves the config file.
*/
void Decompiler::saveConfig() {
	if (!ConfigPath.empty()) {
		config->saveTo(ConfigPath);
	}
}

/**
* @brief Convert the LLVM IR module into a BIR module using the instantiated
*        converter.
*/
void Decompiler::convertLLVMIRToBIR() {
	std::string moduleName = ForcedModuleName.empty() ?
		llvmModule->getModuleIdentifier() : ForcedModuleName;
	resModule = llvm2BIRConverter->convert(llvmModule, moduleName,
		semantics, config, Debug);
}

/**
* @brief Removes defined functions which are from some standard library whose
*        header file has to be included because of some function declarations.
*/
void Decompiler::removeLibraryFuncs() {
	retdec::llvmir2hll::FuncVector removedFuncs(retdec::llvmir2hll::LibraryFuncsRemover::removeFuncs(
		resModule));

	if (Debug) {
		// Emit the functions that were turned into declarations. Before that,
		// however, sort them by name to provide a more deterministic output.
		retdec::llvmir2hll::sortByName(removedFuncs);
		for (const auto &func : removedFuncs) {
			retdec::llvm_support::printSubPhase("removing " + func->getName() + "()");
		}
	}
}

/**
* @brief Removes code from all the functions in the module that is unreachable
*        in the CFG.
*/
void Decompiler::removeCodeUnreachableInCFG() {
	retdec::llvmir2hll::UnreachableCodeInCFGRemover::removeCode(resModule);
}

/**
* @brief Removes functions with the given prefix.
*/
void Decompiler::removeFuncsPrefixedWith(const retdec::llvmir2hll::StringSet &prefixes) {
	retdec::llvmir2hll::FuncsWithPrefixRemover::removeFuncs(resModule, prefixes);
}

/**
* @brief Fixes signed and unsigned types in the resulting module.
*/
void Decompiler::fixSignedUnsignedTypes() {
	retdec::llvmir2hll::ExprTypesFixer::fixTypes(resModule);
}

/**
* @brief Converts LLVM intrinsic functions to functions from the standard
*        library.
*/
void Decompiler::convertLLVMIntrinsicFunctions() {
	retdec::llvmir2hll::LLVMIntrinsicConverter::convert(resModule);
}

/**
* @brief When available, obtains debugging information.
*/
void Decompiler::obtainDebugInfo() {
	retdec::llvmir2hll::LLVMDebugInfoObtainer::obtainVarNames(resModule);
}

/**
* @brief Initializes the alias analysis.
*/
void Decompiler::initAliasAnalysis() {
	aliasAnalysis->init(resModule);
}

/**
* @brief Runs the optimizations over the resulting module.
*/
void Decompiler::runOptimizations() {
	ShPtr<retdec::llvmir2hll::OptimizerManager> optManager(new retdec::llvmir2hll::OptimizerManager(
		parseListOfOpts(EnabledOpts), parseListOfOpts(DisabledOpts),
		hllWriter, retdec::llvmir2hll::ValueAnalysis::create(aliasAnalysis, true), cio,
		arithmExprEvaluator, AggressiveOpts, Debug));
	optManager->optimize(resModule);
}

/**
* @brief Renames variables in the resulting module by using the selected
*        variable renamer.
*/
void Decompiler::renameVariables() {
	varRenamer->renameVars(resModule);
}

/**
* @brief Converts constants in function calls to symbolic names.
*/
void Decompiler::convertConstantsToSymbolicNames() {
	retdec::llvmir2hll::ConstSymbolConverter::convert(resModule);
}

/**
* @brief Validates the resulting module.
*/
void Decompiler::validateResultingModule() {
	// Run all the registered validators over the resulting module, sorted by
	// name.
	retdec::llvmir2hll::StringVector regValidatorIDs(
		retdec::llvmir2hll::ValidatorFactory::getInstance().getRegisteredObjects());
	std::sort(regValidatorIDs.begin(), regValidatorIDs.end());
	for (const auto &id : regValidatorIDs) {
		if (Debug) retdec::llvm_support::printSubPhase("running " + id + "Validator");
		ShPtr<retdec::llvmir2hll::Validator> validator(
			retdec::llvmir2hll::ValidatorFactory::getInstance().createObject(id));
		validator->validate(resModule, true);
	}
}

/**
* @brief Finds patterns in the resulting module.
*/
void Decompiler::findPatterns() {
	retdec::llvmir2hll::StringVector pfsIds(getIdsOfPatternFindersToBeRun());
	retdec::llvmir2hll::PatternFinderRunner::PatternFinders pfs(instantiatePatternFinders(pfsIds));
	ShPtr<retdec::llvmir2hll::PatternFinderRunner> pfr(instantiatePatternFinderRunner());
	pfr->run(pfs, resModule);
}

/**
* @brief Emits the target HLL code.
*/
void Decompiler::emitTargetHLLCode() {
	hllWriter->setOptionEmitDebugComments(EmitDebugComments);
	hllWriter->setOptionKeepAllBrackets(KeepAllBrackets);
	hllWriter->setOptionEmitTimeVaryingInfo(!NoTimeVaryingInfo);
	hllWriter->setOptionUseCompoundOperators(!NoCompoundOperators);
	hllWriter->emitTargetCode(resModule);
}

/**
* @brief Finalizes the run of the back-end part.
*/
void Decompiler::finalize() {
	saveConfig();
}

/**
* @brief Cleanup.
*/
void Decompiler::cleanup() {
	// Nothing to do.

	// Note: Do not remove this phase, even if there is nothing to do. The
	// presence of this phase is needed for the analyzing scripts in
	// scripts/decompiler_tests (it marks the very last phase of a successful
	// decompilation).
}

/**
* @brief Emits a control-flow graph (CFG) for each function in the resulting
*        module.
*/
void Decompiler::emitCFGs() {
	// Make sure that the requested CFG writer exists.
	retdec::llvmir2hll::StringVector availCFGWriters(
		retdec::llvmir2hll::CFGWriterFactory::getInstance().getRegisteredObjects());
	if (!hasItem(availCFGWriters, std::string(CFGWriter))) {
		printErrorUnsupportedObject<retdec::llvmir2hll::CFGWriterFactory>(
			"CFG writer", "CFG writers");
		return;
	}

	// Instantiate a CFG builder.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());

	// Get the extension of the files that will be written (we use the CFG
	// writer's name for this purpose).
	std::string fileExt(CFGWriter);

	// For each function in the resulting module...
	for (auto i = resModule->func_definition_begin(),
			e = resModule->func_definition_end(); i != e; ++i) {
		// Open the output file.
		std::string fileName(OutputFilename + ".cfg." + (*i)->getName() + "." + fileExt);
		std::ofstream out(fileName.c_str());
		if (!out) {
			retdec::llvm_support::printErrorMessage("Cannot open " + fileName + " for writing.");
			return;
		}
		// Create a CFG for the current function and emit it into the opened
		// file.
		ShPtr<retdec::llvmir2hll::CFGWriter> writer(retdec::llvmir2hll::CFGWriterFactory::getInstance(
			).createObject<ShPtr<retdec::llvmir2hll::CFG>, std::ostream &>(
				CFGWriter, cfgBuilder->getCFG(*i), out));
		ASSERT_MSG(writer, "instantiation of the requested CFG writer `"
			<< CFGWriter << "` failed");
		writer->emitCFG();
	}
}

/**
* @brief Emits a call graph (CG) for the resulting module.
*/
void Decompiler::emitCG() {
	// Make sure that the requested CG writer exists.
	retdec::llvmir2hll::StringVector availCGWriters(
		retdec::llvmir2hll::CGWriterFactory::getInstance().getRegisteredObjects());
	if (!hasItem(availCGWriters, std::string(CGWriter))) {
		printErrorUnsupportedObject<retdec::llvmir2hll::CGWriterFactory>(
			"CG writer", "CG writers");
		return;
	}

	// Get the extension of the file that will be written (we use the CG
	// writer's name for this purpose).
	std::string fileExt(CGWriter);

	// Open the output file.
	std::string fileName(OutputFilename + ".cg." + fileExt);
	std::ofstream out(fileName.c_str());
	if (!out) {
		retdec::llvm_support::printErrorMessage("Cannot open " + fileName + " for writing.");
		return;
	}

	// Create a CG for the current module and emit it into the opened file.
	ShPtr<retdec::llvmir2hll::CGWriter> writer(retdec::llvmir2hll::CGWriterFactory::getInstance(
		).createObject<ShPtr<retdec::llvmir2hll::CG>, std::ostream &>(
			CGWriter, retdec::llvmir2hll::CGBuilder::getCG(resModule), out));
	ASSERT_MSG(writer,
		"instantiation of the requested CG writer `" << CGWriter << "` failed");
	writer->emitCG();
}

/**
* @brief Parses the given list of optimizations.
*
* @a opts should be a list of strings separated by a comma.
*/
retdec::llvmir2hll::StringSet Decompiler::parseListOfOpts(const std::string &opts) const {
	retdec::llvmir2hll::StringVector parsedOpts(split(opts, ','));
	return retdec::llvmir2hll::StringSet(parsedOpts.begin(), parsedOpts.end());
}

/**
* @brief Returns the type of optimizations that should be run (as a string).
*/
std::string Decompiler::getTypeOfRunOptimizations() const {
	return AggressiveOpts ? "aggressive" : "normal";
}

/**
* @brief Returns the IDs of pattern finders to be run.
*/
retdec::llvmir2hll::StringVector Decompiler::getIdsOfPatternFindersToBeRun() const {
	if (FindPatterns == "all") {
		// Get all of them.
		return retdec::llvmir2hll::PatternFinderFactory::getInstance().getRegisteredObjects();
	} else {
		// Get only the selected IDs.
		return split(FindPatterns, ',');
	}
}

/**
* @brief Instantiates and returns the pattern finders described by their ID.
*
* If a pattern finder cannot be instantiated, a warning message is emitted.
*/
retdec::llvmir2hll::PatternFinderRunner::PatternFinders Decompiler::instantiatePatternFinders(
		const retdec::llvmir2hll::StringVector &pfsIds) {
	// Pattern finders need a value analysis, so create it.
	initAliasAnalysis();
	ShPtr<retdec::llvmir2hll::ValueAnalysis> va(retdec::llvmir2hll::ValueAnalysis::create(aliasAnalysis, true));

	// Re-initialize cio to be sure its up-to-date.
	cio->init(retdec::llvmir2hll::CGBuilder::getCG(resModule), va);

	retdec::llvmir2hll::PatternFinderRunner::PatternFinders pfs;
	for (const auto pfId : pfsIds) {
		ShPtr<retdec::llvmir2hll::PatternFinder> pf(
			retdec::llvmir2hll::PatternFinderFactory::getInstance().createObject(pfId, va, cio));
		if (!pf && Debug) {
			retdec::llvm_support::printWarningMessage("the requested pattern finder '" + pfId + "' does not exist");
		} else {
			pfs.push_back(pf);
		}
	}
	return pfs;
}

/**
* @brief Instantiates and returns a proper PatternFinderRunner.
*/
ShPtr<retdec::llvmir2hll::PatternFinderRunner> Decompiler::instantiatePatternFinderRunner() const {
	if (Debug) {
		return ShPtr<retdec::llvmir2hll::PatternFinderRunner>(new retdec::llvmir2hll::CLIPatternFinderRunner(llvm::errs()));
	}
	return ShPtr<retdec::llvmir2hll::PatternFinderRunner>(new retdec::llvmir2hll::NoActionPatternFinderRunner());
}

/**
* @brief Returns the prefixes of functions to be removed.
*/
retdec::llvmir2hll::StringSet Decompiler::getPrefixesOfFuncsToBeRemoved() const {
	return config->getPrefixesOfFuncsToBeRemoved();
}

//
// External interface
//

class DecompilerTargetMachine: public TargetMachine {
public:
	DecompilerTargetMachine(const Target &t, StringRef dataLayoutString,
		const Triple &targetTriple, StringRef cpu, StringRef fs,
		const TargetOptions &options):
			TargetMachine(t, dataLayoutString, targetTriple, cpu, fs, options) {}

	virtual bool addPassesToEmitFile(PassManagerBase &pm,
		raw_pwrite_stream &out, CodeGenFileType fileType,
		bool disableVerify, AnalysisID startBefore, AnalysisID startAfter,
		AnalysisID stopAfter, MachineFunctionInitializer *mfInitializer) override;
};

bool DecompilerTargetMachine::addPassesToEmitFile(PassManagerBase &pm,
		raw_pwrite_stream &out, CodeGenFileType fileType,
		bool disableVerify, AnalysisID startBefore, AnalysisID startAfter,
		AnalysisID stopAfter, MachineFunctionInitializer *mfInitializer) {
	if (fileType != TargetMachine::CGFT_AssemblyFile) {
		return true;
	}

	// Add and initialize all required passes to perform the decompilation.
	pm.add(new LoopInfoWrapperPass());
	pm.add(new ScalarEvolutionWrapperPass());
	pm.add(new Decompiler(out));

	return false;
}

} // namespace llvmir2hlltool

//
// llvm/tools/llc/llc.cpp
//

namespace {

Target decompilerTarget;

std::unique_ptr<tool_output_file> getOutputStream() {
	// Open the file.
	std::error_code ec;
	auto out = std::make_unique<tool_output_file>(OutputFilename, ec, sys::fs::F_None);
	if (ec) {
		errs() << ec.message() << '\n';
		return {};
	}
	return out;
}

int compileModule(char **argv, LLVMContext &context) {
	// Load the module to be compiled.
	SMDiagnostic err;
	std::unique_ptr<Module> mod(parseIRFile(InputFilename, err, context));
	if (!mod) {
		err.print(argv[0], errs());
		return 1;
	}

	// If we are supposed to override the target triple, do so now.
	Triple triple(mod->getTargetTriple());
	if (triple.getTriple().empty()) {
		triple.setTriple(sys::getDefaultTargetTriple());
	}

	// Get the target-specific parser.
	auto target = std::make_unique<llvmir2hlltool::DecompilerTargetMachine>(
		decompilerTarget, "", triple, "", "", TargetOptions()
	);
	assert(target && "Could not allocate target machine!");
	assert(mod && "Should have exited after outputting help!");

	// Figure out where we are going to send the output.
	auto out = getOutputStream();
	if (!out) {
		return 1;
	}

	// Build up all of the passes that we want to do to the module.
	legacy::PassManager pm;

	// Add an appropriate TargetLibraryInfo pass for the module's triple.
	TargetLibraryInfoImpl tlii(Triple(mod->getTargetTriple()));
	pm.add(new TargetLibraryInfoWrapperPass(tlii));

	// Override default to generate verbose assembly.
	{
		raw_pwrite_stream &os(out->os());

		bool disableVerify = false;
		AnalysisID startBefore = nullptr;
		AnalysisID startAfter = nullptr;
		AnalysisID stopAfter = nullptr;
		MachineFunctionInitializer *mfInitializer = nullptr;

		// Ask the target to add back-end passes as necessary.
		if (target->addPassesToEmitFile(pm, os, TargetMachine::CodeGenFileType(),
				disableVerify, startBefore, startAfter, stopAfter, mfInitializer)) {
			errs() << argv[0] << ": target does not support generation of this"
					<< " file type!\n";
			return 1;
		}

		// Before executing passes, print the final values of the LLVM options.
		cl::PrintOptionValues();

		pm.run(*mod);
	}

	// Declare success.
	out->keep();

	return 0;
}

} // anonymous namespace

int main(int argc, char **argv) {
	sys::PrintStackTraceOnErrorSignal(argv[0]);
	PrettyStackTraceProgram X(argc, argv);
	llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.
	EnableDebugBuffering = true;

	cl::ParseCommandLineOptions(argc, argv,
		"convertor of LLVMIR into the target high-level language\n");

	LLVMContext context;
	int rc = compileModule(argv, context);
	return rc;
}
