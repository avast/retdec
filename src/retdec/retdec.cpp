/**
 * @file src/retdec/retdec.cpp
 * @brief RetDec library.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/ADT/Triple.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
#include <llvm/Analysis/LoopPass.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/Bitcode/BitcodeWriterPass.h>
#include <llvm/CodeGen/CommandFlags.inc>
#include <llvm/IR/CFG.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LegacyPassNameParser.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/InitializePasses.h>
#include <llvm/LinkAllIR.h>
#include <llvm/MC/SubtargetFeature.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/SystemUtils.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/optimizations/provider_init/provider_init.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"

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

#include "retdec/config/config.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/retdec/retdec.h"
#include "retdec/utils/memory.h"

using retdec::llvmir2hll::ShPtr;
using retdec::utils::hasItem;
using retdec::utils::joinStrings;
using retdec::utils::limitSystemMemory;
using retdec::utils::limitSystemMemoryToHalfOfTotalSystemMemory;
using retdec::utils::split;
using retdec::utils::strToNum;

/**
 * Create an empty input module.
 */
std::unique_ptr<llvm::Module> createLlvmModule(llvm::LLVMContext& Context)
{
	llvm::SMDiagnostic Err;

	std::string c = "; ModuleID = 'test'\nsource_filename = \"test\"\n";
	auto mb = llvm::MemoryBuffer::getMemBuffer(c);
	if (mb == nullptr)
	{
		throw std::runtime_error("failed to create llvm::MemoryBuffer");
	}
	std::unique_ptr<Module> M = parseIR(mb->getMemBufferRef(), Err, Context);
	if (M == nullptr)
	{
		throw std::runtime_error("failed to create llvm::Module");
	}

	// Immediately run the verifier to catch any problems before starting up the
	// pass pipelines. Otherwise we can crash on broken code during
	// doInitialization().
	if (verifyModule(*M, &errs()))
	{
		throw std::runtime_error("created llvm::Module is broken");
	}

	return M;
}

namespace retdec {

common::BasicBlock fillBasicBlock(
		bin2llvmir::Config* config,
		llvm::BasicBlock& bb,
		llvm::BasicBlock& bbEnd)
{
	common::BasicBlock ret;

	ret.setStartEnd(
		bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(&bb),
		bin2llvmir::AsmInstruction::getBasicBlockEndAddress(&bbEnd)
	);

	for (auto pit = pred_begin(&bb), e = pred_end(&bb); pit != e; ++pit)
	{
		// Find BB with address - there should always be some.
		// Some BBs may not have addresses - e.g. those inside
		// if-then-else instruction models.
		auto* pred = *pit;
		auto start = bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(pred);
		while (start.isUndefined())
		{
			pred = pred->getPrevNode();
			assert(pred);
			start = bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(pred);
		}
		ret.preds.insert(start);
	}

	for (auto sit = succ_begin(&bbEnd), e = succ_end(&bbEnd); sit != e; ++sit)
	{
		// Find BB with address - there should always be some.
		// Some BBs may not have addresses - e.g. those inside
		// if-then-else instruction models.
		auto* succ = *sit;
		auto start = bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(succ);
		while (start.isUndefined())
		{
			succ = succ->getPrevNode();
			assert(succ);
			start = bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(succ);
		}
		ret.succs.insert(start);
	}
	// MIPS likely delays slot hack - recognize generated pattern and
	// find all sucessors.
	// Also applicable to ARM cond call/return patterns, and other cases.
	if (bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(&bbEnd).isUndefined() // no addr
			&& (++pred_begin(&bbEnd)) == pred_end(&bbEnd) // single pred
			&& bbEnd.getPrevNode() == *pred_begin(&bbEnd)) // pred right before
	{
		auto* br = llvm::dyn_cast<llvm::BranchInst>(
				(*pred_begin(&bbEnd))->getTerminator());
		if (br
				&& br->isConditional()
				&& br->getSuccessor(0) == &bbEnd
				&& bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(
						br->getSuccessor(1)))
		{
			ret.succs.insert(
					bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(
							br->getSuccessor(1)));
		}
	}

	auto* nextBb = bbEnd.getNextNode(); // may be nullptr
	for (auto ai = bin2llvmir::AsmInstruction(&bb);
			ai.isValid() && ai.getBasicBlock() != nextBb;
			ai = ai.getNext())
	{
		ret.instructions.push_back(ai.getCapstoneInsn());

		for (auto& i : ai)
		{
			auto call = llvm::dyn_cast<llvm::CallInst>(&i);
			if (call && call->getCalledFunction())
			{
				auto cf = call->getCalledFunction();
				auto target = bin2llvmir::AsmInstruction::getFunctionAddress(cf);
				if (target.isUndefined())
				{
					target = config->getFunctionAddress(cf);
				}
				if (target.isDefined())
				{
					auto src = ai.getAddress();
					// MIPS hack: there are delay slots on MIPS, calls/branches
					// are placed at the end of the next instruction (delay slot)
					// we need to modify reference address.
					// This assums that all references on MIPS have delays slots of
					// 4 bytes, and therefore need to be fixed, it it is not the
					// case, it will cause problems.
					//
					if (config->getConfig().architecture.isMipsOrPic32())
					{
						src -= 4;
					}

					ret.calls.emplace(
							common::BasicBlock::CallEntry{src, target});
				}
			}
		}
	}

	return ret;
}

common::Function fillFunction(
		bin2llvmir::Config* config,
		llvm::Function& f)
{
	common::Function ret(
			bin2llvmir::AsmInstruction::getFunctionAddress(&f),
			bin2llvmir::AsmInstruction::getFunctionEndAddress(&f),
			f.getName()
	);

	for (llvm::BasicBlock& bb : f)
	{
		// There are more BBs in LLVM IR than we created in control-flow
		// decoding - e.g. BBs inside instructions that behave like
		// if-then-else created by capstone2llvmir.
		if (bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(&bb).isUndefined())
		{
			continue;
		}

		llvm::BasicBlock* bbEnd = &bb;
		while (bbEnd->getNextNode())
		{
			// Next has address -- is a proper BB.
			//
			if (bin2llvmir::AsmInstruction::getTrueBasicBlockAddress(
					bbEnd->getNextNode()).isDefined())
			{
				break;
			}
			else
			{
				bbEnd = bbEnd->getNextNode();
			}
		}

		ret.basicBlocks.emplace(
				fillBasicBlock(config, bb, *bbEnd));
	}

	for (auto* u : f.users())
	{
		if (auto* i = llvm::dyn_cast<llvm::Instruction>(u))
		{
			if (auto ai = bin2llvmir::AsmInstruction(i))
			{
				auto addr = ai.getAddress();
				// MIPS hack: there are delay slots on MIPS, calls/branches
				// are placed at the end of the next instruction (delay slot)
				// we need to modify reference address.
				// This assums that all references on MIPS have delays slots of
				// 4 bytes, and therefore need to be fixed, it it is not the
				// case, it will cause problems.
				//
				if (config->getConfig().architecture.isMipsOrPic32())
				{
					addr -= 4;
				}
				ret.codeReferences.insert(addr);
			}
		}
	}

	return ret;
}

void fillFunctions(
		llvm::Module& module,
		retdec::common::FunctionSet* fs)
{
	if (fs == nullptr)
	{
		return;
	}

	auto* config = bin2llvmir::ConfigProvider::getConfig(&module);
	if (config == nullptr)
	{
		return;
	}

	for (llvm::Function& f : module.functions())
	{
		if (f.isDeclaration()
			|| f.empty()
			|| bin2llvmir::AsmInstruction::getFunctionAddress(&f).isUndefined())
		{
			auto sa = config->getFunctionAddress(&f);
			if (sa.isDefined())
			{
				fs->emplace(common::Function(sa, sa, f.getName()));
			}
			continue;
		}

		fs->emplace(fillFunction(config, f));
	}
}

LlvmModuleContextPair disassemble(
		const std::string& inputPath,
		retdec::common::FunctionSet* fs)
{
	auto context = std::make_unique<llvm::LLVMContext>();
	auto module = createLlvmModule(*context);

	config::Config c;
	c.setInputFile(inputPath);

	// Create a PassManager to hold and optimize the collection of passes we
	// are about to build.
	llvm::legacy::PassManager pm;

	pm.add(new bin2llvmir::ProviderInitialization(&c));
	pm.add(new bin2llvmir::Decoder());

	// Now that we have all of the passes ready, run them.
	pm.run(*module);

	fillFunctions(*module, fs);

	return LlvmModuleContextPair{std::move(module), std::move(context)};
}

//==============================================================================
// bin2llvmir
//==============================================================================

/**
 * Call a bunch of LLVM initialization functions, same as the original opt.
 */
llvm::PassRegistry& initializeLlvmPasses()
{
	// Initialize passes
	llvm::PassRegistry& Registry = *llvm::PassRegistry::getPassRegistry();
	initializeCore(Registry);
	initializeScalarOpts(Registry);
	initializeIPO(Registry);
	initializeAnalysis(Registry);
	initializeTransformUtils(Registry);
	initializeInstCombine(Registry);
	initializeTarget(Registry);
	return Registry;
}

/**
* Limits the maximal memory of the tool based on the command-line parameters.
*/
void limitMaximalMemoryIfRequested(const retdec::config::Parameters& params)
{
	if (params.isMaxMemoryLimitHalfRam())
	{
		auto ok = retdec::utils::limitSystemMemoryToHalfOfTotalSystemMemory();
		if (!ok)
		{
			throw std::runtime_error(
				"failed to limit maximal memory to half of system RAM"
			);
		}
	}
	else if (auto lim = params.getMaxMemoryLimit(); lim > 0)
	{
		auto ok = retdec::utils::limitSystemMemory(lim);
		if (!ok)
		{
			throw std::runtime_error(
				"failed to limit maximal memory to " + std::to_string(lim)
			);
		}
	}
}

/**
 * This pass just prints phase information about other, subsequent passes.
 * In pass manager, tt should be placed right before the pass which phase info
 * it is printing.
 */
class ModulePassPrinter : public ModulePass
{
	public:
		static char ID;
		std::string PhaseName;
		std::string PassName;

		static const std::string LlvmAggregatePhaseName;
		static std::string LastPhase;

	public:
		ModulePassPrinter(const std::string& phaseName) :
				ModulePass(ID),
				PhaseName(phaseName),
				PassName("ModulePass Printer: " + PhaseName)
		{

		}

		bool runOnModule(Module &M) override
		{
			// if (llvmPassesNormalized.count(retdec::utils::toLower(PhaseName)))
			// {
			// 	if (!llvmPassesNormalized.count(retdec::utils::toLower(LastPhase)))
			// 	{
			// 		retdec::llvm_support::printPhase(LlvmAggregatePhaseName);
			// 	}
			// }
			// else
			{
				retdec::llvm_support::printPhase(PhaseName);
			}

			// LastPhase gets updated every time.
			LastPhase = PhaseName;

			return false;
		}

		llvm::StringRef getPassName() const override
		{
			return PassName.c_str();
		}

		void getAnalysisUsage(AnalysisUsage &AU) const override
		{
			AU.setPreservesAll();
		}
};
char ModulePassPrinter::ID = 0;
std::string ModulePassPrinter::LastPhase = std::string();
const std::string ModulePassPrinter::LlvmAggregatePhaseName = "LLVM";

/**
 * Add the pass to the pass manager - no verification.
 */
static inline void addPass(
		legacy::PassManagerBase& PM,
		Pass* P,
		const std::string& phaseName = std::string())
{
	std::string pn = phaseName.empty() ? P->getPassName().str() : phaseName;

	PM.add(new ModulePassPrinter(pn));
	PM.add(P);
}

/**
 * Create bitcode output file object.
 */
std::unique_ptr<ToolOutputFile> createBitcodeOutputFile(
		const retdec::config::Parameters& params)
{
	std::unique_ptr<ToolOutputFile> Out;

	auto& bitcodeOut = params.getOutputBitcodeFile();
	if (bitcodeOut.empty())
	{
		throw std::runtime_error("bitcode output file was not specified");
	}

	std::error_code EC;
	Out.reset(new ToolOutputFile(bitcodeOut, EC, sys::fs::F_None));
	if (EC)
	{
		throw std::runtime_error(
			"failed to create llvm::ToolOutputFile for .bc: " + EC.message()
		);
	}

	return Out;
}

/**
 * Create assembly output file object.
 */
std::unique_ptr<ToolOutputFile> createAssemblyOutputFile(
		const retdec::config::Parameters& params)
{
	std::unique_ptr<ToolOutputFile> Out;

	auto& asmOut = params.getOutputLlvmirFile();
	if (asmOut.empty())
	{
		throw std::runtime_error("LLVM IR output file was not specified");
	}

	std::error_code EC;
	Out.reset(new ToolOutputFile(asmOut, EC, sys::fs::F_None));
	if (EC)
	{
		throw std::runtime_error(
			"failed to create llvm::ToolOutputFile for .ll: " + EC.message()
		);
	}

	return Out;
}

//==============================================================================
// llvmir2hll
//==============================================================================

std::string TargetHLL = "c";
std::string OutputFormat = "plain";
bool Debug = true;
std::string Semantics = "";
std::string ConfigPath = "";
bool EmitDebugComments = true;
std::string EnabledOpts = "";
std::string DisabledOpts = "";
bool NoOpts = false;
bool AggressiveOpts = false;
bool NoVarRenaming = false;
bool NoSymbolicNames = false;
bool KeepAllBrackets = false;
bool KeepLibraryFunctions = false;
bool NoTimeVaryingInfo = false;
bool NoCompoundOperators = false;
bool ValidateModule = false;
std::string FindPatterns = "";
std::string AliasAnalysis = "simple";
std::string VarNameGen = "fruit";
std::string VarNameGenPrefix = "";
std::string VarRenamer = "readable";
bool EmitCFGs = false;
std::string CFGWriter = "dot";
bool EmitCG = false;
std::string CGWriter = "dot";
std::string CallInfoObtainer = "optim";
std::string ArithmExprEvaluator = "c";
std::string ForcedModuleName = "";
bool StrictFPUSemantics = false;
std::string OutputFilename;

std::unique_ptr<ToolOutputFile> getOutputStream(
		const retdec::config::Parameters& params)
{
	// Open the file.
	std::error_code ec;
	auto out = std::make_unique<ToolOutputFile>(params.getOutputFile(), ec, sys::fs::F_None);
	if (ec)
	{
		errs() << ec.message() << '\n';
		return {};
	}
	return out;
}

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
			typeOfObjectsPlural, ". Please SHIT, recompile the backend and try it"
			" again.");
	}
}

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
	explicit Decompiler(
			raw_pwrite_stream &out,
			const retdec::config::Parameters& params,
			config::Config& c);

	virtual llvm::StringRef getPassName() const override { return "Decompiler"; }
	virtual bool runOnModule(Module &m) override;

public:
	/// Class identification.
	static char ID;

private:
	virtual void getAnalysisUsage(AnalysisUsage &au) const override {
		au.addRequired<llvm::LoopInfoWrapperPass>();
		au.addRequired<llvm::ScalarEvolutionWrapperPass>();
		au.setPreservesAll();
	}

	bool initialize(Module &m);
	// bool limitMaximalMemoryIfRequested();
	void createSemantics();
	void createSemanticsFromParameter();
	void createSemanticsFromLLVMIR();
	bool loadConfig();
	// void saveConfig();
	bool convertLLVMIRToBIR();
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

	const retdec::config::Parameters& params;

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
};

// Static variables and constants initialization.
char Decompiler::ID = 0;

/**
* @brief Constructs a new decompiler.
*
* @param[in] out Output stream into which the generated HLL code will be
*                emitted.
*/
Decompiler::Decompiler(
		raw_pwrite_stream &out,
		const retdec::config::Parameters& params,
		config::Config& c)
		:
		ModulePass(ID),
		out(out),
		params(params),
		llvmModule(nullptr),
		resModule(),
		semantics(),
		// config(&c),
		// config(retdec::llvmir2hll::JSONConfig::fromString(c.generateJsonString())),
		hllWriter(),
		aliasAnalysis(),
		cio(),
		arithmExprEvaluator(),
		varNameGen(),
		varRenamer()
{
	// std::cout << c.generateJsonString() << std::endl;
}

bool Decompiler::runOnModule(Module &m) {
	if (Debug) retdec::llvm_support::printPhase("initialization");

	bool decompilationShouldContinue = initialize(m);
	if (!decompilationShouldContinue) {
		return false;
	}

	if (Debug) retdec::llvm_support::printPhase("conversion of LLVM IR into BIR");
	decompilationShouldContinue = convertLLVMIRToBIR();
	if (!decompilationShouldContinue) {
		return false;
	}

	retdec::llvmir2hll::StringSet funcPrefixes(getPrefixesOfFuncsToBeRemoved());
	if (Debug) retdec::llvm_support::printPhase("removing functions prefixed with [" + joinStrings(funcPrefixes) + "]");
	removeFuncsPrefixedWith(funcPrefixes);

	// if (!KeepLibraryFunctions) {
	// 	if (Debug) retdec::llvm_support::printPhase("removing functions from standard libraries");
	// 	removeLibraryFuncs();
	// }

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
	// bool memoryLimitationSucceeded = limitMaximalMemoryIfRequested();
	// if (!memoryLimitationSucceeded) {
	// 	return false;
	// }

	// Instantiate the requested HLL writer and make sure it exists. We need to
	// explicitly specify template parameters because raw_pwrite_stream has
	// a private copy constructor, so it needs to be passed by reference.
	if (Debug) retdec::llvm_support::printSubPhase("creating the used HLL writer [" + TargetHLL + "]");
	hllWriter = retdec::llvmir2hll::HLLWriterFactory::getInstance().createObject<
		raw_pwrite_stream &>(TargetHLL, out, OutputFormat);
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
// bool Decompiler::limitMaximalMemoryIfRequested() {
// 	if (MaxMemoryLimitHalfRAM) {
// 		auto limitationSucceeded = limitSystemMemoryToHalfOfTotalSystemMemory();
// 		if (!limitationSucceeded) {
// 			retdec::llvm_support::printErrorMessage(
// 				"Failed to limit maximal memory to half of system RAM."
// 			);
// 			return false;
// 		}
// 	} else if (MaxMemoryLimit > 0) {
// 		auto limitationSucceeded = limitSystemMemory(MaxMemoryLimit);
// 		if (!limitationSucceeded) {
// 			retdec::llvm_support::printErrorMessage(
// 				"Failed to limit maximal memory to " + std::to_string(MaxMemoryLimit) + "."
// 			);
// 		}
// 	}

// 	return true;
// }

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
// void Decompiler::saveConfig() {
	// if (!ConfigPath.empty()) {
	// 	config->saveTo(ConfigPath);
	// }
// }

/**
* @brief Convert the LLVM IR module into a BIR module using the instantiated
*        converter.
* @return @c True if decompilation should continue, @c False if something went
*         wrong and decompilation should abort.
*/
bool Decompiler::convertLLVMIRToBIR() {
	auto llvm2BIRConverter = retdec::llvmir2hll::LLVMIR2BIRConverter::create(this);
	// Options
	llvm2BIRConverter->setOptionStrictFPUSemantics(StrictFPUSemantics);

	std::string moduleName = ForcedModuleName.empty() ?
		llvmModule->getModuleIdentifier() : ForcedModuleName;
	resModule = llvm2BIRConverter->convert(llvmModule, moduleName,
		semantics, config, Debug);

	return true;
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
	// saveConfig();
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
	const retdec::config::Parameters& params;
	config::Config& c;

	DecompilerTargetMachine(
			const Target &t,
			StringRef dataLayoutString,
			const Triple &targetTriple,
			StringRef cpu,
			StringRef fs,
			const TargetOptions &options,
			const retdec::config::Parameters& params,
			config::Config& c)
			: TargetMachine(t, dataLayoutString, targetTriple, cpu, fs, options)
			, params(params)
			, c(c)

	{}

	virtual bool addPassesToEmitFile(
			PassManagerBase &pm,
			raw_pwrite_stream &out,
			raw_pwrite_stream *,
			CodeGenFileType fileType,
			bool disableVerify = true,
			MachineModuleInfo *MMI = nullptr) override;


};

bool DecompilerTargetMachine::addPassesToEmitFile(
		PassManagerBase &pm,
		raw_pwrite_stream &out,
		raw_pwrite_stream *,
		CodeGenFileType fileType,
		bool disableVerify,
		MachineModuleInfo *MMI) {
	if (fileType != TargetMachine::CGFT_AssemblyFile) {
		return true;
	}

	// Add and initialize all required passes to perform the decompilation.
	pm.add(new LoopInfoWrapperPass());
	pm.add(new ScalarEvolutionWrapperPass());
	pm.add(new Decompiler(out, params, c));

	return false;
}

//==============================================================================
// bin2llvmir + llvmir2hll
//==============================================================================

llvm::Target decompilerTarget;

bool decompile(const retdec::config::Parameters& params)
{

//==============================================================================
// bin2llvmir
//==============================================================================

	retdec::llvm_support::printPhase("Initialization");
	auto& passRegistry = initializeLlvmPasses();

	limitMaximalMemoryIfRequested(params);

	auto context = std::make_unique<llvm::LLVMContext>();
	auto module = createLlvmModule(*context);

	// Add an appropriate TargetLibraryInfo pass for the module's triple.
	Triple ModuleTriple(module->getTargetTriple());
	TargetLibraryInfoImpl TLII(ModuleTriple);

	// Create a PassManager to hold and optimize the collection of passes we
	// are about to build.
	llvm::legacy::PassManager pm;

	// The -disable-simplify-libcalls flag actually disables all builtin optzns.
	TLII.disableAllFunctions();

	addPass(pm, new TargetLibraryInfoWrapperPass(TLII));

	// Add internal analysis passes from the target machine.
	addPass(pm, createTargetTransformInfoWrapperPass(TargetIRAnalysis()));

config::Config c;
c.setInputFile(params.getInputFile());
c.parameters = params;
c.parameters.setOrdinalNumbersDirectory("/home/peter/retdec/retdec/build/install/bin/../share/retdec/support/x86/ords/");
c.parameters.libraryTypeInfoPaths =
{
	"/home/peter/retdec/retdec/build/install/share/retdec/support/generic/types/arm.json",
	"/home/peter/retdec/retdec/build/install/share/retdec/support/generic/types/cstdlib.json",
	"/home/peter/retdec/retdec/build/install/share/retdec/support/generic/types/linux.json",
	"/home/peter/retdec/retdec/build/install/share/retdec/support/generic/types/windows.json",
	"/home/peter/retdec/retdec/build/install/share/retdec/support/generic/types/windrivers.json"
};
c.parameters.staticSignaturePaths =
{
	"/home/peter/retdec/retdec/build/install/share/retdec/support/generic/yara_patterns/static-code",
};

ConfigPath = c.parameters.getOutputConfigFile();
OutputFilename = c.parameters.getOutputFile();

pm.add(new bin2llvmir::ProviderInitialization(&c));

	std::vector<std::string> passes =
	{
		// retdec
		//"provider-init",
		"decoder",
		"verify",
		"x86-addr-spaces",
		"x87-fpu",
		"main-detection",
		"idioms-libgcc",
		"inst-opt",
		"cond-branch-opt",
		"syscalls",
		"stack",
		"constants",
		"param-return",
		"inst-opt-rda",
		"inst-opt",
		"simple-types",
		"generate-dsm",
		"remove-asm-instrs",
		"class-hierarchy",
		"select-fncs",
		"unreachable-funcs",
		"inst-opt",
		"register-localization",
		"value-protect",
		// llvm 1
		"instcombine",
		"tbaa",
		"basicaa",
		"simplifycfg",
		"early-cse",
		"tbaa",
		"basicaa",
		"globalopt",
		"mem2reg",
		"instcombine",
		"simplifycfg",
		"early-cse",
		"lazy-value-info",
		"jump-threading",
		"correlated-propagation",
		"simplifycfg",
		"instcombine",
		"simplifycfg",
		"reassociate",
		"loops",
		"loop-simplify",
		"lcssa",
		"loop-rotate",
		"licm",
		"lcssa",
		"instcombine",
		"loop-simplifycfg",
		"loop-simplify",
		"aa",
		"loop-accesses",
		"loop-load-elim",
		"lcssa",
		"indvars",
		"loop-idiom",
		"loop-deletion",
		"gvn",
		"sccp",
		"instcombine",
		"lazy-value-info",
		"jump-threading",
		"correlated-propagation",
		"dse",
		"bdce",
		"adce",
		"simplifycfg",
		"instcombine",
		"strip-dead-prototypes",
		"globaldce",
		"constmerge",
		"constprop",
		"instcombine",
		// llvm 2
		"instcombine",
		"tbaa",
		"basicaa",
		"simplifycfg",
		"early-cse",
		"tbaa",
		"basicaa",
		"globalopt",
		"mem2reg",
		"instcombine",
		"simplifycfg",
		"early-cse",
		"lazy-value-info",
		"jump-threading",
		"correlated-propagation",
		"simplifycfg",
		"instcombine",
		"simplifycfg",
		"reassociate",
		"loops",
		"loop-simplify",
		"lcssa",
		"loop-rotate",
		"licm",
		"lcssa",
		"instcombine",
		"loop-simplifycfg",
		"loop-simplify",
		"aa",
		"loop-accesses",
		"loop-load-elim",
		"lcssa",
		"indvars",
		"loop-idiom",
		"loop-deletion",
		"gvn",
		"sccp",
		"instcombine",
		"lazy-value-info",
		"jump-threading",
		"correlated-propagation",
		"dse",
		"bdce",
		"adce",
		"simplifycfg",
		"instcombine",
		"strip-dead-prototypes",
		"globaldce",
		"constmerge",
		"constprop",
		"instcombine",
		// retdec + llvm
		"inst-opt",
		"simple-types",
		"stack-ptr-op-remove",
		"idioms",
		"instcombine",
		"inst-opt",
		"idioms",
		"remove-phi",
		"value-protect",
		"config-generator",
		"sink",
	};
	for (auto& p : passes)
	{
		if (auto* info = passRegistry.getPassInfo(p))
		{
			if (auto* ctr = info->getNormalCtor())
			{
				addPass(pm, ctr());
				continue;
			}
		}

		throw std::runtime_error("cannot create pass: " + p);
	}

	// Check that the module is well formed on completion of optimization
	addPass(pm, createVerifierPass());

	// Write bitcode to the output as the last step.
	std::unique_ptr<ToolOutputFile> bcOut = createBitcodeOutputFile(params);
	raw_ostream *bcOs = &bcOut->os();
	bool PreserveBitcodeUseListOrder = false;
	addPass(pm, createBitcodeWriterPass(*bcOs, PreserveBitcodeUseListOrder));

	// Write assembly to the output as the last step.
	std::unique_ptr<ToolOutputFile> llOut = createAssemblyOutputFile(params);
	raw_ostream *llOs = &llOut->os();
	bool PreserveAssemblyUseListOrder = false;
	addPass(
			pm,
			createPrintModulePass(*llOs, "", PreserveAssemblyUseListOrder),
			"Assembly Writer"); // original name = "Print module to stderr"

	// Now that we have all of the passes ready, run them.
	// pm.run(*module);

	// Declare success.
	// retdec::llvm_support::printPhase("Cleanup");
	// bcOut->keep();
	// llOut->keep();

//==============================================================================
// llvmir2hll
//==============================================================================

	llvm::Triple triple(module->getTargetTriple());
	if (triple.getTriple().empty()) {
		triple.setTriple(sys::getDefaultTargetTriple());
	}

	// Get the target-specific parser.
	auto target = std::make_unique<DecompilerTargetMachine>(
		decompilerTarget, "", triple, "", "", TargetOptions(), params, c
	);

	// Figure out where we are going to send the output.
	auto out = getOutputStream(params);
	if (!out) {
		return EXIT_FAILURE;
	}

	// Override default to generate verbose assembly.
	{
		raw_pwrite_stream &os(out->os());

		bool disableVerify = false;

		// Ask the target to add back-end passes as necessary.
		if (target->addPassesToEmitFile(
				pm,
				os,
				nullptr,
				llvm::TargetMachine::CodeGenFileType(),
				disableVerify)) {
			errs() << ": target does not support generation of this"
					<< " file type!\n";
			return 1;
		}

	// 	// Before executing passes, print the final values of the LLVM options.
	// 	// cl::PrintOptionValues();

	// 	// pm.run(*mod);
	}

// pm.add(new LoopInfoWrapperPass());
// pm.add(new ScalarEvolutionWrapperPass());
// raw_pwrite_stream &os(out->os());
// pm.add(new Decompiler(os));

//==============================================================================
// together
//==============================================================================

	pm.run(*module);

	retdec::llvm_support::printPhase("Cleanup");
	bcOut->keep();
	llOut->keep();
	out->keep();

	return EXIT_SUCCESS;
}

} // namespace retdec
