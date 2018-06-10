/**
 * @file src/bin2llvmirtool/bin2llvmir.cpp
 * @brief Converts binary file into LLVM IR bitcode (*.bc).
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 *
 * Optimizations may be specified an arbitrary number of times on the command
 * line, They are run in the order specified.
 *
 * Created by taking LLVM's tool opt, removing all unneeded code, and adding
 * some code specific to our purpose.
 */

#include <algorithm>
#include <iostream>
#include <memory>
#include <set>

#include <llvm/ADT/Triple.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
#include <llvm/Analysis/LoopPass.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/Bitcode/BitcodeWriterPass.h>
#include <llvm/CodeGen/CommandFlags.h>
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
#include <llvm/Support/PluginLoader.h>
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

#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/memory.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

using namespace llvm;

// The OptimizationList is automatically populated with registered Passes by the
// PassNameParser.
//
static cl::list<const PassInfo*, bool, PassNameParser>
PassList(cl::desc("Optimizations available:"));

// Other command line options...
//
static cl::opt<std::string>
OutputFilename("o", cl::desc("Output filename"),
		cl::value_desc("filename"));

// Does not work with std::size_t or std::uint64_t (passing -max-memory=100
// fails with "Cannot find option named '100'!"), so we have to use unsigned
// long long, which should be 64b.
static cl::opt<unsigned long long>
MaxMemoryLimit("max-memory",
		cl::desc("Limit maximal memory to the given number of bytes (0 means no limit)."),
		cl::init(0));

static cl::opt<bool>
MaxMemoryLimitHalfRAM("max-memory-half-ram",
		cl::desc("Limit maximal memory to half of system RAM."),
		cl::init(false));

static cl::opt<bool>
NoVerify("disable-verify", cl::desc("Do not run the verifier"), cl::Hidden);

static cl::opt<bool>
VerifyEach("verify-each", cl::desc("Verify after each transform"));

static cl::opt<bool>
DisableInline("disable-inlining", cl::desc("Do not run the inliner pass"));

static cl::opt<bool>
DisableLoopUnrolling("disable-loop-unrolling",
		cl::desc("Disable loop unrolling in all relevant passes"),
		cl::init(false));

static cl::opt<bool>
DisableLoopVectorization("disable-loop-vectorization",
		cl::desc("Disable the loop vectorization pass"),
		cl::init(false));

static cl::opt<bool>
DisableSLPVectorization("disable-slp-vectorization",
		cl::desc("Disable the slp vectorization pass"),
		cl::init(false));

static cl::opt<bool>
DisableSimplifyLibCalls("disable-simplify-libcalls",
		cl::desc("Disable simplify-libcalls"));

/**
 * These passes are considered to be from LLVM, not from RetDec.
 * We do not want to write phase information for each of them.
 * We aggregate them to a single phase called 'LLVM'.
 *
 * This list was taken from:
 * /scripts/decompiler_tests/analysis/analyses/phase_runtime_analysis.py
 *
 * However, we do want to recognize some LLVM phases (e.g. 'Bitcode Writer').
 * Moreover, some phases were renamed because their original names are not
 * very descriptive (e.g. 'Print module to stderr').
 */
std::set<std::string> llvmPasses =
{
	// LLVM passes to aggregate to a single phase called 'LLVM'.
	//
	"Aggressive Dead Code Elimination",
	"Assign names to anonymous instructions",
	"Assumption cache tracker",
	"Basic Alias Analysis (stateless AA impl)",
	"Bit-tracking dead code elimination",
	"CallGraph Construction",
	"Canonicalize natural loops",
	"Combine redundant instructions",
	"Dead Code Elimination",
	"Dead Global Elimination",
	"Dead Instruction Elimination",
	"Dead Store Elimination",
	"Debug info verifier",
	"Delete dead loops",
	"Demanded bits analysis",
	"Dominator Tree Construction",
	"Early CSE",
	"Function alias analysis results",
	"Global Value Numbering",
	"Global Variable Optimizer",
	"Induction Variable Simplification",
	"Interprocedural Sparse Conditional Constant Propagation",
	"Interprocedural constant propagation",
	"Jump Threading",
	"Lazy Value Information Analysis",
	"Loop Invariant Code Motion",
	"Loop-Closed SSA Form Pass",
	"Loop access analysis",
	"Loop load elimination",
	"Lower 'expect' Intrinsics",
	"Memory Dependence Analysis",
	"Merge Duplicate Global Constants",
	"Module Verifier",
	"Natural Loop Information",
	"No Alias Analysis (always returns 'may' alias)",
	"No target information",
	"Parse ir",
	"Preliminary module verification",
	"Promote memory to register",
	"Reassociate expressions",
	"Recognize loop idioms",
	"Rotate Loops",
	"Scalar Evolution Analysis",
	"Scalar Replacement of Aggregates (SSAUp)",
	"Simple constant propagation",
	"Simplify loop cfg",
	"Simplify the CFG",
	"Sparse Conditional Constant Propagation",
	"Strip Unused Function Prototypes",
	"Target Library Information",
	"Target transform information",
	"Type-based alias analysis",
	"Value Propagation",

	// LLVM passes which we want to keep.
	//
//	"Bitcode Writer",
//	"Print module to stderr", // renamed to "Assembly Writer"
};
std::set<std::string> llvmPassesNormalized;

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
			if (llvmPassesNormalized.count(retdec::utils::toLower(PhaseName)))
			{
				if (!llvmPassesNormalized.count(retdec::utils::toLower(LastPhase)))
				{
					retdec::llvm_support::printPhase(LlvmAggregatePhaseName);
				}
			}
			else
			{
				retdec::llvm_support::printPhase(PhaseName);
			}

			// LastPhase gets updated every time.
			LastPhase = PhaseName;

			return false;
		}

		const char *getPassName() const override
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
 * Add the pass to the pass manager + possible verification.
 */
static inline void addPassWithPossibleVerification(
		legacy::PassManagerBase &PM,
		Pass *P,
		const std::string& phaseName = std::string())
{
	std::string pn = phaseName.empty() ? P->getPassName() : phaseName;

	PM.add(new ModulePassPrinter(pn));
	PM.add(P);

	// If we are verifying all of the intermediate steps, add the verifier...
	if (VerifyEach)
	{
		PM.add(createVerifierPass());
	}
}

/**
 * Add the pass to the pass manager - no verification.
 */
static inline void addPassWithoutVerification(
		legacy::PassManagerBase &PM,
		Pass *P,
		const std::string& phaseName = std::string())
{
	std::string pn = phaseName.empty() ? P->getPassName() : phaseName;

	PM.add(new ModulePassPrinter(pn));
	PM.add(P);
}

/**
* Limits the maximal memory of the tool based on the command-line parameters.
*/
void limitMaximalMemoryIfRequested()
{
	if (MaxMemoryLimitHalfRAM)
	{
		auto limitationSucceeded = retdec::utils::limitSystemMemoryToHalfOfTotalSystemMemory();
		if (!limitationSucceeded)
		{
			throw std::runtime_error("failed to limit maximal memory to half of system RAM");
		}
	}
	else if (MaxMemoryLimit > 0)
	{
		auto limitationSucceeded = retdec::utils::limitSystemMemory(MaxMemoryLimit);
		if (!limitationSucceeded)
		{
			throw std::runtime_error(
				"failed to limit maximal memory to " + std::to_string(MaxMemoryLimit)
			);
		}
	}
}

/**
 * Call a bunch of LLVM initialization functions, same as the original opt.
 */
void initializeLlvmPasses()
{
	// Initialize passes
	PassRegistry &Registry = *PassRegistry::getPassRegistry();
	initializeCore(Registry);
	initializeScalarOpts(Registry);
	initializeIPO(Registry);
	initializeAnalysis(Registry);
	initializeTransformUtils(Registry);
	initializeInstCombine(Registry);
	initializeTarget(Registry);
}

/**
 * Create an empty input module.
 */
std::unique_ptr<Module> createLlvmModule(LLVMContext& Context)
{
	SMDiagnostic Err;

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
	if (!NoVerify && verifyModule(*M, &errs()))
	{
		throw std::runtime_error("created llvm::Module is broken");
	}

	return M;
}

/**
 * Create bitcode output file object.
 */
std::unique_ptr<tool_output_file> createBitcodeOutputFile()
{
	std::unique_ptr<tool_output_file> Out;

	if (OutputFilename.empty())
	{
		throw std::runtime_error("output file was not specified");
	}

	std::error_code EC;
	Out.reset(new tool_output_file(OutputFilename, EC, sys::fs::F_None));
	if (EC)
	{
		throw std::runtime_error(
			"failed to create llvm::tool_output_file for .bc: " + EC.message()
		);
	}

	return Out;
}

/**
 * Create assembly output file object.
 */
std::unique_ptr<tool_output_file> createAssemblyOutputFile()
{
	std::unique_ptr<tool_output_file> Out;

	std::string out = OutputFilename;
	if (out.empty())
	{
		throw std::runtime_error("output file was not specified");
	}

	std::string asmOut = out + ".ll";
	if (out.find_last_of('.') != std::string::npos)
	{
		asmOut = out.substr(0, out.find_last_of('.')) + ".ll";
	}

	std::error_code EC;
	Out.reset(new tool_output_file(asmOut, EC, sys::fs::F_None));
	if (EC)
	{
		throw std::runtime_error(
			"failed to create llvm::tool_output_file for .dsm: " + EC.message()
		);
	}

	return Out;
}

/**
 * Real main -- it does all the work.
 */
int _main(int argc, char **argv)
{
	std::transform (
			llvmPasses.begin(),
			llvmPasses.end(),
			std::inserter(llvmPassesNormalized, llvmPassesNormalized.end()),
			retdec::utils::toLower);

	retdec::llvm_support::printPhase("Initialization");
	initializeLlvmPasses();

	cl::ParseCommandLineOptions(
			argc,
			argv,
			// Program overview.
			"binary -> llvm .bc modular decompiler and optimizer\n");

	limitMaximalMemoryIfRequested();

	LLVMContext Context;
	std::unique_ptr<Module> M = createLlvmModule(Context);

	// Add an appropriate TargetLibraryInfo pass for the module's triple.
	Triple ModuleTriple(M->getTargetTriple());
	TargetLibraryInfoImpl TLII(ModuleTriple);

	// Create a PassManager to hold and optimize the collection of passes we are
	// about to build.
	legacy::PassManager Passes;

	// The -disable-simplify-libcalls flag actually disables all builtin optzns.
	if (DisableSimplifyLibCalls)
	{
		TLII.disableAllFunctions();
	}
	addPassWithoutVerification(Passes, new TargetLibraryInfoWrapperPass(TLII));

	// Add internal analysis passes from the target machine.
	addPassWithoutVerification(
			Passes,
			createTargetTransformInfoWrapperPass(TargetIRAnalysis()));

	// Create a new optimization pass for each one specified on the command line
	for (unsigned i = 0; i < PassList.size(); ++i)
	{
		const PassInfo *PassInf = PassList[i];
		Pass *P = nullptr;
		if (PassInf->getTargetMachineCtor())
		{
			P = PassInf->getTargetMachineCtor()(nullptr);
		}
		else if (PassInf->getNormalCtor())
		{
			P = PassInf->getNormalCtor()();
		}
		else
		{
			throw std::runtime_error(std::string("cannot create pass: ")
					+ PassInf->getPassName());
		}

		if (P)
		{
			addPassWithPossibleVerification(Passes, P);
		}
	}

	// Check that the module is well formed on completion of optimization
	if (!NoVerify && !VerifyEach)
	{
		addPassWithoutVerification(Passes, createVerifierPass());
	}

	// Write bitcode to the output as the last step.
	std::unique_ptr<tool_output_file> bcOut = createBitcodeOutputFile();
	raw_ostream *bcOs = &bcOut->os();
	bool PreserveBitcodeUseListOrder = true;
	addPassWithoutVerification(
			Passes,
			createBitcodeWriterPass(*bcOs, PreserveBitcodeUseListOrder));

	// Write assembly to the output as the last step.
	std::unique_ptr<tool_output_file> llOut = createAssemblyOutputFile();
	raw_ostream *llOs = &llOut->os();
	bool PreserveAssemblyUseListOrder = true;
	addPassWithoutVerification(
			Passes,
			createPrintModulePass(*llOs, "", PreserveAssemblyUseListOrder),
			"Assembly Writer"); // original name = "Print module to stderr"

	// Before executing passes, print the final values of the LLVM options.
	cl::PrintOptionValues();

	// Now that we have all of the passes ready, run them.
	Passes.run(*M);

	// Declare success.
	retdec::llvm_support::printPhase("Cleanup");
	bcOut->keep();
	llOut->keep();
	return EXIT_SUCCESS;
}

/**
 * Main function -- calls real main and handles exceptions.
 */
int main(int argc, char **argv)
{
	bool ret = EXIT_SUCCESS;

	try
	{
		ret = _main(argc, argv);
	}
	catch (const std::runtime_error& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	return ret;
}
