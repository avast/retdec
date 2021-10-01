
#include <algorithm>
#include <fstream>
#include <memory>

#include "retdec/llvmir2hll/llvmir2hll.h"
#include "retdec/utils/io/log.h"

using namespace llvm;
using namespace retdec::utils::io;
using retdec::llvmir2hll::ShPtr;
using retdec::utils::hasItem;
using retdec::utils::joinStrings;
using retdec::utils::limitSystemMemory;
using retdec::utils::limitSystemMemoryToHalfOfTotalSystemMemory;
using retdec::utils::split;
using retdec::utils::strToNum;

// Fixed options.
// These used to be controllable by user via program options, but during
// refactoring they become fixed. Implement it back if needed.
//
std::string TargetHLL = "c";
std::string oArithmExprEvaluator = "c";
bool ValidateModule = true;
bool StrictFPUSemantics = false;
std::string ForcedModuleName = "";
// This could be implemented, but it would have to be across all parts
// (including bin2llvmir), and all messages, not just pahses.
// Otherwise it is useless half solution.
bool Debug = true;
bool EmitDebugComments = true;
std::string oCFGWriter = "dot";
std::string oCGWriter = "dot";
std::string VarNameGenPrefix = "";
std::string oVarNameGen = "fruit"; // fruit|num|word
std::string oAliasAnalysis = "simple"; // simple|basic
std::string FindPatterns = ""; // all TODO: enable?
std::string oSemantics = "";

std::unique_ptr<llvm::ToolOutputFile> getOutputStream(
		const std::string& outputFile)
{
	// Open the file.
	std::error_code ec;
	auto out = std::make_unique<ToolOutputFile>(
			outputFile,
			ec,
			sys::fs::F_None
	);
	if (ec)
	{
		Log::error() << ec.message() << '\n';
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
std::string getListOfSupportedObjects()
{
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
void printErrorUnsupportedObject(
		const std::string &typeOfObjectsSingular,
		const std::string &typeOfObjectsPlural)
{
	std::string supportedObjects(getListOfSupportedObjects<FactoryType>());
	if (!supportedObjects.empty())
	{
		Log::error() << Log::Error
			<< "Invalid name of the " << typeOfObjectsSingular
			<< " (supported names are: " << supportedObjects << ")."
			<< std::endl;
	}
	else
	{
		Log::error() << Log::Error
				<< "There are no available "
				<< typeOfObjectsPlural
				<< ". Please SHIT, recompile the backend and try it again."
			<< std::endl;
	}
}

namespace retdec {
namespace llvmir2hll {

// Static variables and constants initialization.
char LlvmIr2Hll::ID = 0;

static RegisterPass<LlvmIr2Hll> X(
		"retdec-llvmir2hll",
		"LLVM IR -> HLL",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

/**
* @brief Constructs a new decompiler.
*/
LlvmIr2Hll::LlvmIr2Hll(retdec::config::Config* c) :
		ModulePass(ID)
{
	setConfig(c);
}

void LlvmIr2Hll::setConfig(retdec::config::Config* c)
{
	globalConfig = c;
}

void LlvmIr2Hll::setOutputString(std::string* outString)
{
	if (outString)
	{
		outStringStream = std::make_unique<raw_string_ostream>(*outString);
	}
}

void LlvmIr2Hll::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<llvm::LoopInfoWrapperPass>();
	au.addRequired<llvm::ScalarEvolutionWrapperPass>();
	au.setPreservesAll();
}

bool LlvmIr2Hll::runOnModule(llvm::Module &m)
{
	Log::phase("initialization");

	bool decompilationShouldContinue = initialize(m);
	if (!decompilationShouldContinue)
	{
		return false;
	}

	Log::phase("conversion of LLVM IR into BIR");
	decompilationShouldContinue = convertLLVMIRToBIR();
	if (!decompilationShouldContinue)
	{
		return false;
	}

	if (!globalConfig->parameters.isBackendKeepLibraryFuncs())
	{
		Log::phase("removing functions from standard libraries");
		removeLibraryFuncs();
	}

	// The following phase needs to be done right after the conversion because
	// there may be code that is not reachable in a CFG. This happens because
	// the conversion of LLVM IR to BIR is not perfect, so it may introduce
	// unreachable code. This causes problems later during optimizations
	// because the code exists in BIR, but not in a CFG.
	Log::phase("removing code that is not reachable in a CFG");
	removeCodeUnreachableInCFG();

	Log::phase("signed/unsigned types fixing");
	fixSignedUnsignedTypes();

	Log::phase("converting LLVM intrinsic functions to standard functions");
	convertLLVMIntrinsicFunctions();

	if (resModule->isDebugInfoAvailable())
	{
		Log::phase("obtaining debug information");
		obtainDebugInfo();
	}

	if (!globalConfig->parameters.isBackendNoOpts())
	{
		Log::phase("alias analysis [" + aliasAnalysis->getId() + "]");
		initAliasAnalysis();

		Log::phase("optimizations");
		runOptimizations();
	}

	if (!globalConfig->parameters.isBackendNoVarRenaming())
	{
		Log::phase("variable renaming [" + varRenamer->getId() + "]");
		renameVariables();
	}

	if (!globalConfig->parameters.isBackendNoSymbolicNames())
	{
		Log::phase("converting constants to symbolic names");
		convertConstantsToSymbolicNames();
	}

	if (ValidateModule)
	{
		Log::phase("module validation");
		validateResultingModule();
	}

	if (!FindPatterns.empty())
	{
		Log::phase("finding patterns");
		findPatterns();
	}

	if (globalConfig->parameters.isBackendEmitCfg())
	{
		Log::phase("emission of control-flow graphs");
		emitCFGs();
	}

	if (globalConfig->parameters.isBackendEmitCg())
	{
		Log::phase("emission of a call graph");
		emitCG();
	}

	Log::phase("emission of the target code [" + hllWriter->getId() + "]");
	emitTargetHLLCode();

	Log::phase("finalization");
	finalize();

	Log::phase("cleanup");
	cleanup();

	return false;
}

/**
* @brief Initializes all the needed private variables.
*
* @return @c true if the decompilation should continue (the initialization went
*         OK), @c false otherwise.
*/
bool LlvmIr2Hll::initialize(llvm::Module &m)
{
	llvmModule = &m;

	bool configLoaded = loadConfig();
	if (!configLoaded)
	{
		return false;
	}

	// Instantiate the requested HLL writer and make sure it exists. We need to
	// explicitly specify template parameters because raw_pwrite_stream has
	// a private copy constructor, so it needs to be passed by reference.
	Log::phase(
		"creating the used HLL writer [" + TargetHLL + "]",
		Log::SubPhase
	);

	// Output stream into which the generated code will be emitted.
	if (outStringStream)
	{
		hllWriter = llvmir2hll::HLLWriterFactory::getInstance().createObject<
		raw_string_ostream &>(TargetHLL, *outStringStream, globalConfig->parameters.getOutputFormat());
	}
	else
	{
		outFile = getOutputStream(globalConfig->parameters.getOutputFile());
		if (!outFile)
		{
			return false;
		}

		hllWriter = llvmir2hll::HLLWriterFactory::getInstance().createObject<
		raw_pwrite_stream &>(TargetHLL, outFile->os(), globalConfig->parameters.getOutputFormat());
	}

	if (!hllWriter)
	{
		printErrorUnsupportedObject<llvmir2hll::HLLWriterFactory>(
				"target HLL", "target HLLs"
		);
		return false;
	}

	// Instantiate the requested alias analysis and make sure it exists.
	Log::phase(
		"creating the used alias analysis [" + oAliasAnalysis + "]",
		Log::SubPhase
	);
	aliasAnalysis = llvmir2hll::AliasAnalysisFactory::getInstance().createObject(
		oAliasAnalysis
	);
	if (!aliasAnalysis)
	{
		printErrorUnsupportedObject<llvmir2hll::AliasAnalysisFactory>(
				"alias analysis", "alias analyses"
		);
		return false;
	}

	// Instantiate the requested obtainer of information about function
	// calls and make sure it exists.
	Log::phase(
		"creating the used call info obtainer ["
		+ globalConfig->parameters.getBackendCallInfoObtainer() + "]",
		Log::SubPhase
	);
	cio = llvmir2hll::CallInfoObtainerFactory::getInstance().createObject(
		globalConfig->parameters.getBackendCallInfoObtainer()
	);
	if (!cio)
	{
		printErrorUnsupportedObject<llvmir2hll::CallInfoObtainerFactory>(
				"call info obtainer", "call info obtainers"
		);
		return false;
	}

	// Instantiate the requested evaluator of arithmetical expressions and make
	// sure it exists.
	Log::phase(
		"creating the used evaluator of arithmetical expressions [" +
		oArithmExprEvaluator + "]",
		Log::SubPhase
	);
	auto& aeef = llvmir2hll::ArithmExprEvaluatorFactory::getInstance();
	arithmExprEvaluator = aeef.createObject(oArithmExprEvaluator);
	if (!arithmExprEvaluator)
	{
		printErrorUnsupportedObject<llvmir2hll::ArithmExprEvaluatorFactory>(
				"evaluator of arithmetical expressions",
				"evaluators of arithmetical expressions"
		);
		return false;
	}

	// Instantiate the requested variable names generator and make sure it
	// exists.
	Log::phase(
		"creating the used variable names generator [" + oVarNameGen + "]",
		Log::SubPhase
	);
	varNameGen = llvmir2hll::VarNameGenFactory::getInstance().createObject(
		oVarNameGen,
		VarNameGenPrefix
	);
	if (!varNameGen)
	{
		printErrorUnsupportedObject<llvmir2hll::VarNameGenFactory>(
				"variable names generator", "variable names generators"
		);
		return false;
	}

	// Instantiate the requested variable renamer and make sure it exists.
	Log::phase(
		"creating the used variable renamer ["
		+ globalConfig->parameters.getBackendVarRenamer() + "]",
		Log::SubPhase
	);
	varRenamer = llvmir2hll::VarRenamerFactory::getInstance().createObject(
			globalConfig->parameters.getBackendVarRenamer(),
			varNameGen,
			true
	);
	if (!varRenamer)
	{
		printErrorUnsupportedObject<llvmir2hll::VarRenamerFactory>(
				"renamer of variables", "renamers of variables"
		);
		return false;
	}

	createSemantics();

	// Everything went OK.
	return true;
}

/**
* @brief Creates the used semantics.
*/
void LlvmIr2Hll::createSemantics()
{
	if (!oSemantics.empty())
	{
		// The user has requested some concrete semantics, so use it.
		createSemanticsFromParameter();
	}
	else
	{
		// The user didn't request any semantics, so create it based on the
		// data in the input LLVM IR.
		createSemanticsFromLLVMIR();
	}
}

/**
* @brief Creates the used semantics as requested by the user.
*/
void LlvmIr2Hll::createSemanticsFromParameter()
{
	if (oSemantics.empty() || oSemantics == "-")
	{
		// Do no use any semantics.
		Log::phase(
			"creating the used semantics [none]",
			Log::SubPhase
		);
		semantics = llvmir2hll::DefaultSemantics::create();
	}
	else
	{
		// Use the given semantics.
		Log::phase(
			"creating the used semantics [" + oSemantics + "]",
			Log::SubPhase
		);
		semantics = llvmir2hll::CompoundSemanticsBuilder::build(
				split(oSemantics, ',')
		);
	}
}

/**
* @brief Creates the used semantics based on the data in the input LLVM IR.
*/
void LlvmIr2Hll::createSemanticsFromLLVMIR()
{
	// Create a list of the semantics to be used.
	// TODO Use some data from the input LLVM IR, like the used compiler.
	std::string usedSemantics("libc,gcc-general,win-api");

	// Use the list to create the semantics.
	Log::phase(
		"creating the used semantics [" + usedSemantics + "]",
		Log::SubPhase
	);
	semantics = llvmir2hll::CompoundSemanticsBuilder::build(
			split(usedSemantics, ',')
	);
}

/**
* @brief Loads a config for the module.
*
* @return @a true if the config was loaded successfully, @c false otherwise.
*/
bool LlvmIr2Hll::loadConfig()
{
	// Currently, we always use the JSON config.
	if (globalConfig == nullptr)
	{
		Log::phase("creating a new config", Log::SubPhase);
		config = llvmir2hll::JSONConfig::empty();
		return true;
	}

	Log::phase("loading the input config", Log::SubPhase);
	try
	{
		config = llvmir2hll::JSONConfig::fromString(
				globalConfig->generateJsonString()
		);
		return true;
	}
	catch (const llvmir2hll::ConfigError &ex)
	{
		Log::error() << Log::Error
			<< "Loading of the config failed: " << ex.getMessage() << "."
			<< std::endl;
		return false;
	}
}

/**
* @brief Saves the config file.
*/
void LlvmIr2Hll::saveConfig()
{
	if (globalConfig
			&& !globalConfig->parameters.getOutputConfigFile().empty())
	{
		config->saveTo(globalConfig->parameters.getOutputConfigFile());
	}
}

/**
* @brief Convert the LLVM IR module into a BIR module using the instantiated
*        converter.
* @return @c True if decompilation should continue, @c False if something went
*         wrong and decompilation should abort.
*/
bool LlvmIr2Hll::convertLLVMIRToBIR()
{
	auto llvm2BIRConverter = llvmir2hll::LLVMIR2BIRConverter::create(this);
	// Options
	llvm2BIRConverter->setOptionStrictFPUSemantics(StrictFPUSemantics);

	std::string moduleName = ForcedModuleName.empty()
			? llvmModule->getModuleIdentifier()
			: ForcedModuleName;
	resModule = llvm2BIRConverter->convert(
			llvmModule,
			moduleName,
			semantics,
			config,
			Debug
	);

	return true;
}

/**
* @brief Removes defined functions which are from some standard library whose
*        header file has to be included because of some function declarations.
*/
void LlvmIr2Hll::removeLibraryFuncs()
{
	llvmir2hll::FuncVector removedFuncs(
			llvmir2hll::LibraryFuncsRemover::removeFuncs(resModule)
	);

	if (Debug)
	{
		// Emit the functions that were turned into declarations. Before that,
		// however, sort them by name to provide a more deterministic output.
		llvmir2hll::sortByName(removedFuncs);
		for (const auto &func : removedFuncs)
		{
			Log::phase("removing " + func->getName() + "()");
		}
	}
}

/**
* @brief Removes code from all the functions in the module that is unreachable
*        in the CFG.
*/
void LlvmIr2Hll::removeCodeUnreachableInCFG()
{
	llvmir2hll::UnreachableCodeInCFGRemover::removeCode(resModule);
}

/**
* @brief Fixes signed and unsigned types in the resulting module.
*/
void LlvmIr2Hll::fixSignedUnsignedTypes()
{
	llvmir2hll::ExprTypesFixer::fixTypes(resModule);
}

/**
* @brief Converts LLVM intrinsic functions to functions from the standard
*        library.
*/
void LlvmIr2Hll::convertLLVMIntrinsicFunctions()
{
	llvmir2hll::LLVMIntrinsicConverter::convert(resModule);
}

/**
* @brief When available, obtains debugging information.
*/
void LlvmIr2Hll::obtainDebugInfo()
{
	llvmir2hll::LLVMDebugInfoObtainer::obtainVarNames(resModule);
}

/**
* @brief Initializes the alias analysis.
*/
void LlvmIr2Hll::initAliasAnalysis()
{
	aliasAnalysis->init(resModule);
}

/**
* @brief Runs the optimizations over the resulting module.
*/
void LlvmIr2Hll::runOptimizations()
{
	ShPtr<llvmir2hll::OptimizerManager> optManager(
			new llvmir2hll::OptimizerManager(
					parseListOfOpts(globalConfig->parameters.getBackendEnabledOpts()),
					parseListOfOpts(globalConfig->parameters.getBackendDisabledOpts()),
					hllWriter,
					llvmir2hll::ValueAnalysis::create(aliasAnalysis, true),
					cio,
					arithmExprEvaluator,
					Debug
			)
	);
	optManager->optimize(resModule);
}

/**
* @brief Renames variables in the resulting module by using the selected
*        variable renamer.
*/
void LlvmIr2Hll::renameVariables()
{
	varRenamer->renameVars(resModule);
}

/**
* @brief Converts constants in function calls to symbolic names.
*/
void LlvmIr2Hll::convertConstantsToSymbolicNames()
{
	llvmir2hll::ConstSymbolConverter::convert(resModule);
}

/**
* @brief Validates the resulting module.
*/
void LlvmIr2Hll::validateResultingModule()
{
	// Run all the registered validators over the resulting module, sorted by
	// name.
	llvmir2hll::StringVector regValidatorIDs(
		llvmir2hll::ValidatorFactory::getInstance().getRegisteredObjects()
	);
	std::sort(regValidatorIDs.begin(), regValidatorIDs.end());
	for (const auto &id : regValidatorIDs)
	{
		Log::phase("running " + id + "Validator", Log::SubPhase);
		ShPtr<llvmir2hll::Validator> validator(
				llvmir2hll::ValidatorFactory::getInstance().createObject(id)
		);
		validator->validate(resModule, true);
	}
}

/**
* @brief Finds patterns in the resulting module.
*/
void LlvmIr2Hll::findPatterns()
{
	llvmir2hll::StringVector pfsIds(getIdsOfPatternFindersToBeRun());
	llvmir2hll::PatternFinderRunner::PatternFinders pfs(
			instantiatePatternFinders(pfsIds)
	);
	ShPtr<llvmir2hll::PatternFinderRunner> pfr(
			instantiatePatternFinderRunner()
	);
	pfr->run(pfs, resModule);
}

/**
* @brief Emits the target HLL code.
*/
void LlvmIr2Hll::emitTargetHLLCode()
{
	hllWriter->setOptionEmitDebugComments(EmitDebugComments);
	hllWriter->setOptionKeepAllBrackets(
		globalConfig->parameters.isBackendKeepAllBrackets()
	);
	hllWriter->setOptionEmitTimeVaryingInfo(
		!globalConfig->parameters.isBackendNoTimeVaryingInfo()
	);
	hllWriter->setOptionUseCompoundOperators(
		!globalConfig->parameters.isBackendNoCompoundOperators()
	);
	hllWriter->emitTargetCode(resModule);
}

/**
* @brief Finalizes the run of the back-end part.
*/
void LlvmIr2Hll::finalize()
{
	saveConfig();
	if (outFile) outFile->keep();
}

/**
* @brief Cleanup.
*/
void LlvmIr2Hll::cleanup()
{
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
void LlvmIr2Hll::emitCFGs()
{
	if (globalConfig->parameters.getOutputFile().empty())
	{
		Log::error() << Log::Error
			<< "Output file not set, cannot generate output CFG files."
			<< std::endl;

		return;
	}

	// Make sure that the requested CFG writer exists.
	llvmir2hll::StringVector availCFGWriters(
		llvmir2hll::CFGWriterFactory::getInstance().getRegisteredObjects());
	if (!hasItem(availCFGWriters, oCFGWriter))
	{
		printErrorUnsupportedObject<llvmir2hll::CFGWriterFactory>(
			"CFG writer", "CFG writers");
		return;
	}

	// Instantiate a CFG builder.
	ShPtr<llvmir2hll::CFGBuilder> cfgBuilder(
			llvmir2hll::NonRecursiveCFGBuilder::create()
	);

	// Get the extension of the files that will be written (we use the CFG
	// writer's name for this purpose).
	std::string fileExt(oCFGWriter);

	// For each function in the resulting module...
	for (auto i = resModule->func_definition_begin(),
			e = resModule->func_definition_end();
			i != e;
			++i)
	{
		// Open the output file.
		std::string fileName(
				globalConfig->parameters.getOutputFile()
				+ ".cfg." + (*i)->getName() + "." + fileExt
		);
		std::ofstream out(fileName.c_str());
		if (!out)
		{
			Log::error() << Log::Error
				<< "Cannot open " + fileName + " for writing."
				<< std::endl;
			return;
		}
		// Create a CFG for the current function and emit it into the opened
		// file.
		auto& cfgwf = llvmir2hll::CFGWriterFactory::getInstance();
		ShPtr<llvmir2hll::CFGWriter> writer(
				cfgwf.createObject<ShPtr<llvmir2hll::CFG>, std::ostream &>(
						oCFGWriter,
						cfgBuilder->getCFG(*i),
						out
				)
		);
		ASSERT_MSG(
				writer,
				"instantiation of the requested CFG writer `"
				<< oCFGWriter << "` failed"
		);
		writer->emitCFG();
	}
}

/**
* @brief Emits a call graph (CG) for the resulting module.
*/
void LlvmIr2Hll::emitCG()
{
	if (globalConfig->parameters.getOutputFile().empty())
	{
		Log::error() << Log::Error
			<< "Output file not set, cannot generate output CG file."
			<< std::endl;
		return;
	}

	// Make sure that the requested CG writer exists.
	auto& inst = llvmir2hll::CGWriterFactory::getInstance();
	llvmir2hll::StringVector availCGWriters(
			inst.getRegisteredObjects()
	);
	if (!hasItem(availCGWriters, std::string(oCGWriter)))
	{
		printErrorUnsupportedObject<llvmir2hll::CGWriterFactory>(
				"CG writer", "CG writers"
		);
		return;
	}

	// Get the extension of the file that will be written (we use the CG
	// writer's name for this purpose).
	std::string fileExt(oCGWriter);

	// Open the output file.
	std::string fileName(
			globalConfig->parameters.getOutputFile() + ".cg." + fileExt
	);
	std::ofstream out(fileName.c_str());
	if (!out)
	{
		Log::error() << Log::Error
			<< "Cannot open " + fileName + " for writing."
			<< std::endl;
		return;
	}

	// Create a CG for the current module and emit it into the opened file.
	auto& cgwf = llvmir2hll::CGWriterFactory::getInstance();
	ShPtr<llvmir2hll::CGWriter> writer(
			cgwf.createObject<ShPtr<llvmir2hll::CG>, std::ostream &>(
			oCGWriter, llvmir2hll::CGBuilder::getCG(resModule), out
	));
	ASSERT_MSG(
			writer,
			"instantiation of the requested CG writer `"
			<< oCGWriter << "` failed"
	);
	writer->emitCG();
}

/**
* @brief Parses the given list of optimizations.
*
* @a opts should be a list of strings separated by a comma.
*/
retdec::llvmir2hll::StringSet LlvmIr2Hll::parseListOfOpts(
		const std::string &opts) const
{
	llvmir2hll::StringVector parsedOpts(split(opts, ','));
	return llvmir2hll::StringSet(parsedOpts.begin(), parsedOpts.end());
}

/**
* @brief Returns the IDs of pattern finders to be run.
*/
retdec::llvmir2hll::StringVector
LlvmIr2Hll::getIdsOfPatternFindersToBeRun() const
{
	if (FindPatterns == "all")
	{
		// Get all of them.
		auto& inst = llvmir2hll::PatternFinderFactory::getInstance();
		return inst.getRegisteredObjects();
	}
	else
	{
		// Get only the selected IDs.
		return split(FindPatterns, ',');
	}
}

/**
* @brief Instantiates and returns the pattern finders described by their ID.
*
* If a pattern finder cannot be instantiated, a warning message is emitted.
*/
retdec::llvmir2hll::PatternFinderRunner::PatternFinders
LlvmIr2Hll::instantiatePatternFinders(
		const retdec::llvmir2hll::StringVector &pfsIds)
{
	// Pattern finders need a value analysis, so create it.
	initAliasAnalysis();
	ShPtr<llvmir2hll::ValueAnalysis> va(
			llvmir2hll::ValueAnalysis::create(aliasAnalysis, true));

	// Re-initialize cio to be sure its up-to-date.
	cio->init(llvmir2hll::CGBuilder::getCG(resModule), va);

	llvmir2hll::PatternFinderRunner::PatternFinders pfs;
	for (const auto &pfId : pfsIds)
	{
		auto& inst = llvmir2hll::PatternFinderFactory::getInstance();
		ShPtr<llvmir2hll::PatternFinder> pf(
				inst.createObject(pfId, va, cio)
		);
		if (!pf && Debug)
		{
			Log::error() << Log::Warning
				<< "the requested pattern finder '" + pfId + "' does not exist"
				<< std::endl;
		}
		else
		{
			pfs.push_back(pf);
		}
	}
	return pfs;
}

/**
* @brief Instantiates and returns a proper PatternFinderRunner.
*/
ShPtr<retdec::llvmir2hll::PatternFinderRunner>
LlvmIr2Hll::instantiatePatternFinderRunner() const
{
	if (Debug)
	{
		return ShPtr<llvmir2hll::PatternFinderRunner>(
			new llvmir2hll::CLIPatternFinderRunner(Log::get(Log::Type::Error)));
	}
	return ShPtr<llvmir2hll::PatternFinderRunner>(
		new llvmir2hll::NoActionPatternFinderRunner()
	);
}

} // namespace llvmir2hll
} // namespace retdec
