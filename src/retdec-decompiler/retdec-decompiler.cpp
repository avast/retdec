/**
 * @file src/retdec-decompiler/retdec-decompiler.cpp
 * @brief RetDec decompiler.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <future>
#include <chrono>
#include <thread>

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

#include "retdec/ar-extractor/archive_wrapper.h"
#include "retdec/ar-extractor/detection.h"
#include "retdec/config/config.h"
#include "retdec/retdec/retdec.h"
#include "retdec/macho-extractor/break_fat.h"
#include "retdec/unpackertool/unpackertool.h"
#include "retdec/utils/binary_path.h"
#include "retdec/utils/filesystem.h"
#include "retdec/utils/io/log.h"
#include "retdec/utils/memory.h"
#include "retdec/utils/string.h"
#include "retdec/utils/version.h"

using namespace retdec::utils::io;

const int EXIT_TIMEOUT = 137;
const int EXIT_BAD_ALLOC = 135;

//
//==============================================================================
// Program options
//==============================================================================
//

class ProgramOptions
{
	public:
		std::string programName;
		retdec::config::Config& config;
		retdec::config::Parameters& params;
		std::list<std::string> _argv;

		std::string mode = "bin";
		uint64_t bitSize = 32;
		std::string arExtractPath;
		std::string arName;
		std::optional<uint64_t> arIdx;

		bool cleanup = false;
		std::set<std::string> toClean;

	public:
		ProgramOptions(
				int argc,
				char *argv[],
				retdec::config::Config& c,
				retdec::config::Parameters& p);

		void load();

	private:
		void loadOption(std::list<std::string>::iterator& i);
		bool isParam(
				std::list<std::string>::iterator i,
				const std::string& shortp,
				const std::string& longp = std::string());
		std::string getParamOrDie(std::list<std::string>::iterator& i);
		void printHelpAndDie();
		void afterLoad();
		std::string checkFile(
				const std::string& path,
				const std::string& errorMsgPrefix);
};

ProgramOptions::ProgramOptions(
		int argc,
		char *argv[],
		retdec::config::Config& c,
		retdec::config::Parameters& p)
		: config(c)
		, params(p)
{
	if (argc > 0)
	{
		programName = argv[0];
	}

	for (int i = 1; i < argc; ++i)
	{
		_argv.push_back(argv[i]);
	}
}

void ProgramOptions::load()
{
	for (auto i = _argv.begin(); i != _argv.end();)
	{
		// Load config if specified.
		if (isParam(i, "", "--config"))
		{
			auto backup = config.parameters;
			auto file = getParamOrDie(i);
			file = checkFile(file, "[--config]");

			try
			{
				config = retdec::config::Config::fromFile(file);
			}
			catch (const retdec::config::ParseException& e)
			{
				throw std::runtime_error(
					"[--config] loading of config failed: "
					+ std::string(e.what())
				);
			}

			// TODO:
			// This redefines all the params from the loaded config.
			// Maybe we should do some kind of merge.
			// But it is hard to know what was defined, what was not,
			// and which value to prefer.
			config.parameters = backup;
		}
		++i;
	}

	for (auto i = _argv.begin(); i != _argv.end();)
	{
		loadOption(i);
		if (i != _argv.end())
		{
			++i;
		}
	}

	afterLoad();
}

void ProgramOptions::loadOption(std::list<std::string>::iterator& i)
{
	std::string c = *i;

	if (isParam(i, "-h", "--help"))
	{
		printHelpAndDie();
	}
	else if (isParam(i, "", "--version"))
	{
		Log::info() << retdec::utils::version::getVersionStringLong() << "\n";
		exit(EXIT_SUCCESS);
	}
	else if (isParam(i, "", "--print-after-all"))
	{
		llvm::StringMap<llvm::cl::Option*> &opts =
				llvm::cl::getRegisteredOptions();

		auto* paa = static_cast<llvm::cl::opt<bool>*>(
					opts["print-after-all"]
		);
		paa->setInitialValue(true);
	}
	else if (isParam(i, "", "--print-before-all"))
	{
		llvm::StringMap<llvm::cl::Option*> &opts =
				llvm::cl::getRegisteredOptions();

		auto* paa = static_cast<llvm::cl::opt<bool>*>(
				opts["print-before-all"]
		);
		paa->setInitialValue(true);
	}
	else if (isParam(i, "-m", "--mode"))
	{
		auto m = getParamOrDie(i);
		if (!(m == "bin" || m == "raw"))
		{
			throw std::runtime_error(
				"[-m|--mode] unknown mode: " + m
			);
		}
		mode = m;
	}
	else if (isParam(i, "-b", "--bit-size"))
	{
		auto val = getParamOrDie(i);
		try
		{
			bitSize = std::stoull(val);
			if (!(bitSize == 16 || bitSize == 32 || bitSize == 64))
			{
				throw std::runtime_error("");
			}
		}
		catch (...)
		{
			throw std::runtime_error(
				"[-b|--bit-size] invalid value: " + val
			);
		}
	}
	else if (isParam(i, "-a", "--arch"))
	{
		auto a = getParamOrDie(i);
		if (!(a == "mips"
				|| a == "pic32"
				|| a == "arm"
				|| a == "thumb"
				|| a == "arm64"
				|| a == "powerpc"
				|| a == "x86"
				|| a == "x86-64"))
		{
			throw std::runtime_error(
				"[-a|--arch] unknown architecture: " + a
			);
		}
		config.architecture.setName(a);
	}
	else if (isParam(i, "-e", "--endian"))
	{
		auto e = getParamOrDie(i);
		if (e == "little")
		{
			config.architecture.setIsEndianLittle();
		}
		else if (e == "big")
		{
			config.architecture.setIsEndianBig();
		}
		else
		{
			throw std::runtime_error(
				"[-e|--endian] unknown endian: " + e
			);
		}
	}
	else if (isParam(i, "-f", "--output-format"))
	{
		auto of = getParamOrDie(i);
		if (!(of == "plain" || of == "json" || of == "json-human"))
		{
			throw std::runtime_error(
				"[-f|--output-format] unknown output format: " + of
			);
		}
		config.parameters.setOutputFormat(of);
	}
	else if (isParam(i, "", "--max-memory"))
	{
		auto val = getParamOrDie(i);
		try
		{
			params.setMaxMemoryLimit(std::stoull(val));
			params.setIsMaxMemoryLimitHalfRam(false);
		}
		catch (...)
		{
			throw std::runtime_error(
				"[--max-memory] invalid value: " + val
			);
		}
	}
	else if (isParam(i, "", "--no-memory-limit"))
	{
		params.setMaxMemoryLimit(0);
		params.setIsMaxMemoryLimitHalfRam(false);
	}
	else if (isParam(i, "-o", "--output"))
	{
		std::string out = getParamOrDie(i);
		params.setOutputFile(out);

		auto lastDot = out.find_last_of('.');
		if (lastDot != std::string::npos)
		{
			out = out.substr(0, lastDot);
		}
		params.setOutputAsmFile(out + ".dsm");
		params.setOutputBitcodeFile(out + ".bc");
		params.setOutputLlvmirFile(out + ".ll");
		params.setOutputConfigFile(out + ".config.json");
		params.setOutputUnpackedFile(out + "-unpacked");
		arExtractPath = out + "-extracted";
	}
	else if (isParam(i, "-k", "--keep-unreachable-funcs"))
	{
		params.setIsKeepAllFunctions(true);
	}
	else if (isParam(i, "-p", "--pdb"))
	{
		std::string pdb = checkFile(getParamOrDie(i), "[-p|--pdb]");
		config.parameters.setInputPdbFile(pdb);
	}
	else if (isParam(i, "", "--select-ranges"))
	{
		std::stringstream ranges(getParamOrDie(i));
		while(ranges.good())
		{
			std::string range;
			getline(ranges, range, ',' );
			auto r = retdec::common::stringToAddrRange(range);
			if (r.getStart().isUndefined() || r.getEnd().isUndefined())
			{
				throw std::runtime_error(
					"[--select-ranges] invalid range: " + range
				);
			}
			params.selectedRanges.insert(r);
			params.setIsKeepAllFunctions(true);
		}
	}
	else if (isParam(i, "", "--select-functions"))
	{
		std::stringstream funcs(getParamOrDie(i));
		while(funcs.good())
		{
			std::string func;
			getline(funcs, func, ',' );
			if (!func.empty())
			{
				params.selectedFunctions.insert(func);
				params.setIsKeepAllFunctions(true);
			}
		}
	}
	else if (isParam(i, "", "--select-decode-only"))
	{
		params.setIsSelectedDecodeOnly(true);
	}
	else if (isParam(i, "", "--raw-section-vma"))
	{
		auto val = getParamOrDie(i);
		retdec::common::Address addr(val);
		if (addr.isUndefined())
		{
			throw std::runtime_error(
				"[--raw-section-vma] invalid address: " + val
			);
		}
		params.setSectionVMA(addr);
	}
	else if (isParam(i, "", "--raw-entry-point"))
	{
		auto val = getParamOrDie(i);
		retdec::common::Address addr(val);
		if (addr.isUndefined())
		{
			throw std::runtime_error(
				"[--raw-entry-point] invalid address: " + val
			);
		}
		params.setEntryPoint(addr);
	}
	else if (isParam(i, "", "--cleanup"))
	{
		cleanup = true;
	}
	else if (isParam(i, "", "--config"))
	{
		getParamOrDie(i);
		// ignore: it was already processed
	}
	else if (isParam(i, "", "--disable-static-code-detection"))
	{
		params.setIsDetectStaticCode(false);
	}
	else if (isParam(i, "", "--backend-disabled-opts"))
	{
		params.setBackendDisabledOpts(getParamOrDie(i));
	}
	else if (isParam(i, "", "--backend-enabled-opts"))
	{
		params.setBackendEnabledOpts(getParamOrDie(i));
	}
	else if (isParam(i, "", "--backend-call-info-obtainer"))
	{
		auto n = getParamOrDie(i);
		if (!(n == "optim" || n == "pessim"))
		{
			throw std::runtime_error(
				"[--backend-call-info-obtainer] unknown name: " + n
			);
		}
		params.setBackendCallInfoObtainer(n);
	}
	else if (isParam(i, "", "--backend-var-renamer"))
	{
		auto s = getParamOrDie(i);
		if (!(s == "address"
				|| s == "hungarian"
				|| s == "readable"
				|| s == "simple"
				|| s == "unified"))
		{
			throw std::runtime_error(
				"[--backend-var-renamer] unknown style: " + s
			);
		}
		params.setBackendVarRenamer(s);
	}
	else if (isParam(i, "", "--backend-no-opts"))
	{
		params.setIsBackendNoOpts(true);
	}
	else if (isParam(i, "", "--backend-emit-cfg"))
	{
		params.setIsBackendEmitCfg(true);
	}
	else if (isParam(i, "", "--backend-emit-cg"))
	{
		params.setIsBackendEmitCg(true);
	}
	else if (isParam(i, "", "--backend-keep-all-brackets"))
	{
		params.setIsBackendKeepAllBrackets(true);
	}
	else if (isParam(i, "", "--backend-keep-library-funcs"))
	{
		params.setIsBackendKeepLibraryFuncs(true);
	}
	else if (isParam(i, "", "--backend-no-time-varying-info"))
	{
		params.setIsBackendNoTimeVaryingInfo(true);
	}
	else if (isParam(i, "", "--backend-no-var-renaming"))
	{
		params.setIsBackendNoVarRenaming(true);
	}
	else if (isParam(i, "", "--backend-no-compound-operators"))
	{
		params.setIsBackendNoCompoundOperators(true);
	}
	else if (isParam(i, "", "--backend-no-symbolic-names"))
	{
		params.setIsBackendNoSymbolicNames(true);
	}
	else if (isParam(i, "", "--ar-index"))
	{
		if (!arName.empty())
		{
			throw std::runtime_error(
				"[--ar-index] and [--ar-name] are mutually exclusive, "
				"use only one"
			);
		}

		auto val = getParamOrDie(i);
		try
		{
			arIdx = std::stoull(val);
		}
		catch (...)
		{
			throw std::runtime_error(
				"[--ar-index] invalid index: " + val
			);
		}
	}
	else if (isParam(i, "", "--ar-name"))
	{
		if (arIdx.has_value())
		{
			throw std::runtime_error(
				"[--ar-name] and [--ar-index] are mutually exclusive, "
				"use only one"
			);
		}

		arName = getParamOrDie(i);
	}
	else if (isParam(i, "", "--static-code-sigfile"))
	{
		auto file = checkFile(getParamOrDie(i), "[--static-code-sigfile]");
		params.userStaticSignaturePaths.insert(file);
	}
	else if (isParam(i, "", "--timeout"))
	{
		auto t = getParamOrDie(i);
		try
		{
			params.setTimeout(std::stoull(t));
		}
		catch (...)
		{
			throw std::runtime_error(
				"[--timeout] invalid timeout value: " + t
			);
		}
	}
	else if (isParam(i, "-s", "--silent"))
	{
		params.setIsVerboseOutput(false);
	}
	// Input file is the only argument that does not have -x or --xyz
	// before it. But only one input is expected.
	else if (params.getInputFile().empty())
	{
		params.setInputFile(c);
	}
	else
	{
		printHelpAndDie();
	}
}

/**
 * Some things can be set or checked only after all the arguments were loaded.
 */
void ProgramOptions::afterLoad()
{
	auto in = params.getInputFile();
	if (params.getOutputAsmFile().empty())
		params.setOutputAsmFile(in + ".dsm");
	if (params.getOutputBitcodeFile().empty())
		params.setOutputBitcodeFile(in + ".bc");
	if (params.getOutputLlvmirFile().empty())
		params.setOutputLlvmirFile(in + ".ll");
	if (params.getOutputConfigFile().empty())
		params.setOutputConfigFile(in + ".config.json");
	if (params.getOutputFile().empty())
	{
		if (params.getOutputFormat() == "plain")
			params.setOutputFile(in + ".c");
		else
			params.setOutputFile(in + ".c.json");
	}
	if (params.getOutputUnpackedFile().empty())
		params.setOutputUnpackedFile(in + "-unpacked");
	if (arExtractPath.empty())
		arExtractPath = in + "-extracted";

	if (mode == "raw")
	{
		if (params.getSectionVMA().isUndefined())
		{
			throw std::runtime_error(
				"[--mode=raw] option --raw-section-vma must be set"
			);
		}
		if (params.getEntryPoint().isUndefined())
		{
			throw std::runtime_error(
				"[--mode=raw] option --raw-entry-point must be set"
			);
		}
		if (config.architecture.isUnknown())
		{
			throw std::runtime_error(
				"[--mode=raw] option -a|--arch must be set"
			);
		}
		if (config.architecture.isEndianUnknown())
		{
			throw std::runtime_error(
				"[--mode=raw] option -e|--endian must be set"
			);
		}

		config.fileFormat.setIsRaw();
		config.fileFormat.setFileClassBits(bitSize);
		config.architecture.setBitSize(bitSize);
		params.setIsKeepAllFunctions(true);
	}

	// After everything, input file must be set.
	if (params.getInputFile().empty())
	{
		throw std::runtime_error(
			"INPUT_FILE not set"
		);
	}
}

std::string ProgramOptions::checkFile(
		const std::string& path,
		const std::string& errorMsgPrefix)
{
	if (!fs::is_regular_file(path))
	{
		throw std::runtime_error(errorMsgPrefix + " bad file: " + path);
	}
	return fs::absolute(path).string();
}

void ProgramOptions::printHelpAndDie()
{
	Log::info() << programName << R"(:
Mandatory arguments:
	INPUT_FILE File to decompile.
General arguments:
	[-o|--output FILE] Output file (default: INPUT_FILE.c if OUTPUT_FORMAT is plain, INPUT_FILE.c.json if OUTPUT_FORMAT is json|json-human).
	[-s|--silent] Turns off informative output of the decompilation.
	[-f|--output-format OUTPUT_FORMAT] Output format [plain|json|json-human] (default: plain).
	[-m|--mode MODE] Force the type of decompilation mode [bin|raw] (default: bin).
	[-p|--pdb FILE] File with PDB debug information.
	[-k|--keep-unreachable-funcs] Keep functions that are unreachable from the main function.
	[--cleanup] Removes temporary files created during the decompilation.
	[--config] Specify JSON decompilation configuration file.
	[--disable-static-code-detection] Prevents detection of statically linked code.
Selective decompilation arguments:
	[--select-ranges RANGES] Specify a comma separated list of ranges to decompile (example: 0x100-0x200,0x300-0x400,0x500-0x600).
	[--select-functions FUNCS] Specify a comma separated list of functions to decompile (example: fnc1,fnc2,fnc3).
	[--select-decode-only] Decode only selected parts (functions/ranges). Faster decompilation, but worse results.
Raw or Intel HEX decompilation arguments:
	[-a|--arch ARCH] Specify target architecture [mips|pic32|arm|thumb|arm64|powerpc|x86|x86-64].
	                 Required if it cannot be autodetected from the input (e.g. raw mode, Intel HEX).
	[-e|--endian ENDIAN] Specify target endianness [little|big].
	                     Required if it cannot be autodetected from the input (e.g. raw mode, Intel HEX).
	[-b|--bit-size SIZE] Specify target bit size [16|32|64] (default: 32).
	                     Required if it cannot be autodetected from the input (e.g. raw mode).
	[--raw-section-vma ADDRESS] Virtual address where section created from the raw binary will be placed.
	[--raw-entry-point ADDRESS] Entry point address used for raw binary (default: architecture dependent).
Archive decompilation arguments:
	[--ar-index INDEX] Pick file from archive for decompilation by its zero-based index.
	[--ar-name NAME] Pick file from archive for decompilation by its name.
	[--static-code-sigfile FILE] Adds additional signature file for static code detection.
Backend arguments:
	[--backend-disabled-opts LIST] Prevents the optimizations from the given comma-separated list of optimizations to be run.
	[--backend-enabled-opts LIST] Runs only the optimizations from the given comma-separated list of optimizations.
	[--backend-call-info-obtainer NAME] Name of the obtainer of information about function calls [optim|pessim] (Default: optim).
	[--backend-var-renamer STYLE] Used renamer of variables [address|hungarian|readable|simple|unified] (Default: readable).
	[--backend-no-opts] Disables backend optimizations.
	[--backend-emit-cfg] Emits a CFG for each function in the backend IR (in the .dot format).
	[--backend-emit-cg] Emits a CG for the decompiled module in the backend IR (in the .dot format).
	[--backend-keep-all-brackets] Keeps all brackets in the generated code.
	[--backend-keep-library-funcs] Keep functions from standard libraries.
	[--backend-no-time-varying-info] Do not emit time-varying information, like dates.
	[--backend-no-var-renaming] Disables renaming of variables in the backend.
	[--backend-no-compound-operators] Do not emit compound operators (like +=) instead of assignments.
	[--backend-no-symbolic-names] Disables the conversion of constant arguments to their symbolic names.
Decompilation process arguments:
	[--timeout SECONDS]
	[--max-memory MAX_MEMORY] Limits the maximal memory used by the given number of bytes.
	[--no-memory-limit] Disables the default memory limit (half of system RAM).
LLVM IR debug arguments:
	[--print-after-all] Dump LLVM IR to stderr after every LLVM pass.
	[--print-before-all] Dump LLVM IR to stderr before every LLVM pass.
Other arguments:
	[-h|--help] Show this help.
	[--version] Show RetDec version.
)";

	exit(EXIT_SUCCESS);
}

bool ProgramOptions::isParam(
		std::list<std::string>::iterator i,
		const std::string& shortp,
		const std::string& longp)
{
	std::string str = *i;

	if (!shortp.empty() && retdec::utils::startsWith(str, shortp))
	{
		str.erase(0, shortp.length());
		if (str.size() > 1 && str[0] == '=')
		{
			str.erase(0, 1);
			++i;
			_argv.insert(i, str);
		}
		return true;
	}

	if (!longp.empty() && retdec::utils::startsWith(str, longp))
	{
		str.erase(0, longp.length());
		if (str.size() > 1 && str[0] == '=')
		{
			str.erase(0, 1);
			++i;
			_argv.insert(i, str);
		}
		return true;
	}

	return false;
}

std::string ProgramOptions::getParamOrDie(std::list<std::string>::iterator& i)
{
	++i;
	if (i != _argv.end())
	{
		return *i;
	}
	else
	{
		printHelpAndDie();
		return std::string();
	}
}

//
//==============================================================================
// Utility functions.
//==============================================================================
//

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

//
//==============================================================================
// Decompilation.
//==============================================================================
//

/**
 * TODO: this function is exact copy of the function located in retdec/retdec.cpp.
 * The reason for this is that right now creation of correct interface that
 * would hold this function is much more time expensive than hard copy.
 *
 * This function should be located in utils/io/log.{cpp,h}. For that it should
 * now retdec::config::Parameters object. Inclusion of this object would be,
 * however, only possible after linking rapidjson library to the retdec::utils.
 * This is not wanted. Best solution would be making Parameters unaware of
 * rapidjson.
 */
void setLogsFrom(const retdec::config::Parameters& params)
{
	auto logFile = params.getLogFile();
	auto errFile = params.getErrFile();
	auto verbose = params.isVerboseOutput();

	Logger::Ptr outLog = nullptr;

	outLog.reset(
		logFile.empty()
			? new Logger(std::cout, verbose)
			: new FileLogger(logFile, verbose)
	);

	Log::set(Log::Type::Info, std::move(outLog));

	if (!errFile.empty()) {
		Log::set(Log::Type::Error, Logger::Ptr(new FileLogger(errFile)));
	}
}

int decompile(retdec::config::Config& config, ProgramOptions& po)
{
	setLogsFrom(config.parameters);

	// Macho-O extraction.
	//
	retdec::macho_extractor::BreakMachOUniversal fat(
			config.parameters.getInputFile()
	);
	if (fat.isValid())
	{
		Log::phase("Mach-O extraction");

		auto extractedFile = po.arExtractPath + "_m";

		if (config.architecture.isKnown())
		{
			if (!fat.extractArchiveForFamily(
					config.architecture.getName(),
					extractedFile))
			{
				std::stringstream ss;
				ss << "Invalid --arch option '"
						<< config.architecture.getName()
						<< "'. File contains these architecture families:"
						<< std::endl;
				fat.listArchitectures(ss);
				throw std::runtime_error(ss.str());
			}
		}
		else
		{
			if (!fat.extractBestArchive(extractedFile))
			{
				throw std::runtime_error(
						"Mach-O extraction: extractBestArchive() failed."
				);
				return EXIT_FAILURE;
			}
		}

		config.parameters.setInputFile(extractedFile);
		po.toClean.insert(extractedFile);
	}

	// Archive extraction.
	//
	if (po.arIdx || !po.arName.empty())
	{
		Log::phase("Archive extraction");

		bool ok = true;
		std::string errMsg;
		retdec::ar_extractor::ArchiveWrapper arw(
				config.parameters.getInputFile(),
				ok,
				errMsg
		);

		if (!ok)
		{
			throw std::runtime_error(
					"failed to create archive wrapper: " + errMsg
			);
		}

		if (po.arIdx)
		{
			if (!arw.extractByIndex(po.arIdx.value(), errMsg, po.arExtractPath))
			{
				throw std::runtime_error(
						"failed to extract archive: " + errMsg + "\n"
						"Error: File on index '"
						+ std::to_string(po.arIdx.value())
						+ "' was not found in the input archive."
						  " Valid indexes are 0-"
						+ std::to_string(arw.getNumberOfObjects()-1)
						+ ".\n"
				);
			}
		}
		else if (!po.arName.empty())
		{
			if (!arw.extractByName(po.arName, errMsg, po.arExtractPath))
			{
				throw std::runtime_error(
						"failed to extract archive: " + errMsg + "\n"
						"Error: File named '" + po.arName
						+ "' was not found in the input archive.\n"
				);
			}
		}

		config.parameters.setInputFile(po.arExtractPath);
		po.toClean.insert(po.arExtractPath);
	}
	else
	{
		bool ok = true;
		std::string errMsg;
		retdec::ar_extractor::ArchiveWrapper arw(
				config.parameters.getInputFile(),
				ok,
				errMsg
		);
		if (ok && arw.isThinArchive())
		{
			Log::error() << "This file is an archive!" << std::endl;
			Log::error() << "Error: File is a thin archive and cannot be decompiled." << std::endl;
			return EXIT_FAILURE;
		}
		else if (ok && arw.isEmptyArchive())
		{
			Log::error() << "This file is an archive!" << std::endl;
			Log::error() << "Error: The input archive is empty." << std::endl;
			return EXIT_FAILURE;
		}
		else if (ok)
		{
			Log::error() << "This file is an archive!" << std::endl;

			std::string result;
			if (arw.getPlainTextList(result, errMsg, false, true))
			{
				Log::error() << result << std::endl;
			}
			return EXIT_FAILURE;
		}

		if (!ok && retdec::ar_extractor::isArchive(config.parameters.getInputFile()))
		{
			Log::error() << "This file is an archive!" << std::endl;
			Log::error() << "Error: The input archive has invalid format." << std::endl;
			return EXIT_FAILURE;
		}
	}

	// Unpacking
	//

	Log::phase("Unpacking");
	std::vector<std::string> unpackArgs;
	unpackArgs.push_back("whatever_program_name");
	unpackArgs.push_back(config.parameters.getInputFile());
	unpackArgs.push_back("--output");
	unpackArgs.push_back(config.parameters.getOutputUnpackedFile());
	char* uargv[4] = {
			unpackArgs[0].data(),
			unpackArgs[1].data(),
			unpackArgs[2].data(),
			unpackArgs[3].data()
	};
	auto unpackCode = retdec::unpackertool::_main(4, uargv);
	if (unpackCode == 0) // EXIT_CODE_OK
	{
		config.parameters.setInputFile(
				config.parameters.getOutputUnpackedFile()
		);
		po.toClean.insert(config.parameters.getOutputUnpackedFile());
	}

	// Decompilation.
	//
	return retdec::decompile(config);
}

//
//==============================================================================
// Cleanup.
//==============================================================================
//

void cleanup(ProgramOptions& po)
{
	if (!po.cleanup)
	{
		return;
	}

	for (auto& p : po.toClean)
	{
		remove(p.c_str());
	}
}

//
//==============================================================================
// Main.
//==============================================================================
//

int main(int argc, char **argv)
{
	// Set LLVM debug.
	//
	llvm::sys::PrintStackTraceOnErrorSignal(argv[0]);
	llvm::PrettyStackTraceProgram X(argc, argv);
	llvm::llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.
	llvm::EnableDebugBuffering = true;

	// Load the default config parameters.
	//
	retdec::config::Config config;
	auto binpath = retdec::utils::getThisBinaryDirectoryPath();
	fs::path configPath(fs::canonical(binpath).parent_path());
	configPath.append("share");
	configPath.append("retdec");
	configPath.append("decompiler-config.json");
	if (fs::exists(configPath))
	{
		config = retdec::config::Config::fromFile(configPath.string());
		config.parameters.fixRelativePaths(fs::canonical(configPath).parent_path().string());
	}

	// Parse program arguments.
	//
	ProgramOptions po(argc, argv, config, config.parameters);
	try
	{
		po.load();
	}
	catch (const std::runtime_error& e)
	{
		Log::error() << Log::Error << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	// Limit program memory.
	//
	limitMaximalMemoryIfRequested(config.parameters);


	// Decompile.
	//
	int ret = 0;
	try
	{
		std::stringstream buffer;
		if (config.parameters.isTimeout())
		{
			std::packaged_task<
					int(retdec::config::Config&,
					ProgramOptions&)> task(decompile);
			auto future = task.get_future();
			std::thread thr(std::move(task), std::ref(config), std::ref(po));
			auto timeout = std::chrono::seconds(config.parameters.getTimeout());
			if (future.wait_for(timeout) != std::future_status::timeout)
			{
				thr.join();
				ret = future.get(); // this will propagate exception
			}
			else
			{
				thr.detach(); // we leave the thread still running
				Log::error() << "timeout after: " << config.parameters.getTimeout()
						<< " seconds" << std::endl;
				ret = EXIT_TIMEOUT;
			}
		}
		else
		{
			ret = decompile(config, po);
		}
	}
	catch (const std::runtime_error& e)
	{
		Log::error() << Log::Error << e.what() << std::endl;
		ret = EXIT_FAILURE;
	}
	catch (const std::bad_alloc& e)
	{
		Log::error() << "catched std::bad_alloc" << std::endl;
		ret = EXIT_BAD_ALLOC;
	}

	cleanup(po);

	return ret;
}
