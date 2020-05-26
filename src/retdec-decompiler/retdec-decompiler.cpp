/**
 * @file src/retdec-decompiler/retdec-decompiler.cpp
 * @brief RetDec decompiler.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

/**
 * TODO: paths are checked that they exists and converted to absolute paths.
 * TODO: format == ihex: -a -e must be specified
 *       set bitsize = 32, fileclass = 32
 * TODO: resulting file stripepd = trailing whitespace, redundant empty new lines
 * TODO: mode = raw: -a -e must be specified
 *       set bitsize = 32, fileclass = 32
 * TODO: Options --ar-name and --ar-index are mutually exclusive. Pick one
 */

#include <iostream>
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
#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/string.h"
#include "retdec/utils/memory.h"

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

class ProgramOptions
{
public:
	std::string programName;
	retdec::config::Config& config;
	retdec::config::Parameters& params;
	std::list<std::string> _argv;

	std::string mode = "bin";
	std::string arExtractPath;
	std::string arName;
	std::optional<uint64_t> arIdx;

public:
	ProgramOptions(
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

	void load()
	{
		for (auto i = _argv.begin(); i != _argv.end();)
		{
			if (isParam(i, "", "--config"))
			{
				auto backup = config.parameters;

				try
				{
					config = retdec::config::Config::fromFile(getParamOrDie(i));
				}
				catch (const retdec::config::ParseException& e)
				{
					throw std::runtime_error(
						"loading of config failed: " + std::string(e.what())
					);
				}

				config.parameters = backup;
			}
			++i;
		}

		for (auto i = _argv.begin(); i != _argv.end();)
		{
			std::string c = *i;

			if (isParam(i, "-h", "--help"))
			{
				printHelpAndDie();
			}
			else if (isParam(i, "", "-print-after-all"))
			{
				llvm::StringMap<llvm::cl::Option*> &opts = llvm::cl::getRegisteredOptions();

				// opts["print-after-all"]->printOptionInfo(80);
				// opts["print-after-all"]->printOptionValue(80, true);

				auto* paa = static_cast<llvm::cl::opt<bool>*>(opts["print-after-all"]);
				paa->setInitialValue(true);

				// opts["print-after-all"]->printOptionValue(80, true);
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
				if (m == "raw")
				{
					// TODO
					// In py there was always 32 for raw.
					// we should demand other argument, e.g. --bit-size
					config.fileFormat.setIsRaw32();
					config.architecture.setBitSize(32);
					params.setIsKeepAllFunctions(true);
				}

				mode = m;
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
				params.setMaxMemoryLimit(std::stoull(
					getParamOrDie(i)
				));
				params.setIsMaxMemoryLimitHalfRam(false);
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
				config.parameters.setInputPdbFile(getParamOrDie(i));
			}
			else if (isParam(i, "", "--select-ranges"))
			{
				std::stringstream ranges(getParamOrDie(i));
				while(ranges.good())
				{
					std::string range;
					getline(ranges, range, ',' );
					auto r = retdec::common::stringToAddrRange(range);
					if (r.getStart().isDefined() && r.getEnd().isDefined())
					{
						params.selectedRanges.insert(r);
						params.setIsKeepAllFunctions(true);
					}
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
				retdec::common::Address addr(getParamOrDie(i));
				params.setSectionVMA(addr);
				// TODO: must be used in RAW mode
			}
			else if (isParam(i, "", "--raw-entry-point"))
			{
				retdec::common::Address addr(getParamOrDie(i));
				params.setEntryPoint(addr);
				// TODO: rename to simply entry point
				// TODO: must be used in RAW mode
			}
			else if (isParam(i, "", "--cleanup"))
			{
				// TODO: remove unpacked, archive results, macho results, etc.
			}
			else if (isParam(i, "", "--config"))
			{
				getParamOrDie(i);
				// ignore
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
			else if (isParam(i, "", "--backend-aggressive-opts"))
			{
				params.setIsBackendAggressiveOpts(true);
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
				auto a = getParamOrDie(i);
				try
				{
					arIdx = std::stoull(a);
				}
				catch (...)
				{
					std::cerr << "Invalid --ar-index argument: " << a << std::endl;
					exit(EXIT_FAILURE);
				}
			}
			else if (isParam(i, "", "--ar-name"))
			{
				arName = getParamOrDie(i);
			}
			else if (isParam(i, "", "--static-code-sigfile"))
			{
				params.userStaticSignaturePaths.insert(getParamOrDie(i));
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
					std::cerr << "Invalid --timeout argument: " << t << std::endl;
					exit(EXIT_FAILURE);
				}
			}
			// Input file is the only argument that does not have -x or --xyz
			// before it. But only one input is expected.
			else if (params.getInputFile().empty())
			{
				params.setInputFile(c);
			}
			else
			{
std::cout << "=============> unrecognized option: " << c << std::endl;
				printHelpAndDie();
			}

			if (i != _argv.end())
			{
				++i;
			}
		}
	}

	void check()
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
			if (params.getOutputFormat() == "plain")
				params.setOutputFile(in + ".c");
			else
				params.setOutputFile(in + ".c.json");
		if (params.getOutputUnpackedFile().empty())
			params.setOutputUnpackedFile(in + "-unpacked");
		if (arExtractPath.empty())
			arExtractPath = in + "-extracted";
	}

	void dump()
	{
		std::cout << std::endl;
		std::cout << "Program Options:" << std::endl;
		std::cout << "\t" << "program name : " << programName << std::endl;
		std::cout << "\t" << "input file   : " << params.getInputFile() << std::endl;
		std::cout << std::endl;
	}

	void printHelpAndDie()
	{
		std::cout << programName << R"(:
	[-h|--help] Print this help.
	[-o|--output FILE] Output file (default: INPUT_FILE.c if OUTPUT_FORMAT is plain, INPUT_FILE.c.json if OUTPUT_FORMAT is json|json-human).
	[-f|--output-format OUTPUT_FORMAT] Output format [plain|json|json-human] (default: plain).
	[-m|--mode MODE] Force the type of decompilation mode [bin|raw] (default: bin).
	[-a|--arch ARCH] Specify target architecture [mips|pic32|arm|thumb|arm64|powerpc|x86|x86-64].
	                 Required if it cannot be autodetected from the input (e.g. raw mode, Intel HEX).
	[-e|--endian ENDIAN] Specify target endianness [little|big].
	                     Required if it cannot be autodetected from the input (e.g. raw mode, Intel HEX).
	[-p|--pdb FILE] File with PDB debug information.
	[-k|--keep-unreachable-funcs] Keep functions that are unreachable from the main function.
	[--select-ranges RANGES] Specify a comma separated list of ranges to decompile (example: 0x100-0x200,0x300-0x400,0x500-0x600).
	[--select-functions FUNCS] Specify a comma separated list of functions to decompile (example: fnc1,fnc2,fnc3).
	[--select-decode-only] Decode only selected parts (functions/ranges). Faster decompilation, but worse results.

	[--raw-section-vma ADDRESS] Virtual address where section created from the raw binary will be placed.
	[--raw-entry-point ADDRESS] Entry point address used for raw binary (default: architecture dependent).

	[--cleanup] Removes temporary files created during the decompilation.
	[--config] Specify JSON decompilation configuration file.

	[--ar-index INDEX] Pick file from archive for decompilation by its zero-based index.
	[--ar-name NAME] Pick file from archive for decompilation by its name.
	[--static-code-sigfile FILE] Adds additional signature file for static code detection.

	[--disable-static-code-detection] Prevents detection of statically linked code.
	[--backend-disabled-opts LIST] Prevents the optimizations from the given comma-separated list of optimizations to be run.
	[--backend-enabled-opts LIST] Runs only the optimizations from the given comma-separated list of optimizations.
	[--backend-call-info-obtainer NAME] Name of the obtainer of information about function calls [optim|pessim] (Default: optim).
	[--backend-var-renamer STYLE] Used renamer of variables [address|hungarian|readable|simple|unified] (Default: readable).
	[--backend-no-opts] Disables backend optimizations.
	[--backend-emit-cfg] Emits a CFG for each function in the backend IR (in the .dot format).
	[--backend-emit-cg] Emits a CG for the decompiled module in the backend IR (in the .dot format).
	[--backend-aggressive-opts] Enables aggressive optimizations.
	[--backend-keep-all-brackets] Keeps all brackets in the generated code.
	[--backend-keep-library-funcs] Keep functions from standard libraries.
	[--backend-no-time-varying-info] Do not emit time-varying information, like dates.
	[--backend-no-var-renaming] Disables renaming of variables in the backend.
	[--backend-no-compound-operators] Do not emit compound operators (like +=) instead of assignments.
	[--backend-no-symbolic-names] Disables the conversion of constant arguments to their symbolic names.

	[--timeout SECONDS]
	[--max-memory MAX_MEMORY] Limits the maximal memory used by the given number of bytes.
	[--no-memory-limit] Disables the default memory limit (half of system RAM).

	INPUT_FILE File to decompile.
)";

		exit(EXIT_SUCCESS);
	}

private:
	bool isParam(
			std::list<std::string>::iterator i,
			const std::string& shortp,
			const std::string& longp = std::string())
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

	std::string getParamOrDie(std::list<std::string>::iterator& i)
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
};

int decompile(retdec::config::Config& config, ProgramOptions& po)
{
	// llvm::sys::PrintStackTraceOnErrorSignal(argv[0]);
	// llvm::PrettyStackTraceProgram X(argc, argv);
	// llvm::llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.
	// llvm::EnableDebugBuffering = true;

// macho extract
// =============================================================================

retdec::macho_extractor::BreakMachOUniversal fat(config.parameters.getInputFile());
if (fat.isValid())
{
	if (config.architecture.isKnown())
	{
		if (!fat.extractArchiveForFamily(
				config.architecture.getName(),
				po.arExtractPath + "_m"))
		{
			std::cerr << "Invalid --arch option '"
					<< config.architecture.getName()
					<< "'. File contains these architecture families:"
					<< std::endl;
			fat.listArchitectures(std::cerr);
			return EXIT_FAILURE;
		}
	}
	else
	{
		if (!fat.extractBestArchive(po.arExtractPath + "_m"))
		{
			// TODO
			return EXIT_FAILURE;
		}
	}

	config.parameters.setInputFile(po.arExtractPath + "_m");
}

// ar extract
// =============================================================================

if (po.arIdx || !po.arName.empty())
// if (!fat.isValid() && po.arIdx || !po.arName.empty())
{
	bool ok = true;
	std::string errMsg;
	retdec::ar_extractor::ArchiveWrapper arw(
			config.parameters.getInputFile(),
			ok,
			errMsg
	);

	if (!ok)
	{
		throw std::runtime_error("failed to create archive wrapper: " + errMsg);
	}

	if (po.arIdx)
	{
		if (!arw.extractByIndex(po.arIdx.value(), errMsg, po.arExtractPath))
		{
			std::cerr << errMsg << std::endl;
			std::cerr << "Error: File on index '"
					<< po.arIdx.value()
					<< "' was not found in the input archive."
					<< " Valid indexes are 0-" << arw.getNumberOfObjects()-1 << "."
					<< std::endl;
			throw std::runtime_error("failed to extract archive: " + errMsg);
		}
	}
	else if (!po.arName.empty())
	{
		if (!arw.extractByName(po.arName, errMsg, po.arExtractPath))
		{
			std::cerr << "Error: File named '" << po.arName
					<< "' was not found in the input archive."
					<< std::endl;
			throw std::runtime_error("failed to extract archive: " + errMsg);
		}
	}

	config.parameters.setInputFile(po.arExtractPath);
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
		std::cerr << "This file is an archive!" << std::endl;
		std::cerr << "Error: File is a thin archive and cannot be decompiled." << std::endl;
		return EXIT_FAILURE;
	}
	else if (ok && arw.isEmptyArchive())
	{
		std::cerr << "This file is an archive!" << std::endl;
		std::cerr << "Error: The input archive is empty." << std::endl;
		return EXIT_FAILURE;
	}
	else if (ok)
	{
		std::cerr << "This file is an archive!" << std::endl;

		std::string result;
		if (arw.getPlainTextList(result, errMsg, false, true))
		{
			std::cerr << result << std::endl;
		}
		return EXIT_FAILURE;
	}

	if (!ok && retdec::ar_extractor::isArchive(config.parameters.getInputFile()))
	{
		std::cerr << "This file is an archive!" << std::endl;
		std::cerr << "Error: The input archive has invalid format." << std::endl;
		return EXIT_FAILURE;
	}
}

// unpack
// =============================================================================

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
	config.parameters.setInputFile(config.parameters.getOutputUnpackedFile());
}

// decompiler
// =============================================================================

	try
	{
		if (retdec::decompile(config))
		{
			std::cout << "decompilation FAILED" << std::endl;
		}
		else
		{
			std::cout << "decompilation OK" << std::endl;
		}
	}
	catch (const std::runtime_error& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	return 0;
}

int main(int argc, char **argv)
{
	retdec::config::Config config;

	auto binpath = retdec::utils::getThisBinaryDirectoryPath();
	retdec::utils::FilesystemPath configPath(binpath.getParentPath());
	configPath.append("share");
	configPath.append("retdec");
	configPath.append("decompiler-config.json");
	if (configPath.exists())
	{
		config = retdec::config::Config::fromFile(configPath.getPath());
		config.parameters.fixRelativePaths(configPath.getParentPath());
		config.parameters.setOutputConfigFile("");
	}

	ProgramOptions po(argc, argv, config, config.parameters);
	try
	{
		po.load();
		po.check();
	}
	catch (const std::runtime_error& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	po.dump();
	if (config.parameters.getInputFile().empty())
	{
		po.printHelpAndDie();
	}

	limitMaximalMemoryIfRequested(config.parameters);

// decompile
// =============================================================================

// TODO: error messages.
// TODO: cleanup on error

int ret = 0;
try
{
	std::stringstream buffer;
	if (config.parameters.isTimeout())
	{
		std::packaged_task<int(retdec::config::Config&, ProgramOptions&)> task(decompile);
		auto future = task.get_future();
		std::thread thr(std::move(task), std::ref(config), std::ref(po));
		auto timeout = std::chrono::seconds(config.parameters.getTimeout());
		if (future.wait_for(timeout) != std::future_status::timeout)
		{
			thr.join();
			ret = future.get(); // this will propagate exception from f() if any
		}
		else
		{
			thr.detach(); // we leave the thread still running
			std::cerr << "timeout after: " << config.parameters.getTimeout()
					<< " seconds" << std::endl;
			exit(137);
		}
	}
	else
	{
		ret = decompile(config, po);
	}
}
catch (const std::bad_alloc& e)
{
	exit(135);
}

	return ret;
}
