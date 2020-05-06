/**
 * @file src/retdec-decompiler/retdec-decompiler.cpp
 * @brief RetDec decompiler.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <iostream>

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

#include "retdec/config/config.h"
#include "retdec/retdec/retdec.h"
#include "retdec/utils/binary_path.h"
#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/string.h"

class ProgramOptions
{
public:
	std::string programName;
	retdec::config::Config& config;
	retdec::config::Parameters& params;
	std::list<std::string> _argv;

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

		// for (int i = 1; i < argc; ++i)
		for (auto i = _argv.begin(); i != _argv.end();)
		{
			// std::string c = argv[i];
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
				if (!(m == "bin" || m == "raw" || m == "ll"))
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
				}
			}
			else if (isParam(i, "-a", "--arch"))
			{
				auto a = getParamOrDie(i);
				if (!(a == "mips" || a == "pic32" || a == "arm" || a == "thumb"
						|| a == "arm64" || a == "powerpc" || a == "x86"
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
			else if (isParam(i, "", "--max-memory"))
			{
				params.setMaxMemoryLimit(std::stoull(
					getParamOrDie(i)
				));
				params.setMaxMemoryLimitHalfRam(false);
			}
			else if (isParam(i, "", "--no-memory-limit"))
			{
				params.setMaxMemoryLimit(0);
				params.setMaxMemoryLimitHalfRam(false);
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
			}
			else if (isParam(i, "-k", "--keep-unreachable-funcs"))
			{
				params.setIsKeepAllFunctions(true);
			}
			else if (isParam(i, "-p", "--pdb"))
			{
				config.setPdbInputFile(getParamOrDie(i));
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
				config.setSectionVMA(addr);
			}
			else if (isParam(i, "", "--raw-entry-point"))
			{
				retdec::common::Address addr(getParamOrDie(i));
				config.setEntryPoint(addr);
			}
			else if (isParam(i, "", "--backend-disabled-opts"))
			{
				params.backendDisabledOpts = getParamOrDie(i);
			}
			else if (isParam(i, "", "--static-code-archive"))
			{
				// TODO
			}
			else if (isParam(i, "", "--cleanup"))
			{
				// TODO
			}
			// Input file is the only argument that does not have -x or --xyz
			// before it. But only one input is expected.
			else if (params.getInputFile().empty())
			{
				auto& out = c;
				config.setInputFile(out);
				params.setInputFile(out);
				if (params.getOutputAsmFile().empty())
					params.setOutputAsmFile(out + ".dsm");
				if (params.getOutputBitcodeFile().empty())
					params.setOutputBitcodeFile(out + ".bc");
				if (params.getOutputLlvmirFile().empty())
					params.setOutputLlvmirFile(out + ".ll");
				if (params.getOutputConfigFile().empty())
					params.setOutputConfigFile(out + ".config.json");
				if (params.getOutputFile().empty())
					params.setOutputFile(out + ".c");
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
	[-h|--help]
	[-o|--output] Output file.
	[-m|--mode MODE] Force the type of decompilation mode [bin|ll|raw] (default: bin otherwise).
	[-a|--arch ARCH] Specify target architecture [mips|pic32|arm|thumb|arm64|powerpc|x86|x86-64].
	                 Required if it cannot be autodetected from the input (e.g. raw mode, Intel HEX).
	[-e||--endian ENDIAN] Specify target endianness [little|big].
	                      Required if it cannot be autodetected from the input (e.g. raw mode, Intel HEX).
	[-p|--pdb FILE] File with PDB debug information.
	[-k|--keep-unreachable-funcs] Keep functions that are unreachable from the main function.
	[--select-ranges RANGES] Specify a comma separated list of ranges to decompile (example: 0x100-0x200,0x300-0x400,0x500-0x600).
	[--select-functions FUNCS] Specify a comma separated list of functions to decompile (example: fnc1,fnc2,fnc3).
	[--select-decode-only] Decode only selected parts (functions/ranges). Faster decompilation, but worse results.
	[--raw-section-vma]
	[--raw-entry-point]
	[--backend-disabled-opts]
	[--static-code-archive]
	[--cleanup]
	[--max-memory MAX_MEMORY] Limits the maximal memory used by the given number of bytes.
	[--no-memory-limit] Disables the default memory limit (half of system RAM)
	FILE
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
	}

	llvm::sys::PrintStackTraceOnErrorSignal(argv[0]);
	llvm::PrettyStackTraceProgram X(argc, argv);
	llvm::llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.
	llvm::EnableDebugBuffering = true;

	ProgramOptions po(argc, argv, config, config.parameters);
	po.dump();
	if (config.parameters.getInputFile().empty())
	{
		po.printHelpAndDie();
	}

	if (retdec::decompile(config))
	{
		std::cout << "decompilation FAILED" << std::endl;
	}
	else
	{
		std::cout << "decompilation OK" << std::endl;
	}

	return 0;
}
