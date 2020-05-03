/**
 * @file src/retdec-decompiler/retdec-decompiler.cpp
 * @brief RetDec decompiler.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

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

#include "retdec/config/parameters.h"
#include "retdec/retdec/retdec.h"

class ProgramOptions
{
public:
	std::string programName;
	retdec::config::Parameters params;

public:
	ProgramOptions(int argc, char *argv[])
	{
		if (argc > 0)
		{
			programName = argv[0];
		}

		for (int i = 1; i < argc; ++i)
		{
			std::string c = argv[i];

			if (c == "-h" || c == "--help")
			{
				printHelpAndDie();
			}
			else if (c == "--max-memory")
			{
				params.setMaxMemoryLimit(std::stoull(
					getParamOrDie(argc, argv, i)
				));
				params.setMaxMemoryLimitHalfRam(false);
			}
			else if (c == "--no-memory-limit")
			{
				params.setMaxMemoryLimit(0);
				params.setMaxMemoryLimitHalfRam(false);
			}
			else if (c == "-o")
			{
				std::string out = getParamOrDie(argc, argv, i);
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
			// Input file is the only argument that does not have -x or --xyz
			// before it. But only one input is expected.
			else if (params.getInputFile().empty())
			{
				auto& out = c;
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
				printHelpAndDie();
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
private:
	std::string getParamOrDie(int argc, char *argv[], int& i)
	{
		if (argc > i+1)
		{
			return argv[++i];
		}
		else
		{
			printHelpAndDie();
			return std::string();
		}
	}

	void printHelpAndDie()
	{
		std::cout << programName << ":\n"
				<< "[-h|--help]\n"
				<< "[--max-memory] Limits the maximal memory used by the given number of bytes.\n"
				<< "[--no-memory-limit] Disables the default memory limit (half of system RAM)\n"
				<< "\tinputFile\n";

		exit(EXIT_SUCCESS);
	}
};

int main(int argc, char **argv)
{
	llvm::sys::PrintStackTraceOnErrorSignal(argv[0]);
	llvm::PrettyStackTraceProgram X(argc, argv);
	llvm::llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.
	llvm::EnableDebugBuffering = true;

	ProgramOptions po(argc, argv);
	po.dump();

	if (retdec::decompile(po.params))
	{
		std::cout << "decompilation FAILED" << std::endl;
	}
	else
	{
		std::cout << "decompilation OK" << std::endl;
	}

	return 0;
}
