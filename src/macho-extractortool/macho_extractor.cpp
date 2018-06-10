/**
 * @file src/macho-extractortool/macho_extractor.cpp
 * @brief This program breaks Mach-O Universal static libraries.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <set>

#include <llvm/Support/FileSystem.h>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/macho-extractor/break_fat.h"

using namespace retdec::macho_extractor;
using namespace rapidjson;

namespace {

enum class Mode { All, Best, Arch, Family, Index };

void printUsage()
{
	std::cerr <<
	"\nExtract objects from Mach-O Universal Binaries.\n"
	"Usage: retdec-macho-extractor [OPTIONS] FILE\n\n"
	"Extraction options:\n\n"
	"  --all\n"
	"    Extract all objects from binary (default action).\n\n"
	"  -b --best\n"
	"    Extract the best binary for decompilation in the RetDec.\n\n"
	"  -a --arch NAME\n"
	"    Extract the binary with selected LLVM architecture name.\n\n"
	"  -f --family NAME\n"
	"    Extract the binary with selected architecture family.\n\n"
	"  -i --index INDEX\n"
	"    Extract the binary with selected zero-based index.\n\n"
	"  To see list of supported values for family or architecture\n"
	"  options run application in --list or --json mode.\n\n"
	"List options:\n\n"
	"  -l --list\n"
	"    List target architectures and quit.\n\n"
	"  -j --json\n"
	"    List target architectures in JSON format and quit.\n\n"
	"  --objects\n"
	"    Add list of objects to the list of architectures.This option\n"
	"    implies --list option. This option works only with archives.\n\n"
	"  --check-archive\n"
	"    Writes info about the binary being static library or not. Returns\n"
	"    zero if it is an archive, non-zero value otherwise. This option\n"
	"    ignores --json option.\n\n"
	"Output options:\n\n"
	"  -o --out PATH\n"
	"    Output will be written to the PATH.\n\n";
}

/**
 * Fetch parameter value or die with error message.
 * @param argv vector with arguments
 * @param i index of argument
 * @return argument value
 */
std::string getParamOrDie(
		std::vector<std::string> &argv,
		std::size_t &i)
{
	if (argv.size() > i + 1)
	{
		return argv[++i];
	}
	else
	{
		std::cerr << "Error: missing argument value.\n\n";
		printUsage();
		exit(1);
	}
}

/**
 * Print error message
 * @param message error message
 * @param isJson if @c true use JSON format
 */
void printError(
		const std::string &message,
		bool isJson = false)
{
	if(isJson)
	{
		Document outDoc(kObjectType);
		outDoc.AddMember(
				"error",
				Value(message.c_str(), outDoc.GetAllocator()).Move(),
				outDoc.GetAllocator());
		StringBuffer outBuffer;
		PrettyWriter<StringBuffer> outWriter(outBuffer);
		outDoc.Accept(outWriter);
		std::cout << outBuffer.GetString();
	}
	else
	{
		std::cerr << "Error: " << message << ".\n";
	}
}

/**
 * Parse arguments
 * @param args vector with arguments
 * @return program return value
 */
int handleArguments(
		std::vector<std::string> &args)
{
	if(args.size() < 1)
	{
		printUsage();
		std::cerr << "Error: not enough arguments!\n";
		return 1;
	}

	std::string arch;
	std::string family;
	unsigned index = 0;

	std::string inFile;
	std::string outFile;

	Mode mode = Mode::All;
	bool listOnly = false;
	bool jsonOut = false;
	bool addObjects = false;
	bool isArchiveVerif = false;

	std::set<std::string> withArgs =
	{
		"i",    "index",
		"a",    "arch",
		"f",    "family",
		"o",    "out"
	};

	std::vector<std::string> argv;
	for (const auto& a : args)
	{
		bool added = false;
		for (auto& o : withArgs)
		{
			std::string start = (o.size() == 1 ? "-" : "--") + o + "=";
			if (retdec::utils::startsWith(a, start))
			{
				argv.push_back(a.substr(0, start.size()-1));
				argv.push_back(a.substr(start.size()));
				added = true;
				break;
			}
		}
		if (added)
		{
			continue;
		}

		argv.push_back(a);
	}

	for(std::size_t i = 0; i < argv.size(); ++i)
	{
		std::string& c = argv[i];

		if(c == "-h" || c == "--help")
		{
			printUsage();
			return 0;
		}
		else if(c == "--check-archive")
		{
			isArchiveVerif = true;
		}
		else if(c == "-o" || c == "--out")
		{
			outFile = getParamOrDie(argv, i);
		}
		else if(c == "-l" || c == "--list")
		{
			listOnly = true;
		}
		else if(c == "-j" || c == "--json")
		{
			listOnly = jsonOut = true;
		}
		else if(c == "--objects")
		{
			listOnly = addObjects = true;
		}
		else if(c == "--all")
		{
			mode = Mode::All;
		}
		else if(c == "-b" || c == "--best")
		{
			mode = Mode::Best;
		}
		else if(c == "-i" || c == "--index")
		{
			mode = Mode::Index;
			const auto arg = getParamOrDie(argv, i);
			if(!retdec::utils::strToNum(arg, index))
			{
				printError("invalid '--index' option value!", jsonOut);
				return 1;
			}
		}
		else if(c == "-a" || c == "--arch")
		{
			mode = Mode::Arch;
			arch = getParamOrDie(argv, i);
		}
		else if(c == "-f" || c == "--family")
		{
			mode = Mode::Family;
			family = getParamOrDie(argv, i);
		}
		else
		{
			if(llvm::sys::fs::is_regular_file(llvm::Twine(c)))
			{
				inFile = c;
			}
			else
			{
				printError("invalid argument '" + args[i] + "'", jsonOut);
				return 1;
			}
		}
	}

	// Load input file
	if(inFile.empty())
	{
		printError("no input file", jsonOut);
		return 2;
	}
	BreakMachOUniversal binary(inFile);
	if(!binary.isValid())
	{
		printError("file is not valid Mach-O Universal binary", jsonOut);
		return 2;
	}

	// Check only for static archives
	if(isArchiveVerif)
	{
		if(binary.isStaticLibrary())
		{
			std::cout << "Input file is a static library.\n";
			return 0;
		}

		std::cout << "Input file is NOT a static library.\n";
		return 3;
	}

	// List mode
	if(listOnly)
	{
		if(jsonOut)
		{
			return binary.listArchitecturesJson(std::cout, addObjects) ? 0 : 1;
		}
		else
		{
			return binary.listArchitectures(std::cout, addObjects) ? 0 : 1;
		}
	}

	// Set default name if no name was given
	if(outFile.empty())
	{
		outFile = inFile + ".extracted";
		outFile += binary.isStaticLibrary() ? ".a" : "";
	}

	// Extract
	switch(mode)
	{
		case Mode::All:
			return binary.extractAllArchives() ? 0 : 1;
		case Mode::Best:
			return binary.extractBestArchive(outFile) ? 0 : 1;
		case Mode::Family:
			return binary.extractArchiveForFamily(family, outFile) ? 0 : 1;
		case Mode::Arch:
			return binary.extractArchiveForArchitecture(arch, outFile) ? 0 : 1;
		case Mode::Index:
			return binary.extractArchiveWithIndex(index, outFile) ? 0 : 1;
		default:
			return 1;
	}
}

} // anonymous namespace

int main(int argc, char **argv)
{
	std::vector<std::string> arguments(argv + 1, argv + argc);
	return handleArguments(arguments);
}
