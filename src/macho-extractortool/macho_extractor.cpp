/**
 * @file src/macho-extractortool/macho_extractor.cpp
 * @brief This program breaks Mach-O Universal static libraries.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/Support/FileSystem.h>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#include "retdec/utils/conversion.h"
#include "retdec/macho-extractor/break_fat.h"

using namespace retdec::macho_extractor;
using namespace rapidjson;

namespace {

enum class Mode { All, Best, Arch, Family, Index };

void printHelp()
{
	std::cerr << "\nExtract static libraries from Mach-O Universal Binaries\n";
	std::cerr << "extract [OPTIONS] INPUT\n\n";
	std::cerr << "Options:\n";
	std::cerr << "--all\t\tExtract all archives (default)\n";
	std::cerr << "--best\t\tExtract best archive for decompilation\n";
	std::cerr << "--family name\tExtract archive with selected architecture family [arm|x86|powerpc]\n";
	std::cerr << "--arch name\tExtract archive with selected architecture\n";
	std::cerr << "--index number\tExtract archive with selected index\n";
	std::cerr << "--out path\tOutput file\n";
	std::cerr << "--list\t\tList target architectures and quit\n";
	std::cerr << "--json\t\tList target architectures in JSON format and quit\n";
	std::cerr << "--objects\tAdd list of objects to architectures list\n\n";
	std::cerr << "For list of supported values for family or arch run in --list or --json mode.\n";
}

void printError(const std::string &message, bool isJson = false)
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

int handleArguments(std::vector<std::string> &args)
{
	if(args.size() < 1)
	{
		printHelp();
		std::cerr << "Error: not enough arguments!\n";
		return 1;
	}

	std::string archVal;
	std::string familyVal;
	std::string inputFile;
	std::string outputFile;
	unsigned indexVal = 0;
	Mode mode = Mode::All;
	bool listOnly = false;
	bool jsonOut = false;
	bool withObjects = false;

	for(std::size_t i = 0; i < args.size(); ++i)
	{
		if(args[i] == "--help" || args[i] == "-h")
		{
			printHelp();
			return 0;
		}
		if(args[i] == "--out")
		{
			if(i + 1 >= args.size())
			{
				std::cerr << "Error: option '--out' needs value!\n";
				return 1;
			}
			else
			{
				outputFile = args[++i];
			}
		}
		else if(args[i] == "--list")
		{
			listOnly = true;
		}
		else if(args[i] == "--json")
		{
			listOnly = jsonOut = true;
		}
		else if(args[i] == "--objects")
		{
			listOnly = withObjects = true;
		}
		else if(args[i] == "--all")
		{
			mode = Mode::All;
		}
		else if(args[i] == "--best")
		{
			mode = Mode::Best;
		}
		else if(args[i] == "--index")
		{
			mode = Mode::Index;
			if(i + 1 >= args.size())
			{
				std::cerr << "Error: option '--index' needs value!\n";
				return 1;
			}
			else
			{
				if(!retdec::utils::strToNum(args[++i], indexVal, std::dec))
				{
					std::cerr << "Error: option '--index' value is not a number!\n";
					return 1;
				}
			}
		}
		else if(args[i] == "--arch")
		{
			mode = Mode::Arch;
			if(i + 1 >= args.size())
			{
				std::cerr << "Error: option '--arch' needs value!\n";
				return 1;
			}
			else
			{
				archVal = args[++i];
			}
		}
		else if(args[i] == "--family")
		{
			mode = Mode::Family;
			if(i + 1 >= args.size())
			{
				std::cerr << "Error: option '--family' needs value!\n";
				return 1;
			}
			else
			{
				familyVal = args[++i];
			}
		}
		else
		{
			if(llvm::sys::fs::is_regular_file(llvm::Twine(args[i])))
			{
				inputFile = args[i];
			}
			else
			{
				std::cerr << "Error: invalid argument '" << args[i] << "'.\n";
				return 1;
			}
		}
	}

	// Load input file
	if(inputFile.empty())
	{
		printError("no input file", jsonOut);
		return 2;
	}
	BreakMachOUniversal binary(inputFile);
	if(!binary.isValid())
	{
		printError("file is not valid Mach-O Universal static library", jsonOut);
		return 2;
	}

	// List mode
	if(listOnly)
	{
		if(jsonOut)
		{
			return binary.listArchitecturesJson(std::cout, withObjects) ? 0 : 1;
		}
		else
		{
			return binary.listArchitectures(std::cout, withObjects) ? 0 : 1;
		}
	}

	// Set default name if no name was given
	if(outputFile.empty())
	{
		outputFile = inputFile + ".picked.a";
	}

	// Extract
	switch(mode)
	{
		case Mode::All:
			return binary.extractAllArchives() ? 0 : 1;
		case Mode::Best:
			return binary.extractBestArchive(outputFile) ? 0 : 1;
		case Mode::Family:
			return binary.extractArchiveForFamily(familyVal, outputFile) ? 0 : 1;
		case Mode::Arch:
			return binary.extractArchiveForArchitecture(archVal, outputFile) ? 0 : 1;
		case Mode::Index:
			return binary.extractArchiveWithIndex(indexVal, outputFile) ? 0 : 1;
		default:
			return 1;
	}
}

} // namespace Anonymous

int main(int argc, char **argv)
{
	std::vector<std::string> arguments(argv + 1, argv + argc);
	return handleArguments(arguments);
}
