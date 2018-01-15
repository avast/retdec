/**
 * @file src/configtool/configtool.cpp
 * @brief Configuration Tool.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstring>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

#include "retdec/config/config.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/string.h"

enum errcode_t
{
	ERROR_OK = 0,
	ERROR_IN_FILE,
	ERROR_PARAMETER,
	ERROR_UNKNOWN
};

const std::string TYPES_SUFFIX     = ".json";
const std::string ABI_SUFFIX       = ".json";
const std::set<std::string> SIGNATURE_SUFFIXES = {".yar", ".yara"};

bool hasEnding(const std::string &str, const std::set<std::string> &suffixes)
{
	return std::any_of(suffixes.begin(), suffixes.end(),
		[&] (const auto &suffix) { return retdec::utils::endsWith(str, suffix); });
}

void printHelp()
{
	std::cout << "retdec-configtool <config_file> --read  [R_OPTION...]  prints comma-separated list of values for options" << std::endl;
	std::cout << "retdec-configtool <config_file> --write [W_OPTION...]  sets options to proviede values" << std::endl;
	std::cout << "retdec-configtool <config_file> --preprocess           allows only whitelisted values to remain in the config file" << std::endl;
	std::cout << std::endl;
	std::cout << "R_OPTION:" << std::endl;
	std::cout << "\t--compiler" << std::endl;
	std::cout << "\t--arch" << std::endl;
	std::cout << "\t--endian" << std::endl;
	std::cout << "\t--format" << std::endl;
	std::cout << "\t--bit-size" << std::endl;
	std::cout << "\t--file-class" << std::endl;
	std::cout << "\t--bytecode" << std::endl;
	std::cout << "\t--input-file" << std::endl;
	std::cout << "\t--unpacked-input-file" << std::endl;
	std::cout << std::endl;
	std::cout << "W_OPTION:" << std::endl;
	std::cout << "\t--compiler name" << std::endl;
	std::cout << "\t--arch name" << std::endl;
	std::cout << "\t--endian {little,big,unknown}" << std::endl;
	std::cout << "\t--format name" << std::endl;
	std::cout << "\t--bit-size" << std::endl;
	std::cout << "\t--entry-point" << std::endl;
	std::cout << "\t--section-vma" << std::endl;
	std::cout << "\t--file-class" << std::endl;
	std::cout << "\t--keep-unreachable-funcs true/false" << std::endl;
	std::cout << "\t--signatures path" << std::endl;
	std::cout << "\t--user-signature path" << std::endl;
	std::cout << "\t--types path" << std::endl;
	std::cout << "\t--abis path" << std::endl;
	std::cout << "\t--ords path" << std::endl;
	std::cout << "\t--pdb-file path" << std::endl;
	std::cout << "\t--input-file path" << std::endl;
	std::cout << "\t--unpacked-in-file path" << std::endl;
	std::cout << "\t--output-file path" << std::endl;
	std::cout << "\t--frontend-output-file path" << std::endl;
	std::cout << "\t--decode-only-selected true/false" << std::endl;
	std::cout << "\t--selected-func name" << std::endl;
	std::cout << "\t--selected-range range" << std::endl;
	std::cout << "\t--set-fnc-fixed fncName" << std::endl;
	std::cout << std::endl;
}

void getDirFiles(const std::string &dirPath, std::vector<std::string> &ret, const std::set<std::string> &suffixes)
{
	retdec::utils::FilesystemPath fsp(dirPath);
	if (!fsp.isDirectory())
	{
		return;
	}

	for (auto f : fsp)
	{
		if (f->isDirectory())
		{
			getDirFiles(f->getPath(), ret, suffixes);
		}
		else if (f->isFile()
				&& hasEnding(f->getPath(), suffixes))
		{
			auto p = fsp.separator() == '\\'
					? retdec::utils::replaceAll(f->getPath(), "\\", "/")
					: f->getPath();
			ret.push_back(p);
		}
	}
}

void getDirFiles(const std::string &dirPath, std::vector<std::string> &ret, const std::string &suffix = "")
{
	std::set<std::string> suffixSet;
	suffixSet.insert(suffix);
	getDirFiles(dirPath, ret, suffixSet);
}

int handleArguments(std::vector<std::string> &args)
{
	if (args.size() == 1 && ( args[0] == "-h" || args[0] == "--help"))
	{
		printHelp();
		return ERROR_OK;
	}
	else if (args.size() < 2)
	{
		printHelp();
		return ERROR_PARAMETER;
	}

	std::string configName = args[0];
	retdec::config::Config config;

	try
	{
		config.readJsonFile(configName);
	}
	catch (const retdec::config::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		return ERROR_IN_FILE;
	}

	if (args[1] == "--read")
	{
		bool first = true;
		for (size_t i = 2; i<args.size(); ++i)
		{
			std::string opt = args[i];

			if (first)
			{
				first = false;
			}
			else
			{
				std::cout << ",";
			}

			if (opt == "--compiler")
			{
				if (!config.tools.empty())
				{
					std::cout << config.tools.getToolMostSignificant()->getName();
				}
			}
			else if (opt == "--arch")
			{
				std::cout << config.architecture.getName() << std::endl;
			}
			else if (opt == "--endian")
			{
				if (config.architecture.isEndianLittle())
				{
					std::cout << "little" << std::endl;
				}
				else if (config.architecture.isEndianBig())
				{
					std::cout << "big" << std::endl;
				}
				else
				{
					std::cout << "unknown" << std::endl;
				}
			}
			else if (opt == "--format")
			{
				std::cout << config.fileFormat.getName() << std::endl;
			}
			else if (opt == "--bit-size")
			{
				std::cout << config.architecture.getBitSize() << std::endl;
			}
			else if (opt == "--file-class")
			{
				std::cout << config.fileFormat.getFileClassBits() << std::endl;
			}
			else if (opt == "--bytecode")
			{
				const auto *lang = config.languages.getFirstBytecode();
				if (lang && !lang->getName().empty())
				{
					std::cout << lang->getName() << std::endl;
				}
			}
			else if (opt == "--input-file")
			{
				std::cout << config.getInputFile() << std::endl;
			}
			else if (opt == "--unpacked-input-file")
			{
				std::cout << config.getUnpackedInputFile() << std::endl;
			}
			else
			{
				printHelp();
				return ERROR_PARAMETER;
			}
		}
	}
	else if (args[1] == "--write")
	{
		for (size_t i = 2; i<args.size()-1; i+=2)
		{
			std::string opt = args[i];
			std::string val = args[i+1];

			if (opt == "--compiler")
			{
				retdec::config::ToolInfo ci;
				ci.setName(val);
				ci.setPercentage(101);

				if (config.tools.empty())
				{
					config.tools.insert(ci);
				}
				else
				{
					config.tools.insert(ci);
				}
			}
			else if (opt == "--arch")
			{
				config.architecture.setName(val);
			}
			else if (opt == "--endian")
			{
				if (val == "little") config.architecture.setIsEndianLittle();
				else if (val == "big") config.architecture.setIsEndianBig();
				else if (val == "unknown") config.architecture.setIsEndianUnknown();
			}
			else if (opt == "--format")
			{
				config.fileFormat.setName(val);
			}
			else if (opt == "--file-class")
			{
				unsigned n = 0;
				if (retdec::utils::strToNum(val, n))
				{
					config.fileFormat.setFileClassBits(n);
				}
			}
			else if (opt == "--bit-size")
			{
				unsigned n = 0;
				if (retdec::utils::strToNum(val, n))
				{
					config.architecture.setBitSize(n);
				}
			}
			else if (opt == "--entry-point")
			{
				unsigned long long n = 0;
				if (retdec::utils::strToNum(val, n, std::hex))
				{
					config.setEntryPoint(n);
				}
			}
			else if (opt == "--section-vma")
			{
				unsigned long long n = 0;
				if (retdec::utils::strToNum(val, n, std::hex))
				{
					config.setSectionVMA(n);
				}
			}
			else if (opt == "--keep-unreachable-funcs")
			{
				config.parameters.setIsKeepAllFunctions( (val == "true") ? (true) : (false) );
			}
			else if (opt == "--signatures")
			{
				std::vector<std::string> files;
				getDirFiles(val, files, SIGNATURE_SUFFIXES);

				for (auto &f : files)
				{
					config.parameters.staticSignaturePaths.insert(f);
				}
			}
			else if (opt == "--user-signature")
			{
				config.parameters.userStaticSignaturePaths.insert(val);
			}
			else if (opt == "--types")
			{
				std::vector<std::string> files;
				getDirFiles(val, files, TYPES_SUFFIX);

				for (auto &f : files)
				{
					config.parameters.libraryTypeInfoPaths.insert(f);
				}
			}
			else if (opt == "--abis")
			{
				std::vector<std::string> files;
				getDirFiles(val, files, ABI_SUFFIX);

				for (auto &f : files)
				{
					config.parameters.abiPaths.insert(f);
				}
			}
			else if (opt == "--ords")
			{
				config.parameters.setOrdinalNumbersDirectory(val);
			}
			else if (opt == "--pdb-file")
			{
				config.setPdbInputFile(val);
			}
			else if (opt == "--input-file")
			{
				config.setInputFile(val);
			}
			else if (opt == "--unpacked-in-file")
			{
				config.setUnpackedInputFile(val);
			}
			else if (opt == "--output-file")
			{
				config.parameters.setOutputFile(val);
			}
			else if (opt == "--frontend-output-file")
			{
				config.parameters.setFrontendOutputFile(val);
			}
			else if (opt == "--decode-only-selected")
			{
				config.parameters.setIsSelectedDecodeOnly( (val == "true") ? (true) : (false) );
			}
			else if (opt == "--selected-func")
			{
				config.parameters.selectedFunctions.insert(val);
			}
			else if (opt == "--selected-range")
			{
				config.parameters.selectedRanges.insert( retdec::config::AddressRangeJson(val) );
			}
			else if (opt == "--set-fnc-fixed")
			{
				auto f = config.functions.getFunctionByName(val);
				if (f)
				{
					f->setIsFixed(true);
				}
			}
			else
			{
				printHelp();
				return ERROR_PARAMETER;
			}
		}
	}
	else if (args[1] == "--preprocess")
	{
		retdec::config::Config newConfig;

		newConfig.setEntryPoint(config.getEntryPoint());
		newConfig.setImageBase(config.getImageBase());
		newConfig.setIsIda(config.isIda());

		newConfig.functions = config.functions;
		newConfig.globals = config.globals;
		newConfig.registers = config.registers;
		newConfig.structures = config.structures;
		newConfig.segments = config.segments;
		newConfig.vtables = config.vtables;
		newConfig.classes = config.classes;

		newConfig.generateJsonFile(configName);
		return ERROR_OK;
	}
	else
	{
		printHelp();
		return ERROR_PARAMETER;
	}

	config.generateJsonFile(configName);
	return ERROR_OK;
}

int main(int argc, char* argv[])
{
	std::vector<std::string> arguments(argv + 1, argv + argc);
	return handleArguments(arguments);
}
