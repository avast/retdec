/**
 * @file src/unpackertool/unpacker.cpp
 * @brief Main function and help.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstddef>
#include <memory>

#include "retdec/utils/conversion.h"
#include "retdec/utils/filesystem.h"
#include "retdec/utils/io/log.h"
#include "retdec/utils/memory.h"
#include "retdec/utils/version.h"
#include "retdec/cpdetect/cpdetect.h"
#include "retdec/fileformat/fileformat.h"
#include "arg_handler.h"
#include "retdec/unpacker/plugin.h"
#include "retdec/unpackertool/unpackertool.h"
#include "plugin_mgr.h"

using namespace retdec::utils;
using namespace retdec::utils::io;
using namespace retdec::unpacker;
using namespace retdec::unpackertool;

namespace retdec {
namespace unpackertool {

/**
 * Possible exit codes of the unpacker as program.
 */
enum ExitCode
{
	EXIT_CODE_OK = 0, ///< Unpacker ended successfully.
	EXIT_CODE_NOTHING_TO_DO, ///< There was not found matching plugin.
	EXIT_CODE_UNPACKING_FAILED, ///< At least one plugin failed at the unpacking of the file.
	EXIT_CODE_PREPROCESSING_ERROR, ///< Error with preprocessing of input file before unpacking.
	EXIT_CODE_MEMORY_LIMIT_ERROR ///< There was an error when setting the memory limit.
};

bool detectPackers(const std::string& inputFile, std::vector<retdec::cpdetect::DetectResult>& detectedPackers)
{
	using namespace retdec::cpdetect;
	using namespace retdec::fileformat;

	DetectParams detectionParams(SearchType::MOST_SIMILAR, true, false);

	ToolInformation toolInfo;
	switch (detectFileFormat(inputFile))
	{
		case Format::UNDETECTABLE:
			Log::error() << "Input file '" << inputFile << "' doesn't exist!" << std::endl;
			return false;
		case Format::UNKNOWN:
			Log::error() << "Input file '" << inputFile << "' is in unknown format!" << std::endl;
			return false;
		default:
		{
			auto fileParser = createFileFormat(inputFile);
			if (!fileParser)
			{
				Log::error() << "Error while detecting format of file '" << inputFile << "'! Please, report this." << std::endl;
				return false;
			}

			auto compilerDetector = std::make_unique<CompilerDetector>(
					*(fileParser.get()),
					detectionParams,
					toolInfo
			);
			if (!compilerDetector)
			{
				Log::error() << "No compiler detector was found! Please, report this." << std::endl;
				return false;
			}

			compilerDetector->getAllInformation();
			break;
		}
	}

	detectedPackers = toolInfo.detectedTools;
	return true;
}

ExitCode unpackFile(const std::string& inputFile, const std::string& outputFile, bool brute, const std::vector<retdec::cpdetect::DetectResult>& detectedPackers)
{
	Plugin::Arguments pluginArgs = { inputFile, outputFile, brute };

	ExitCode ret = EXIT_CODE_NOTHING_TO_DO;
	for (const auto& detectedPacker : detectedPackers)
	{
		PluginList plugins = PluginMgr::matchingPlugins(detectedPacker.name, detectedPacker.versionInfo);

		if (plugins.empty())
		{
			Log::error() << "No matching plugins found for '" << detectedPacker.name;
			if (detectedPacker.versionInfo != WILDCARD_ALL_VERSIONS)
				Log::error() << " " << detectedPacker.versionInfo;
			Log::error() << "'" << std::endl;
			continue;
		}

		for (const auto& plugin : plugins)
		{
			PluginExitCode pluginExitCode = plugin->run(pluginArgs);
			if (pluginExitCode == PLUGIN_EXIT_UNPACKED)
			{
				plugin->log("Successfully unpacked '", inputFile, "'!");
				return EXIT_CODE_OK;
			}
			else if (pluginExitCode == PLUGIN_EXIT_FAILED)
				ret = EXIT_CODE_UNPACKING_FAILED;
		}
	}

	return ret;
}

ExitCode processArgs(ArgHandler& handler, char argc, char** argv)
{
	// In case of failed parsing just print the help
	if (!handler.parse(argc, argv))
	{
		Log::info() << handler << std::endl;
		return EXIT_CODE_OK;
	}

	bool brute = handler["brute"]->used;

	// --max-memory N
	if (handler["max-memory"]->used)
	{
		auto maxMemoryLimitStr = handler["max-memory"]->input;

		std::size_t maxMemoryLimit = 0;
		auto conversionSucceeded = strToNum(maxMemoryLimitStr, maxMemoryLimit);
		if (!conversionSucceeded)
		{
			Log::error() << "Invalid value for --max-memory: '"
				<< maxMemoryLimitStr << "'!\n";
			return EXIT_CODE_MEMORY_LIMIT_ERROR;
		}

		auto limitingSucceeded = limitSystemMemory(maxMemoryLimit);
		if (!limitingSucceeded)
		{
			Log::error() << "Failed to limit memory to "
				<< maxMemoryLimitStr << " bytes!\n";
			return EXIT_CODE_MEMORY_LIMIT_ERROR;
		}
	}
	// --max-memory-half-ram
	else if (handler["max-memory-half-ram"]->used)
	{
		auto limitingSucceeded = limitSystemMemoryToHalfOfTotalSystemMemory();
		if (!limitingSucceeded)
		{
			Log::error() << "Failed to limit memory to half of system RAM!\n";
			return EXIT_CODE_MEMORY_LIMIT_ERROR;
		}
	}

	// -h|--help
	if (handler["help"]->used)
	{
		Log::info() << handler << std::endl;
	}
	// --version
	else if (handler["version"]->used)
	{
		Log::info() << utils::version::getVersionStringLong() << std::endl;
	}
	// -p|--plugins
	else if (handler["plugins"]->used)
	{
		Log::info() << "List of available plugins:" << std::endl;

		for (const auto& plugin : PluginMgr::plugins)
		{
			const Plugin::Info* info = plugin->getInfo();
			Log::info() << info->name << " " << info->pluginVersion
				<< " for packer '" << info->name << " " << info->packerVersion
				<< "' (" << info->author << ")" << std::endl;
		}
	}
	// PACKED_FILE [-o|--output FILE]
	else if (handler.getRawInputs().size() == 1)
	{
		std::string inputFile = handler.getRawInputs()[0];
		std::string outputFile = handler["output"]->used ? handler["output"]->input : std::string{inputFile}.append("-unpacked");
		std::vector<retdec::cpdetect::DetectResult> detectedPackers;

		if (!detectPackers(inputFile, detectedPackers))
			return EXIT_CODE_PREPROCESSING_ERROR;

		return unpackFile(inputFile, outputFile, brute, detectedPackers);
	}
	// Nothing else, just print the help
	else
		Log::info() << handler << std::endl;

	return EXIT_CODE_OK;
}

int _main(int argc, char** argv)
{
	ArgHandler handler("unpacker options [PACKED_FILE] [optional]");
	handler.setHelp(
			"Options are divided into groups. If the command-line argument belongs to any group,\n"
			"all other arguments must be from the same group. If they are not, they are ignored.\n"
			"The groups are parsed in the order given in this help. It is required to input the\n"
			"argument from one of the groups.\n"
			"\n"
			"The command-line arguments, which doesn't belong to any group can be used alongside any group.\n"
			"\n"
			"General group:\n"
			"   -h|--help              Show this help message.\n"
			"   -v|--version           Show RetDec version.\n"
			"\n"
			"Listing group:\n"
			"   -p|--plugins           Show the list of all available plugins.\n"
			"\n"
			"Unpacking group:\n"
			"   PACKED_FILE            Specify the packed file, which is needed to be unpacked.\n"
			"   -o|--output FILE       Optional. Specify the output file of unpacking as FILE.\n"
			"                          Default value is 'PACKED_FILE-unpacked'.\n"
			"\n"
			"Non-group optional arguments:\n"
			"   -b|--brute             Tell unpacker to run plugins in the brute mode. Plugins may or may not\n"
			"                          implement brute methods for unpacking. They can completely ignore this argument.\n"
			"   --max-memory N         Limit maximal memory to N bytes.\n"
			"   --max-memory-half-ram  Limit maximal memory to half of system RAM."
	);

	handler.registerArg('h', "help", false);
	handler.registerArg('v', "version", false);
	handler.registerArg('o', "output", true);
	handler.registerArg('p', "plugins", false);
	handler.registerArg('b', "brute", false);
	handler.registerArg('m', "max-memory", true);
	handler.registerArg('M', "max-memory-half-ram", false);

	return processArgs(handler, argc, argv);
}

} // namespace unpackertool
} // namespace retdec
