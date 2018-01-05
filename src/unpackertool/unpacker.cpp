/**
 * @file src/unpackertool/unpacker.cpp
 * @brief Main function and help.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <memory>

#include "tl-cpputils/filesystem_path.h"
#include "cpdetect/cpdetect.h"
#include "fileformat/fileformat.h"
#include "arg_handler.h"
#include "unpacker/plugin.h"
#include "plugin_mgr.h"

using namespace tl_cpputils;
using namespace unpacker;
using namespace unpackertool;

/**
 * Possible exit codes of the unpacker as program.
 */
enum ExitCode
{
	EXIT_CODE_OK = 0, ///< Unpacker ended successfully.
	EXIT_CODE_NOTHING_TO_DO, ///< There was not found matching plugin.
	EXIT_CODE_UNPACKING_FAILED, ///< At least one plugin failed at the unpacking of the file.
	EXIT_CODE_PREPROCESSING_ERROR ///< Error with preprocessing of input file before unpacking.
};

bool detectPackers(const std::string& inputFile, std::vector<cpdetect::DetectResult>& detectedPackers)
{
	using namespace cpdetect;
	using namespace fileformat;

	DetectParams detectionParams(SearchType::MOST_SIMILAR, true, true);

	ToolInformation toolInfo;
	switch (detectFileFormat(inputFile))
	{
		case Format::UNDETECTABLE:
			std::cerr << "Input file '" << inputFile << "' doesn't exist!" << std::endl;
			return false;
		case Format::UNKNOWN:
			std::cerr << "Input file '" << inputFile << "' is in unknown format!" << std::endl;
			return false;
		default:
		{
			auto fileParser = createFileFormat(inputFile);
			if (!fileParser)
			{
				std::cerr << "Error while detecting format of file '" << inputFile << "'! Please, report this." << std::endl;
				return false;
			}

			auto compilerDetector = createCompilerDetector(*(fileParser.get()), detectionParams, toolInfo);
			if (!compilerDetector)
			{
				std::cerr << "No compiler detector was found! Please, report this." << std::endl;
				return false;
			}

			compilerDetector->getAllInformation();
			break;
		}
	}

	detectedPackers = toolInfo.detectedTools;
	return true;
}

ExitCode unpackFile(const std::string& inputFile, const std::string& outputFile, bool brute, const std::vector<cpdetect::DetectResult>& detectedPackers)
{
	Plugin::Arguments pluginArgs = { inputFile, outputFile, brute };

	ExitCode ret = EXIT_CODE_NOTHING_TO_DO;
	for (const auto& detectedPacker : detectedPackers)
	{
		PluginList plugins = sPluginMgr.matchingPlugins(detectedPacker.name, detectedPacker.versionInfo);

		if (plugins.empty())
		{
			std::cerr << "No matching plugins found for '" << detectedPacker.name;
			if (detectedPacker.versionInfo != WILDCARD_ALL_VERSIONS)
				std::cerr << " " << detectedPacker.versionInfo;
			std::cerr << "'" << std::endl;
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
		std::cout << handler << std::endl;
		return EXIT_CODE_OK;
	}

	// First of all, load plugins
	// If -d|--dir argument isn't specified, take the current path from argv[0]
	std::string pluginsDir = FilesystemPath(argv[0]).getParentPath().append("/unpacker-plugins");
	if (handler["dir"]->used)
		pluginsDir = handler["dir"]->input;
	sPluginMgr.loadPlugins(pluginsDir);

	bool brute = handler["brute"]->used;

	// -h|--help
	if (handler["help"]->used)
	{
		std::cout << handler << std::endl;
	}
	// -p|--plugins
	else if (handler["plugins"]->used)
	{
		std::cout << "List of available plugins:" << std::endl;

		const PluginTable& plugins = sPluginMgr.plugins();
		for (const auto& pluginPair : plugins)
		{
			for (const auto& plugin : pluginPair.second)
			{
				const Plugin::Info* info = plugin->getInfo();
				std::cout << info->name << " " << info->pluginVersion
					<< " for packer '" << info->name << " " << info->packerVersion
					<< "' (" << info->author << ")" << std::endl;
			}
		}
	}
	// PACKED_FILE [-o|--output FILE]
	else if (handler.getRawInputs().size() == 1)
	{
		std::string inputFile = handler.getRawInputs()[0];
		std::string outputFile = handler["output"]->used ? handler["output"]->input : std::string{inputFile}.append("-unpacked");
		std::vector<cpdetect::DetectResult> detectedPackers;

		if (!detectPackers(inputFile, detectedPackers))
			return EXIT_CODE_PREPROCESSING_ERROR;

		return unpackFile(inputFile, outputFile, brute, detectedPackers);
	}
	// Nothing else, just print the help
	else
		std::cout << handler << std::endl;

	return EXIT_CODE_OK;
}

int main(int argc, char** argv)
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
			"Help group:\n"
			"   -h|--help              Prints this help message.\n"
			"\n"
			"Listing group:\n"
			"   -p|--plugins           Prints the list of all available plugins in the plugin directory.\n"
			"\n"
			"Unpacking group:\n"
			"   PACKED_FILE            Specifies the packed file, which is needed to be unpacked.\n"
			"   -o|--output FILE       Optional. Specifies the output file of unpacking as FILE.\n"
			"                          Default value is 'PACKED_FILE-unpacked'.\n"
			"\n"
			"Non-group optional arguments:\n"
			"   -d|--dir DIR           Specifies the directory that contains all the plugins as DIR.\n"
			"                          This directory is recursively searched. If no -d|--dir options is\n"
			"                          specified, the default search path is /path/to/unpacker/unpacker-plugins/.\n"
			"   -b|--brute             Tell unpacker to run plugins in the brute mode. Plugins may or may not\n"
			"                          implement brute methods for unpacking. They can completely ignore this argument."
	);

	handler.registerArg('h', "help", false);
	handler.registerArg('o', "output", true);
	handler.registerArg('p', "plugins", false);
	handler.registerArg('d', "dir", true);
	handler.registerArg('b', "brute", false);

	return processArgs(handler, argc, argv);
}
