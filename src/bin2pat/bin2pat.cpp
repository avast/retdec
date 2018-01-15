/**
 * @file src/bin2pat/bin2pat.cpp
 * @brief Binary pattern generator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <iostream>
#include <ostream>
#include <vector>

#include "retdec/utils/filesystem_path.h"
#include "retdec/patterngen/pattern_extractor/pattern_extractor.h"
#include "yaramod/yaramod.h"

/**
 * Tool for generation of patterns in yara format.
 *
 * Format description:
 * Output is set of yara rules (http://yara.readthedocs.io/en/v3.5.0/).
 */

using namespace retdec::utils;
using namespace retdec::patterngen;

void printUsage(
	std::ostream &outputStream)
{
	outputStream << "Usage: bin2pat [-o OUTPUT_FILE] [-n NOTE]"
		<< " INPUT_FILE [INPUT_FILE...]\n\n"
		<< "-o --output OUTPUT_FILE\n"
		<< "    Output file path (if not given, stdout is used).\n"
		<< "    If multiple paths are given, only last one is used.\n\n"
		<< "-n --note NOTE\n"
		<< "    Optional note that will be added to all rules.\n"
		<< "    If multiple notes are given, only last one is used.\n\n";
}

int printErrorAndDie(
	const std::string &message)
{
	std::cerr << "Error: " << message << ".\n";
	printUsage(std::cerr);
	return 1;
}

int needValue(
	const std::string &arg)
{
	return printErrorAndDie("argument " + arg + " requires value");
}

int processArgs(
	const std::vector<std::string> &args)
{
	std::string note;
	std::string outPath;
	std::vector<std::string> inPaths;

	for (std::size_t i = 0, e = args.size(); i < e; ++i) {
		if (args[i] == "--help" || args[i] == "-h") {
			printUsage(std::cout);
			return 0;
		}
		else if (args[i] == "-o" || args[i] == "--output") {
			if (i + 1 < e) {
				outPath = args[++i];
			}
			else {
				return needValue(args[i]);
			}
		}
		else if (args[i] == "-n" || args[i] == "--note") {
			if (i + 1 < e) {
				note = args[++i];
			}
			else {
				return needValue(args[i]);
			}
		}
		else {
			// Input file. Check file on system level.
			if(!FilesystemPath(args[i]).isFile()) {
				printErrorAndDie("argument '" + args[i]
					+ "' is neither valid file nor argument");
			}
			else {
				inPaths.push_back(args[i]);
			}
		}
	}

	if (inPaths.empty()) {
		return printErrorAndDie("input files missing");
	}

	// Prepare builder.
	yaramod::YaraFileBuilder builder;

	// Process files.
	unsigned index = 0;
	bool atLeastOne = false;
	for (const auto &path : inPaths) {
		PatternExtractor extractor(path, "file_" + std::to_string(index++));

		// Add rules if valid.
		if (!extractor.isValid()) {
			// Sometimes, non-supported files are present in archives. We will
			// only print warning if such a file is encountered.
			std::cerr << "Error: file '" << path << "' was not processed.\n";
			std::cerr << "Problem: " << extractor.getErrorMessage() << ".\n\n";
			continue;
		}
		else {
			atLeastOne = true;
			extractor.addRulesToBuilder(builder, note);

			// Print warnings if any.
			const auto &warnings = extractor.getWarnings();
			if (!warnings.empty()) {
				std::cerr << "Warning: problems with file '" << path << "'\n";
				for (const auto &warning : warnings) {
					std::cerr << "Problem: " << warning << ".\n";
				}
				std::cerr << "\n";
			}
		}
	}

	// Check processing results.
	if (!atLeastOne) {
		printErrorAndDie("no valid files were processed");
	}

	// Print results.
	if (!outPath.empty()) {
		std::ofstream outputFile(outPath);
		if (!outputFile) {
			printErrorAndDie("could not open output file");
		}
		outputFile << builder.get(false)->getText() << "\n";
	}
	else {
		std::cout << builder.get(false)->getText() << "\n";
	}

	return 0;
}

int main(int argc, char *argv[])
{
	std::vector<std::string> args(argv + 1, argv + argc);
	return processArgs(args);
}
