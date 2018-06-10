/**
 * @file src/pat2yara/pat2yara.cpp
 * @brief Yara patterns processing.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <iostream>
#include <ostream>

#include "retdec/utils/filesystem_path.h"
#include "pat2yara/processing.h"
#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/yaramod.h"

/**
 * Application for further processing of raw yara rules from bin2pat.
 */

using namespace retdec::utils;
using namespace yaramod;

/**
 * Print application usage.
 *
 * @param outputStream stream to write usage to
 */
void printUsage(
	std::ostream &outputStream)
{
	outputStream <<
	"Usage: pat2yara [-o OUTPUT_FILE] [--max-size VALUE] [--min-size VALUE]\n"
	"  [--min-pure VALUE] [-o OUTPUT_FILE] INPUT_FILE [INPUT_FILE...]\n\n"
	"-o --output OUTPUT_FILE\n"
	"    Output file path (if not given, stdout is used).\n"
	"    If multiple paths are given, only last one is used.\n\n"
	"-l --logfile LOG_FILE\n"
	"    Log-file path. Stores rules that were thrown away.\n"
	"    If no path is given, no information is stored or printed.\n"
	"    If multiple paths are given, only last one is used.\n\n"
	"--max-size VALUE\n"
	"    Rules longer than VALUE bytes are shortened. Limit is 10kB.\n\n"
	"--min-size VALUE\n"
	"    Rules shorter than VALUE bytes are left out.\n\n"
	"--min-pure VALUE\n"
	"    Only rules with at least VALUE pure bytes are processed.\n\n"
	"--ignore-nops OPCODE\n"
	"    Ignore NOPs with OPCODE when computing (pure) size.\n\n"
	"--delphi\n"
	"    Set special Delphi processing on.\n\n";
}

/**
 * Returns from application with error message.
 *
 * @param message error message for user
 *
 * @return non-zero return code
 */
int dieWithError(
	const std::string &message)
{
	std::cerr << "Error: " << message << "\n";
	return 1;
}

/**
 * Prints warning to standard error output.
 *
 * @param message warning message for user
 */
void printWarning(
	const std::string &message)
{
	std::cerr << "Warning: " << message << "\n";
}

/**
 * Converts passed argument to size value.
 *
 * @param args input vector of arguments
 * @param result variable for conversion result
 * @param index position of argument in input vector
 *
 * @return @c true if conversion was made successfully, @c false otherwise
 */
bool argumentToSize(
	const std::vector<std::string> &args,
	std::size_t &result,
	std::size_t index)
{
	if (index < args.size()) {
		std::size_t processed = 0;
		result = std::stoull(args[index], &processed);
		return processed == args[index].length();
	}

	return false;
}

/**
 * Process program inputs.
 *
 * @param args command line options
 *
 * @return return code
 */
int processArguments(std::vector<std::string> &args)
{
	ProcessingOptions options;
	std::string outputPath;
	std::string logPath;

	for (std::size_t i = 0; i < args.size(); ++i) {
		if (args[i] == "--help" || args[i] == "-h") {
			printUsage(std::cout);
			return 0;
		}
		else if (args[i] == "--delphi") {
			options.isDelphi = true;
		}
		else if (args[i] == "--max-size") {
			if (!argumentToSize(args, options.maxSize, ++i)) {
				return dieWithError("invalid --max-size argument value");
			}
		}
		else if (args[i] == "--min-size") {
			if (!argumentToSize(args, options.minSize, ++i)) {
				return dieWithError("invalid --min-size argument value");
			}
		}
		else if (args[i] == "--min-pure") {
			if (!argumentToSize(args, options.minPure, ++i)) {
				return dieWithError("invalid --min-pure argument value");
			}
		}
		else if (args[i] == "--ignore-nops") {
			options.ignoreNops = true;
			if (!argumentToSize(args, options.nopOpcode, ++i)) {
				return dieWithError("invalid --ignore-nops argument value");
			}
		}
		else if (args[i] == "--output" || args[i] == "-o") {
			if (args.size() > i + 1) {
				outputPath = args[++i];
			}
			else {
				return dieWithError("option " + args[i] + " needs a value");
			}
		}
		else if (args[i] == "--logfile" || args[i] == "-l") {
			if (args.size() > i + 1) {
				options.logOn = true;
				logPath = args[++i];
			}
			else {
				return dieWithError("option " + args[i] + " needs a value");
			}
		}
		else {
			if (FilesystemPath(args[i]).isFile()) {
				options.input.push_back(args[i]);
			}
			else {
				return dieWithError("invalid input file '" + args[i] + "'");
			}
		}
	}

	// Check options.
	std::string errorMessage;
	if (!options.validate(errorMessage)) {
		return dieWithError(errorMessage);
	}

	// Process input files.
	YaraFileBuilder logBuilder;
	YaraFileBuilder fileBuilder;

	if (!outputPath.empty()) {
		std::ofstream outputStream(outputPath);
		if (!outputStream) {
			return dieWithError(
				"cannot open file '" + outputPath + "' for writing");
		}
		else {
			processFiles(fileBuilder, logBuilder, options);
			outputStream << fileBuilder.get(false)->getText();
		}
	}
	else {
		processFiles(fileBuilder, logBuilder, options);
		std::cout << fileBuilder.get(false)->getText() << std::endl;
	}

	// Write log-file.
	if (!logPath.empty()) {
		std::ofstream logStream(logPath);
		if (logStream) {
			logStream << logBuilder.get(false)->getText();
		}
		else {
			return dieWithError(
				"cannot open log-file '" + outputPath + "' for writing");
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	std::vector<std::string> args(argv + 1, argv + argc);
	return processArguments(args);
}
