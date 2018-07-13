/**
 * @file src/ar-extractortool/ar_extractor.cpp
 * @brief New frontend replacing llvm-ar.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <limits>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#include "retdec/utils/filesystem_path.h"
#include "retdec/ar-extractor/archive_wrapper.h"
#include "retdec/ar-extractor/detection.h"

using namespace retdec::utils;
using namespace retdec::ar_extractor;
using namespace rapidjson;

/**
 * Possible actions.
 */
enum class ACTION {
	LIST,           ///< List object files in archive.
	EXTRACT_ALL,    ///< Extract all objects in file.
	EXTRACT_NAME,   ///< Extract first object with given name.
	EXTRACT_INDEX,  ///< Extract object with given index.
	CHECK_AR,       ///< Check if file is an archive.
	CHECK_THIN,     ///< Check if file is a thin archive.
	CHECK_NORMAL,   ///< Check if file is a normal archive.
	OBJECT_COUNT    ///< Get object count.
};

/**
 * Output style selector.
 *
 * Made this global so it does not have to be passed around.
 */
bool isJson = false;

/**
 * Print usage.
 *
 * @param outputStream target stream
 */
void printUsage(
	std::ostream &outputStream)
{

	outputStream << "Usage: ar_extractor [OPTIONS] FILE\n\n"
	"Options:\n\n"
	"--arch-magic\n"
	"    Check if file starts with archive magic constants.\n"
	"    Exit code = 0 if archive magic, 1 otherwise.\n\n"
	"--thin-magic\n"
	"    Check if file starts with thin archive magic constant.\n"
	"    Exit code = 0 if thin archive, 1 otherwise.\n\n"
	"--normal-magic\n"
	"    Check if file starts with normal archive magic constant.\n"
	"    Exit code = 0 if normal archive, 1 otherwise.\n\n"
	"-v --valid\n"
	"    Try to load input file to check if it is usable. Either error is\n"
	"    printed or just zero value returned.\n\n"
	"-c --object-count\n"
	"    Prints number of object files in archive.\n\n"
	"-l --list\n"
	"    List content of archive in either JSON or plain-text format.\n\n"
	"-e --extract\n"
	"    Extract all object files from archive. Files with same name are\n"
	"    are decorated with their index. This is default action.\n\n"
	"-n --name <name>\n"
	"    Extract file with given name. If multiple files have same name\n"
	"    only first encountered file is extracted. Use name as shown in\n"
	"    --list action output - different tools may show different names.\n\n"
	"-i --index <uint>\n"
	"    Extract file with given index. Indexing starts with zero.\n\n"
	"-o --output <path>\n"
	"    Set output path for extraction. If option --extract is used, path\n"
	"    has to be a directory. If option --name or --index is used, a file\n"
	"    will be created on given path.\n\n"
	"-p --plain\n"
	"    Output will be printed in plain-text. This is default style.\n\n"
	"-j --json\n"
	"    Output will be printed in JSON format. This also affects errors.\n\n"
	"--no-numbers\n"
	"    No indexes will be printed. Valid only for --list option.\n\n"
	"--no-fix-names\n"
	"    Names are printed exactly as stored in archive (may break format).\n\n"
	"  Only last action/format option given is considered.\n\n";
}

/**
 * Print error in plain-text.
 *
 * @param message error message
 */
void printErrorPlainText(
	const std::string &message)
{
	std::cerr << "Error: " << message << ".\n";
}

/**
 * Print error in JSON format.
 *
 * @param message error message
 */
void printErrorJson(
	const std::string &message)
{
	Document errorFile(kObjectType);
	errorFile.AddMember(
			"error",
			Value(message.c_str(), errorFile.GetAllocator()).Move(),
			errorFile.GetAllocator());

	StringBuffer buffer;
	PrettyWriter<StringBuffer> writer(buffer);
	errorFile.Accept(writer);

	std::cerr << buffer.GetString() << "\n";
}

/**
 * Print error and return non-zero.
 *
 * @param message error message
 *
 * @return non-zero
 */
int printErrorAndReturn(
	const std::string &message)
{
	isJson ? printErrorJson(message) : printErrorPlainText(message);
	return 1;
}

/**
 * Print archive table.
 *
 * @param archive target archive
 * @param fixNames names will be fixed if @c true
 * @param isNum list will be numbered if @c true
 *
 * @return application error code
 */
int printTable(
	const ArchiveWrapper &archive,
	bool fixNames = true,
	bool isNum = true)
{
	std::string result, error;
	if (isJson) {
		if (!archive.getJsonList(result, error, fixNames, isNum)) {
			return printErrorAndReturn(error);
		}
	}
	else {
		if (!archive.getPlainTextList(result, error, fixNames, isNum)) {
			return printErrorAndReturn(error);
		}
	}

	std::cout << result;
	return 0;
}

/**
 * Get argument on given position.
 *
 * @param index argument position
 * @param args vector with arguments
 * @param result argument on position
 *
 * @return @c true if argument @c exists, @c false otherwise
 */
bool getArgFromArgs(
	const std::size_t index,
	const std::vector<std::string> &args,
	std::string &result)
{
	if (index >= args.size()) {
		return false;
	}

	result = args[index];
	return true;
}

/**
 * Process inputs.
 *
 * @param args vector with command line arguments
 *
 * @return application error code
 */
int processArguments(
	const std::vector<std::string> &args)
{
	ACTION action = ACTION::EXTRACT_ALL;
	bool checkOnly = false;
	bool fixNames = true;
	bool isNum = true;

	std::string outPath;
	std::string inputArchive;
	std::string targetObjectName;
	std::size_t targetObjectIndex = std::numeric_limits<std::size_t>::max();

	for (std::size_t i = 0; i < args.size(); ++i) {
		const auto &arg = args[i];

		if (arg == "-h" || arg == "--help") {
			printUsage(std::cout);
			return 0;
		}
		else if (arg == "-o" || arg == "--output") {
			if (!getArgFromArgs(++i, args, outPath)) {
				return printErrorAndReturn("No -o/--output value");
			}
		}
		else if (arg == "--arch-magic") {
			action = ACTION::CHECK_AR;
		}
		else if (arg == "--thin-magic") {
			action = ACTION::CHECK_THIN;
		}
		else if (arg == "--normal-magic") {
			action = ACTION::CHECK_NORMAL;
		}
		else if (arg == "-c" || arg == "--object-count") {
			action = ACTION::OBJECT_COUNT;
		}
		else if (arg == "-l" || arg == "--list") {
			action = ACTION::LIST;
		}
		else if (arg == "-v" || arg == "--valid") {
			checkOnly = true;
		}
		else if (arg == "-p" || arg == "--plain") {
			isJson = false;
		}
		else if (arg == "-j" || arg == "--json") {
			isJson = true;
		}
		else if (arg == "--no-numbers") {
			isNum = false;
		}
		else if (arg == "--no-fix-names") {
			fixNames = false;
		}
		else if (arg == "-e" || arg == "--extract") {
			action = ACTION::EXTRACT_ALL;
		}
		else if (arg == "-n" || arg == "--name") {
			action = ACTION::EXTRACT_NAME;
			if (!getArgFromArgs(++i, args, targetObjectName)) {
				return printErrorAndReturn("No -n/--name value");
			}
		}
		else if (arg == "-i" || arg == "--index") {
			action = ACTION::EXTRACT_INDEX;
			if (i + 1 < args.size()) {
				try {
					targetObjectIndex = std::stoull(args[++i]);
				}
				catch (...) {
					return printErrorAndReturn("Invalid --index value");
				}
			}
			else {
				return printErrorAndReturn("No -i/--index value");
			}
		}
		else {
			if (FilesystemPath(arg).isFile()) {
				if (inputArchive.empty()) {
					inputArchive = arg;
				}
				else {
					return printErrorAndReturn("Multiple input files");
				}
			}
			else {
				return printErrorAndReturn("Invalid argument '" + arg + "'");
			}
		}
	}

	if (inputArchive.empty()) {
		return printErrorAndReturn("No input file");
	}

	// Do action that does not require parsing whole archive.
	// Negation is used due to conversion to integer return value.
	switch (action) {
		case ACTION::CHECK_AR:
			return !isArchive(inputArchive);

		case ACTION::CHECK_THIN:
			return !isThinArchive(inputArchive);

		case ACTION::CHECK_NORMAL:
			return !isNormalArchive(inputArchive);

		default:
			break;
	}

	// Detect thin archives if extraction is requested.
	if (action != ACTION::LIST && isThinArchive(inputArchive)) {
		return printErrorAndReturn("Archive is thin archive!");
	}

	// Detect Mach-O archives.
	if (isFatMachOArchive(inputArchive)) {
		return printErrorAndReturn(
			"File is Mach-O static library (use macho_extractor utility)");
	}

	// Read archive.
	bool succes;
	std::string error;
	ArchiveWrapper archive(inputArchive, succes, error);
	if (!succes) {
		return printErrorAndReturn(error);
	}

	// At this time either error occurred or we can safely return.
	if (checkOnly) {
		return 0;
	}

	// Do selected action.
	switch (action) {
		case ACTION::LIST:
			return printTable(archive, fixNames, isNum);

		case ACTION::OBJECT_COUNT:
			std::cout << archive.getNumberOfObjects() << "\n";
			return 0;

		case ACTION::EXTRACT_NAME:
			succes = archive.extractByName(targetObjectName, error, outPath);
			break;

		case ACTION::EXTRACT_INDEX:
			succes = archive.extractByIndex(targetObjectIndex, error, outPath);
			break;

		case ACTION::EXTRACT_ALL:
			/* fall-thru */
		default:
			succes = archive.extract(error, outPath);
			break;
	}
	if (!succes) {
		return printErrorAndReturn(error);
	}

	return 0;
}

int main(int argc, char **argv)
{
	return processArguments(std::vector<std::string>(argv + 1, argv + argc));
}
