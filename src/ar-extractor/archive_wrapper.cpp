/**
 * @file src/ar-extractor/archive_wrapper.cpp
 * @brief Definition of ArchiveWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <ostream>

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/string.h"
#include "retdec/ar-extractor/archive_wrapper.h"

using namespace retdec::utils;
using namespace llvm;
using namespace llvm::object;
using namespace rapidjson;

namespace
{

/**
 * Fix name.
 *
 * @param name input name
 *
 * @return new fixed name
 */
std::string fixName(
	std::string name)
{
	std::transform(name.begin(), name.end(), name.begin(),
		[](const unsigned char c) {
			return (!std::isalnum(c) && !strchr("-. \\", c)) ? '_' : c;
		});
	return name;
}

/**
 * Write single file.
 *
 * @param outputPath output file path
 * @param inputBuffer input buffer with data
 * @param errorMessage error message if @c false is returned
 *
 * @return @c true if no errors occurred, @c false otherwise
 */
bool writeFile(
	const std::string &outputPath,
	const llvm::StringRef &inputBuffer,
	std::string &errorMessage)
{
	std::ofstream outStream(outputPath, std::ofstream::binary);
	if (outStream) {
		outStream.write(inputBuffer.data(), inputBuffer.size());
		if (!outStream) {
			errorMessage = "Could not write content to output file";
			return false;
		}

		// Everything OK.
		return true;
	}

	errorMessage = "Could not open output file for writing";
	return false;
}

/**
 * Check for errors.
 *
 * @param error input Error object
 * @param errorMessage error message if @c true is returned
 *
 * @return @c true if error was found, @c false otherwise
 */
bool checkError(
	Error &error,
	std::string &errorMessage)
{
	if (error) {
		errorMessage = toString(std::move(error));
		return true;
	}

	return false;
}

} // anonymous namespace

namespace retdec {
namespace ar_extractor {

/**
 * Constructor.
 *
 * @param archivePath path to input archive
 * @param succes result of object construction
 * @param errorMessage possible error message if @p success is set to false
 */
ArchiveWrapper::ArchiveWrapper(
	const std::string &archivePath,
	bool &succes,
	std::string &errorMessage)
	: buffer(MemoryBuffer::getFile(llvm::Twine(archivePath)))
{
	succes = false;
	if (!buffer) {
		errorMessage = "Could not create file buffer";
		return;
	}

	Error error;
	archive = std::make_unique<Archive>(buffer.get()->getMemBufferRef(), error);
	if (error) {
		errorMessage = toString(std::move(error));
		return;
	}

	// Get object count - this iterates over all objects.
	succes = getCount(objectCount, errorMessage);
}

/**
 * Get number of objects.
 *
 * @return number of objects in file.
 */
std::size_t ArchiveWrapper::getNumberOfObjects() const
{
	return objectCount;
}

/**
 * Check whether archive is thin archive.
 *
 * @return @c true if archive is thin, @c false otherwise
 */
bool ArchiveWrapper::isThinArchive() const
{
	return archive->isThin();
}

/**
 * Check whether archive is empty.
 *
 * @return @c true if archive is empty, @c false otherwise
 */
bool ArchiveWrapper::isEmptyArchive() const
{
	return objectCount == 0;
}

/**
 * Get list of object file names in plain-text.
 *
 * @param result string with complete list in plain-text
 * @param errorMessage possible error message if @c false is returned
 * @param niceNames names will be made nicer if @c true
 * @param numbers list will be numbered if @c true
 *
 * @return @c true if no errors occurred, @c false otherwise
 */
bool ArchiveWrapper::getPlainTextList(
	std::string &result,
	std::string &errorMessage,
	bool niceNames,
	bool numbers) const
{
	result.clear();
	std::size_t counter = 0;
	std::vector<std::string> names;

	if (getNames(names, errorMessage)) {
		for (const auto &name : names) {
			const auto outName = niceNames ? fixName(name) : name;
			result += numbers ? std::to_string(counter++) + "\t" : "";
			result += outName + "\n";
		}
		return true;
	}

	return false;
}

/**
 * Get list of object file names in JSON format.
 *
 * @param result string with complete list in JSON format
 * @param errorMessage possible error message if @c false is returned
 * @param niceNames names will be made nicer if @c true
 * @param numbers list will be numbered if @c true
 *
 * @return @c true if no errors occurred, @c false otherwise
 */
bool ArchiveWrapper::getJsonList(
	std::string &result,
	std::string &errorMessage,
	bool niceNames,
	bool numbers) const
{
	result.clear();
	std::size_t counter = 0;
	std::vector<std::string> names;

	if (getNames(names, errorMessage)) {
		Value objects(kArrayType);
		Document outFile(kObjectType);
		auto& allocator = outFile.GetAllocator();

		for (const auto &name : names) {
			const std::string outName = niceNames ? fixName(name) : name;

			Value object(kObjectType);
			object.AddMember("name", Value(outName.c_str(), allocator).Move(), allocator);
			if (numbers) {
				object.AddMember("index", static_cast<uint64_t>(counter++), allocator);
			}
			objects.PushBack(object, allocator);
		}
		outFile.AddMember("objects", objects, allocator);

		StringBuffer buffer;
		PrettyWriter<StringBuffer> writer(buffer);
		outFile.Accept(writer);
		result = buffer.GetString();
		return true;
	}

	return false;
}

/**
 * Extract all object files.
 *
 * If directory is not specified, current directory is used. If multiple files
 * have same name, they are decorated with their index suffix.
 *
 * @param errorMessage possible error message if @c false is returned
 * @param directory optional target directory
 *
 * @return @c true if no errors occurred, @c false otherwise
 */
bool ArchiveWrapper::extract(
	std::string &errorMessage,
	const std::string &directory) const
{
	// Check if target directory exists if string not empty.
	if (!directory.empty() && !FilesystemPath(directory).isDirectory()) {
		errorMessage = "Invalid target directory";
		return false;
	}

	/**
	 * @todo In writeFile function call, separator is added to path, this may
	 * or may not work on Windows OS.
	 */

	// Map for non-unique names - counts number of name occurrences.
	std::map<std::string, std::size_t> nameMap;

	Error error;
	for (const auto &child : archive->children(error)) {
		if (checkError(error, errorMessage)) {
			return false;
		}

		// Try to get name.
		const auto nameOrErr = child.getName();
		std::string name = !nameOrErr ? "invalid_name" : fixName(*nameOrErr);

		// Increment name count and fix name if it is not unique.
		if (++nameMap[name] != 1) {
			name += "." + std::to_string(nameMap[name]);
		}

		const auto bufferOrErr = child.getBuffer();
		if (!bufferOrErr) {
			errorMessage = "Could not get file buffer";
			return false;
		}
		else {
			auto dir = directory.empty() ? directory : directory + '/';
			if (!writeFile(dir + name, *bufferOrErr, errorMessage)) {
				return false;
			}
		}
	}

	return !checkError(error, errorMessage);
}

/**
 * Extract object file by its name.
 *
 * If output path is not given, object name and current directory is used. If
 * multiple files with the same name are present, only first one is extracted.
 *
 * @param name target name
 * @param errorMessage possible error message if @c false is returned
 * @param outputPath optional output path
 *
 * @return @c true if no errors occurred, @c false otherwise
 */
bool ArchiveWrapper::extractByName(
	const std::string &name,
	std::string &errorMessage,
	const std::string &outputPath) const
{
	Error error;
	for (const auto &child : archive->children(error)) {
		if (checkError(error, errorMessage)) {
			return false;
		}

		const auto nameOrErr = child.getName();
		if (!nameOrErr) {
			// Could not get name.
			continue;
		}

		if (name != fixName(nameOrErr->str())) {
			// Name does not match.
			continue;
		}

		// Get buffer and try to write to a file.
		const auto bufferOrErr = child.getBuffer();
		if (!bufferOrErr) {
			errorMessage = "Could not get file buffer";
			return false;
		}
		else {
			auto path = outputPath.empty() ? name : outputPath;
			return writeFile(path, *bufferOrErr, errorMessage);
		}
	}

	if (checkError(error, errorMessage)) {
		return false;
	}

	errorMessage = "Could not find desired file";
	return false;
}

/**
 * Extract object file by its index.
 *
 * If output path is not given, object name and current directory is used. If
 * name cannot be retrieved, name 'invalid_name' is used.
 *
 * @param index target index
 * @param errorMessage possible error message if @c false is returned
 * @param outputPath optional output path
 *
 * @return @c true if no errors occurred, @c false otherwise
 */
bool ArchiveWrapper::extractByIndex(
	const std::size_t index,
	std::string &errorMessage,
	const std::string &outputPath) const
{
	Error error;
	std::size_t counter = 0;
	for (const auto &child : archive->children(error)) {
		if (checkError(error, errorMessage)) {
			return false;
		}

		// No random access available.
		if (index != counter++) {
			continue;
		}

		// Get buffer and try to write to a file.
		const auto bufferOrErr = child.getBuffer();
		if (!bufferOrErr) {
			errorMessage = "Could not get file buffer";
			return false;
		}
		else {
			std::string path;
			if (outputPath.empty()) {
				// No path given - use object name.
				const auto nameOrErr = child.getName();
				path = !nameOrErr ? "invalid_name" : fixName(nameOrErr->str());
			}
			else {
				path = outputPath;
			}
			return writeFile(path, *bufferOrErr, errorMessage);
		}
	}

	if (checkError(error, errorMessage)) {
		return false;
	}

	errorMessage = "Could not find desired file";
	return false;
}

/**
 * Get names of all object files in archive.
 *
 * If name of object could not be read from input archive, name 'invalid_name'
 * is used.
 *
 * @param result container where names will be added
 * @param errorMessage possible error message if @c false is returned
 *
 * @return @c true if no errors occurred, @c false otherwise
 */
bool ArchiveWrapper::getNames(
	std::vector<std::string> &result,
	std::string &errorMessage) const
{
	Error error;
	for (const auto &child : archive->children(error)) {
		if (checkError(error, errorMessage)) {
			return false;
		}

		auto nameOrErr = child.getName();
		if (!nameOrErr) {
			result.emplace_back("invalid_name");
		}
		else {
			result.push_back(*nameOrErr);
		}
	}

	return !checkError(error, errorMessage);
}

/**
 * Get object count.
 *
 * @param count result
 * @param errorMessage possible error message if @c false is returned
 *
 * @return @c true if no errors occurred, @c false otherwise
 */
bool ArchiveWrapper::getCount(
	std::size_t &count,
	std::string &errorMessage) const
{
	Error error;
	count = 0; // Reset counter.
	const auto &ar = archive;
	for (auto i = ar->child_begin(error), e = ar->child_end(); i != e; ++i) {
		if (checkError(error, errorMessage)) {
			return false;
		}
		count++;
	}

	return !checkError(error, errorMessage);
}

} // namespace ar_extractor
} // namespace retdec
