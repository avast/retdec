/**
 * @file src/idr2pat/idr2pat.cpp
 * @brief IDR knowledge base pattern extractor.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <istream>
#include <map>
#include <set>
#include <vector>

#include "retdec/utils/conversion.h"
#include "yaramod/builder/yara_expression_builder.h"
#include "yaramod/builder/yara_hex_string_builder.h"
#include "yaramod/builder/yara_rule_builder.h"

using namespace retdec::utils;
using namespace yaramod;

/**
 * Offset - Name relocation pair type.
 */
using Relocation = std::pair<std::uint32_t, std::string>;

/**
 * Get one WORD from input stream.
 *
 * @param result where to store result
 * @param inputStream stream with correct position
 * @return @c true if value was read, @c false otherwise
 */
bool getWord(
		std::uint16_t &result,
		std::ifstream &inputStream)
{
	inputStream.read(reinterpret_cast<char*>(&result), sizeof(std::uint16_t));
	return inputStream.good();
}

/**
 * Get one DWORD from input stream.
 *
 * @param result where to store result
 * @param inputStream stream with correct position
 * @return @c true if value was read, @c false otherwise
 */
bool getDword(
		std::uint32_t &result,
		std::ifstream &inputStream)
{
	inputStream.read(reinterpret_cast<char*>(&result), sizeof(std::uint32_t));
	return inputStream.good();
}

/**
 * Get zero terminated string with size information from input stream.
 *
 * @param result where to store result
 * @param inputStream stream with correct position
 * @return @c true if value was read, @c false otherwise
 */
bool getString(
		std::string &result,
		std::ifstream &inputStream)
{
	std::uint16_t size = 0;
	if (!getWord(size, inputStream)) {
		return false;
	}

	result.resize(size);
	inputStream.read(&result[0], size);

	inputStream.get(); // Eat terminating character.
	return inputStream.good();
}

/**
 * Skip N bytes in input stream at actual position.
 *
 * @param N number of bytes to skip
 * @param inputStream stream with correct position
 */
void skip(
		const std::size_t &N,
		std::ifstream &inputStream)
{
	inputStream.seekg(inputStream.tellg() + std::istream::pos_type(N));
}

/**
 * Get string from relocations.
 *
 * @param relocations vectgor with relocation pairs
 * @return formatted string
 */
std::string getRelocationsAsString(
		const std::vector<Relocation> &relocations)
{
	std::string result;
	for (const auto &reloc : relocations) {
		if (!reloc.second.empty()) {
			result += toHex(reloc.first, false, 4) + " " + reloc.second + " ";
		}
	}

	if (!result.empty()) {
		// Pop space after last reference name.
		result.pop_back();
	}

	return result;
}

/**
 * Read one function or procedure from KB.
 *
 * @param inputStream stream with correct position
 * @param index index of function
 */
void readFunction(
		std::ifstream &inputStream,
		const std::size_t &index)
{
	// Skip (for now) unused fields.
	skip(2, inputStream);

	// Read function name.
	std::string name;
	getString(name, inputStream);

	// Skip (for now) unused fields.
	skip(8, inputStream);

	// Skip (for now) unused string.
	std::string returnType;
	getString(returnType, inputStream);

	// Skip (for now) unused fields.
	skip(4, inputStream);

	// Read dump size.
	std::uint32_t size = 0;
	getDword(size, inputStream);

	// Read number of fix-ups.
	std::uint32_t fixCount = 0;
	getDword(fixCount, inputStream);

	// Skip empty names and dumps.
	if (!size || name.empty()) {
		return;
	}

	// Read dump and relocation map (same size).
	std::vector<std::uint8_t> dump(size);
	inputStream.read(reinterpret_cast<char*>(&dump[0]), size);
	std::vector<std::uint8_t> relocationMap(size);
	inputStream.read(reinterpret_cast<char*>(&relocationMap[0]), size);

	// Read relocations.
	std::set<std::string> usedNames;
	std::vector<Relocation> relocations;
	for (std::size_t i = 0; i < fixCount; ++i) {
		// Skip (for now) unused fields.
		skip(1, inputStream);

		// Read offset and check for position validity.
		std::uint32_t fixOffset = 0;
		getDword(fixOffset, inputStream);
		if (fixOffset >= size) {
			// This happens sometimes - safe to ignore.
			continue;
		}

		// Read name and check for duplicates.
		std::string fixName;
		getString(fixName, inputStream);
		if (usedNames.find(fixName) == usedNames.end()) {
			// Create relocation and remember name.
			usedNames.insert(fixName);
			relocations.emplace_back(fixOffset, fixName);
		}
	}

	// Check buffer state before writing rule.
	if (!inputStream) {
		return;
	}

	YaraRuleBuilder ruleBuilder;
	ruleBuilder.withName("function_" + std::to_string(index));
	ruleBuilder.withStringMeta("name", name);
	ruleBuilder.withIntMeta("size", size);
	ruleBuilder.withIntMeta("bitWidth", 32);
	ruleBuilder.withStringMeta("endianness", "little");
	ruleBuilder.withStringMeta("architecture", "x86");

	auto refs = getRelocationsAsString(relocations);
	if (!refs.empty()) {
		ruleBuilder.withStringMeta("refs", refs);
	}

	YaraHexStringBuilder hexBuilder;
	for (std::size_t i = 0; i < size; ++i) {
		if (relocationMap[i] == 0x00) {
			hexBuilder.add(YaraHexStringBuilder(dump[i]));
		}
		else {
			hexBuilder.add(wildcard());
		}
	}
	ruleBuilder.withHexString("$1", hexBuilder.get());
	ruleBuilder.withCondition(stringRef("$1").get());

	std::cout << ruleBuilder.get()->getText() << "\n";
}

/**
 * Read database and print function rules.
 *
 * @param inputStream source input stream
 * @param errorMessage possible error message if @c false is returned
 * @return @c true if information was read correctly, @c false otherwise
 */
bool readDatabase(
		std::ifstream &inputStream,
		std::string &errorMessage)
{
	// Position of section offsets - last 4 bytes.
	inputStream.seekg(-4, std::ios_base::end);

	// Read entry point position.
	std::uint32_t entryPoint;
	getDword(entryPoint, inputStream);

	// Reset eof bit and go to the entry point.
	inputStream.clear();
	inputStream.seekg(entryPoint);

	// Skip (for now) unused fields.
	std::uint32_t toSkip;
	// Module definitions.
	getDword(toSkip, inputStream);
	skip(toSkip * 16 + 4, inputStream);
	// Constants definitions.
	getDword(toSkip, inputStream);
	skip(toSkip * 16 + 4, inputStream);
	// Types definitions.
	getDword(toSkip, inputStream);
	skip(toSkip * 16 + 4, inputStream);
	// Variables definitions.
	getDword(toSkip, inputStream);
	skip(toSkip * 16 + 4, inputStream);
	// String definitions.
	getDword(toSkip, inputStream);
	skip(toSkip * 16 + 4, inputStream);

	// Read function offsets.
	std::uint32_t functionCount;
	getDword(functionCount, inputStream);

	// Skip (for now) unused fields.
	skip(4, inputStream);

	// Read function offsets.
	std::vector<std::uint32_t> functionOffsets(functionCount);
	for (std::size_t i = 0; i < functionCount; ++i) {
		getDword(functionOffsets[i], inputStream);
		skip(12, inputStream);
	}

	// Check buffer.
	if (!inputStream) {
		errorMessage = "could not read function offsets";
		return false;
	}

	// Read functions.
	std::size_t functionIndex = 0;
	for (const auto &offset : functionOffsets) {
		inputStream.seekg(offset);
		readFunction(inputStream, functionIndex++);
	}

	return true;
}

/**
 * Print error and return.
 *
 * @param message error message
 * @return non-zero value
 */
int printError(const std::string &message)
{
	std::cerr << "Error: " << message << ".\n";
	return 1;
}

int main(int argc, char** argv)
{
	if (argc != 2) {
		return printError("need one argument - KB path");
	}

	std::ifstream inputFile(argv[1], std::ios::binary);
	if (!inputFile) {
		return printError("could not open input file");
	}

	char magic[25] = {};
	inputFile.read(magic, 24);
	if (std::string(magic) != "IDR Knowledge Base File") {
		return printError("file is not IDR database file");
	}

	std::string errorMessage;
	if (!readDatabase(inputFile, errorMessage)) {
		return printError(errorMessage);
	}

	return 0;
}
