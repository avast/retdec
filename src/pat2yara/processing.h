/**
 * @file src/pat2yara/processing.h
 * @brief File processing.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef PAT2YARA_PROCESSING_H
#define PAT2YARA_PROCESSING_H

#include <memory>
#include <string>
#include <vector>

// Forward declarations.
namespace yaramod
{

	class YaraFileBuilder;
	class YaraFile;
	class Rule;

} // namespace yaramod

/**
 * Structure to keep information about user options.
 */
struct ProcessingOptions
{
	public:
		std::size_t maxSize = 0; ///< Upper rule size limit.
		std::size_t minSize = 0; ///< Lower rule size limit.
		std::size_t minPure = 0; ///< Pure information limit.

		bool ignoreNops = false;      ///< Do not count NOPs to (pure) size.
		std::size_t nopOpcode = 0x00; ///< Opcode of NOP instruction.

		bool isDelphi = false; ///< Delphi specific functions off/on.

		bool logOn = false;             ///< Log-file on/off.
		std::vector<std::string> input; ///< Input files.

		bool validate(std::string &error);
};

void processFiles(
	yaramod::YaraFileBuilder &fileBuilder,
	yaramod::YaraFileBuilder &logBuilder,
	const ProcessingOptions &options);

#endif
