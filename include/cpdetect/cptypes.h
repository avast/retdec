/**
 * @file include/cpdetec/cptypes.h
 * @brief cpdetectl types and structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_CPTYPES_H
#define CPDETECT_CPTYPES_H

#include <limits>
#include <vector>

#include "fileformat/fftypes.h"

namespace cpdetect {

/**
 * Error codes of library
 */
enum class ReturnCode
{
	OK,
	ARG,
	FILE_NOT_EXIST,
	FILE_PROBLEM,
	ENTRY_POINT_DETECTION,
	UNKNOWN_FORMAT,
	FORMAT_PARSER_PROBLEM,
	MACHO_AR_DETECTED,
	ARCHIVE_DETECTED,
	UNKNOWN_CP,
};

/**
 * Type of tool detection
 */
enum class SearchType
{
	EXACT_MATCH,   ///< only identical signatures
	MOST_SIMILAR,  ///< the most similar signature
	SIM_LIST       ///< list of similar signatures
};

/**
 * Source from which result was obtained
 */
enum class DetectionMethod
{
	UNKNOWN,             ///< unknown detection method
	COMBINED,            ///< combination of methods
	SIGNATURE,           ///< yara or slashed signature
	DWARF_DEBUG_H,       ///< DWARF debug information
	SECTION_TABLE_H,     ///< section table
	IMPORT_TABLE_H,      ///< import symbols
	EXPORT_TABLE_H,      ///< export symbols
	SYMBOL_TABLE_H,      ///< symbols
	LINKER_VERSION_H,    ///< linker version
	LINKED_LIBRARIES_H,  ///< specific libraries
	STRING_SEARCH_H,     ///< specific strings
	DYNAMIC_ENTRIES_H,   ///< .dynamic section
	COMMENT_H,           ///< .comment section
	MANIFEST_H,          ///< manifest resource
	OTHER_H              ///< other heuristic
};

/**
 * Strength of used heuristic
 */
enum class DetectionStrength
{
	LOW,
	MEDIUM,
	HIGH,
	SURE
};

/**
 * Type of detected tool
 */
enum class ToolType
{
	UNKNOWN,
	COMPILER,
	LINKER,
	INSTALLER,
	PACKER
};

/**
 * Packing detection level
 */
enum class Packed
{
	NOT_PACKED,
	PROBABLY_NO,
	PROBABLY_YES,
	PACKED
};

/**
 * Search parameters
 */
struct DetectParams
{
	SearchType searchType;  ///< type of search

	bool internal;  ///< use of internal signature database
	bool external;  ///< use of external signature database

	DetectParams(SearchType searchType_, bool internal_, bool external_);
	~DetectParams();
};

/**
 * Structure with results of tool detection
 */
struct DetectResult
{
	ToolType type = ToolType::UNKNOWN;  ///< type of tool
	std::string name;                   ///< name of tool
	std::string versionInfo;            ///< information about version
	std::string additionalInfo;         ///< some additional information

	unsigned long long impCount = 0;    ///< number of significant nibbles of signature
	unsigned long long agreeCount = 0;  ///< number of significant nibbles of signature agreeing with file content

	DetectionMethod source = DetectionMethod::UNKNOWN;    ///< source from which result was obtained
	DetectionStrength strength = DetectionStrength::LOW;  ///< strength of source

	DetectResult();
	~DetectResult();

	bool isReliable() const;
	bool isCompiler() const;
	bool isLinker() const;
	bool isInstaller() const;
	bool isPacker() const;
	bool isKnownType() const;
	bool isUnknownType() const;
};

/**
 * Detected programming language
 */
struct DetectLanguage
{
	bool bytecode;  /// < @c true if bytecode is detected

	std::string name;            ///< name of programming language
	std::string additionalInfo;  ///< some additional information

	DetectLanguage();
	~DetectLanguage();
};

/**
 * All information about used tools
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for unsigned integer types.
 * If @a entryPointOffset has value @c false, value of @a epOffset is undefined.
 * If @a entryPointAddress has value @c false, values of @a epAddress and @a imageBase are undefined.
 * If @a entryPointSection has value @c false, values of @a epSection are undefined.
 */
struct ToolInformation
{
	std::vector<std::string> errorMessages;         ///< error and warning messages
	std::vector<DetectResult> detectedTools;        ///< detected tools (compilers, packers...)
	std::vector<DetectLanguage> detectedLanguages;  ///< detected programming language(s)

	bool entryPointOffset;           ///< @c false if file has no associated EP or EP offset was not found
	bool entryPointAddress;          ///< @c false if file has no associated EP or EP address was not found
	bool entryPointSection;          ///< @c false if file has no associated EP or EP section was not found
	unsigned long long imageBase;    ///< image base address
	unsigned long long epAddress;    ///< entry point address
	unsigned long long epOffset;     ///< entry point offset
	fileformat::Section epSection;  ///< entry point section
	std::string epBytes;             ///< hexadecimal representation of entry point bytes

	bool packerDetected = false;      ///< @c true if at least one packer was detected
	bool linkerDetected = false;      ///< @c true if at least one linker was detected
	bool compilerDetected = false;    ///< @c true if at least one compiler was detected
	bool installertDetected = false;  ///< @c true if at least one installer was detected

	ToolInformation();
	~ToolInformation();

	/// @name Adding result methods
	/// @{
	void addTool(DetectionMethod source, DetectionStrength strength, ToolType toolType,
		const std::string &name, const std::string &version = "", const std::string &extra = "");
	void addTool(std::size_t matchNibbles, std::size_t totalNibbles, ToolType toolType,
		const std::string &name, const std::string &version = "", const std::string &extra = "");
	void addLanguage(const std::string &name, const std::string &extra = "", bool bytecode = false);
	/// @}

	/// @name Query methods
	/// @{
	bool isReliableResult(std::size_t resultIndex) const;
	bool hasReliableResult() const;
	Packed isPacked() const;
	/// @}

private:
	void setToolTypeVariables(ToolType toolType);
};

/**
 * Similarity with signature
 */
struct Similarity
{
	unsigned long long same;   ///< number of significant nibbles of signature agreeing with file content
	unsigned long long total;  ///< number of significant nibbles of signature
	double ratio;              ///< @a same divided by @a total

	Similarity();
	~Similarity();
};

std::string detectionMetodToString(DetectionMethod method);
std::string toolTypeToString(ToolType toolType);
std::string packedToString(Packed packed);


} // namespace cpdetect

#endif
