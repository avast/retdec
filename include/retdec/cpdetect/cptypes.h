/**
 * @file include/retdec/cpdetect/cptypes.h
 * @brief cpdetectl types and structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_CPTYPES_H
#define RETDEC_CPDETECT_CPTYPES_H

#include <limits>
#include <vector>

#include "retdec/cpdetect/settings.h"
#include "retdec/fileformat/fftypes.h"

namespace retdec {
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
	NOTE_H,              ///< .note section
	MANIFEST_H,          ///< manifest resource
	HEADER_H,            ///< MZ header
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
	PACKER,
	OTHER
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

	std::size_t epBytesCount;

	DetectParams(SearchType searchType_, bool internal_, bool external_, std::size_t epBytesCount_ = EP_BYTES_SIZE);
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

	unsigned long long impCount = 0;    ///< total number of significant nibbles
	unsigned long long agreeCount = 0;  ///< matched number of significant nibbles

	DetectionMethod source = DetectionMethod::UNKNOWN;    ///< detection type
	DetectionStrength strength = DetectionStrength::LOW;  ///< detection strength

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
	bool bytecode = false;  /// < @c true if bytecode is detected

	std::string name;            ///< name of programming language
	std::string additionalInfo;  ///< some additional information
};

/**
 * All information about used tools
 *
 * If @a entryPointOffset is @c false, value of @a epOffset is undefined.
 * If @a entryPointSection is @c false, values of @a epSection are undefined.
 * If @a entryPointAddress is @c false, values of @a epAddress and @a imageBase are undefined.
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for
 * unsigned integer types.
 */
struct ToolInformation
{
	std::vector<std::string> errorMessages;         ///< error and warning messages
	std::vector<DetectResult> detectedTools;        ///< detected tools (compilers, packers...)
	std::vector<DetectLanguage> detectedLanguages;  ///< detected programming language(s)

	bool entryPointOffset = false;                  ///< @c false if file has no has no or invalid EP offset
	/// entry point offset
	unsigned long long epOffset = std::numeric_limits<unsigned long long>::max();

	bool entryPointAddress = false;                 ///< @c false if file has no has no or invalid EP address
	/// entry point address
	unsigned long long epAddress = std::numeric_limits<unsigned long long>::max();
	/// image base address
	unsigned long long imageBase = std::numeric_limits<unsigned long long>::max();

	/// offset of the file overlay. 0 if no overlay
	unsigned long long overlayOffset = 0;
	size_t overlaySize = 0;                         ///< length of the file overlay. 0 if no overlay

	bool entryPointSection = false;                 ///< @c false if file has no or invalid EP section
	retdec::fileformat::Section epSection;          ///< entry point section
	std::string epBytes;                            ///< hexadecimal representation of entry point bytes

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
};

/**
 * Similarity with signature
 */
struct Similarity
{
	unsigned long long same = 0;   ///< matched number of significant nibbles
	unsigned long long total = 0;  ///< total number of significant nibbles
	double ratio = 0.0;              ///< @a same divided by @a total
};

std::string detectionMetodToString(DetectionMethod method);
std::string toolTypeToString(ToolType toolType);
std::string packedToString(Packed packed);

} // namespace cpdetect
} // namespace retdec

#endif
