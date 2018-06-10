/**
 * @file src/cpdetect/cptypes.cpp
 * @brief cpdetectl types and structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/cptypes.h"

namespace retdec {
namespace cpdetect {

/**
 * Constructor of DetectParams structure
 */
DetectParams::DetectParams(SearchType searchType_, bool internal_, bool external_, std::size_t epBytesCount_) :
		searchType(searchType_), internal(internal_), external(external_), epBytesCount(epBytesCount_)
{

}

/**
 * Destructor of DetectParams structure
 */
DetectParams::~DetectParams()
{

}

/**
 * Constructor of DetectResult structure
 */
DetectResult::DetectResult()
{

}

/**
 * Destructor of DetectResult structure
 */
DetectResult::~DetectResult()
{

}

/**
 * Check if result is reliable
 * @return @c true if detected result is reliable, @c false otherwise
 */
bool DetectResult::isReliable() const
{
	return source != DetectionMethod::UNKNOWN && strength > DetectionStrength::MEDIUM;
}

/**
 * Check if result is compiler
 * @return @c true if detected result is compiler, @c false otherwise
 */
bool DetectResult::isCompiler() const
{
	return type == ToolType::COMPILER;
}

/**
 * Check if result is linker
 * @return @c true if detected result is linker, @c false otherwise
 */
bool DetectResult::isLinker() const
{
	return type == ToolType::LINKER;
}

/**
 * Check if result is installer
 * @return @c true if detected result is installer, @c false otherwise
 */
bool DetectResult::isInstaller() const
{
	return type == ToolType::INSTALLER;
}

/**
 * Check if result is packer
 * @return @c true if detected result is packer, @c false otherwise
 */
bool DetectResult::isPacker() const
{
	return type == ToolType::PACKER;
}

/**
 * Check if result is know tool type
 * @return @c true if detected result is known type, @c false otherwise
 */
bool DetectResult::isKnownType() const
{
	return type != ToolType::UNKNOWN;
}

/**
 * Check if result is unknow tool type
 * @return @c true if detected result is unknown type, @c false otherwise
 */
bool DetectResult::isUnknownType() const
{
	return type == ToolType::UNKNOWN;
}

/**
 * Constructor of DetectLanguage structure
 */
DetectLanguage::DetectLanguage() : bytecode(false)
{

}

/**
 * Destructor of DetectLanguage structure
 */
DetectLanguage::~DetectLanguage()
{

}

/**
 * Constructor of CompilerInformation structure
 */
ToolInformation::ToolInformation()
	: epOffset(std::numeric_limits<unsigned long long>::max()),
		epAddress(std::numeric_limits<unsigned long long>::max()),
		imageBase(std::numeric_limits<unsigned long long>::max())
{

}

/**
 * Destructor of CompilerInformation structure
 */
ToolInformation::~ToolInformation()
{

}

/**
 * Add detected tool
 * @param source Used detection method
 * @param strength Strength of detection method
 * @param toolType Type of detected tool
 * @param name Name of detected compiler
 * @param version Version of detected compiler
 * @param extra Extra information about compiler
 */
void ToolInformation::addTool(
		DetectionMethod source, DetectionStrength strength, ToolType toolType,
		const std::string &name, const std::string &version, const std::string &extra)
{
	DetectResult compiler;
	compiler.source = source;
	compiler.strength = strength;

	compiler.type = toolType;
	compiler.name = name;
	compiler.versionInfo = version;
	compiler.additionalInfo = extra;
	detectedTools.push_back(compiler);
}

/**
 * Save all information about detected compiler
 * @param matchNibbles Number of significant nibbles agreeing with file content
 * @param totalNibbles Total number of significant nibbles of signature
 * @param toolType Type of detected tool
 * @param name Name of detected compiler
 * @param version Version of detected compiler
 * @param extra Extra information about compiler
 *
 * This method implies DetectionMethod::SIGNATURE. Strength is computed.
 */
void ToolInformation::addTool(
		std::size_t matchNibbles, std::size_t totalNibbles, ToolType toolType,
		const std::string &name, const std::string &version, const std::string &extra)
{
	DetectResult compiler;
	compiler.source = DetectionMethod::SIGNATURE;
	compiler.strength = DetectionStrength::MEDIUM;
	compiler.impCount = totalNibbles;
	compiler.agreeCount = matchNibbles;

	// Compute strength
	if (totalNibbles != matchNibbles)
	{
		// Only partial match - very unreliable
		compiler.strength = DetectionStrength::LOW;
	}
	else if (matchNibbles > 32)
	{
		// We need at least 16B to consider signature reliable
		compiler.strength = DetectionStrength::HIGH ;
	}

	compiler.type = toolType;
	compiler.name = name;
	compiler.versionInfo = version;
	compiler.additionalInfo = extra;
	detectedTools.push_back(compiler);
}

/**
 * Save all information about detected language
 * @param name Name of detected language
 * @param extra Extra information about detected language
 * @param bytecode Whether language uses byte-code
 */
void ToolInformation::addLanguage(const std::string &name, const std::string &extra, bool bytecode)
{
	// Prevent duplicates.
	for(auto &item : detectedLanguages)
	{
		if(item.name == name)
		{
			if(item.additionalInfo.empty() || item.additionalInfo == extra)
			{
				if(!item.bytecode)
				{
					item.bytecode = bytecode;
				}
				item.additionalInfo = extra;
				return;
			}
		}
	}

	DetectLanguage language;
	language.name = name;
	language.additionalInfo = extra;
	language.bytecode = bytecode;
	detectedLanguages.push_back(language);
}

/**
 * Check out if detected result is reliable
 * @param resultIndex Index of selected result
 * @return @c true if selected result is detected based on reliable source, @c false otherwise
 */
bool ToolInformation::isReliableResult(std::size_t resultIndex) const
{
	return (resultIndex < detectedTools.size()) ? detectedTools[resultIndex].isReliable() : false;
}

/**
 * Check if at least one reliable result was detected
 * @return @c true if at least one reliable result was detected, @c false otherwise
 */
bool ToolInformation::hasReliableResult() const
{
	for(std::size_t i = 0, e = detectedTools.size(); i < e; ++i)
	{
		if(isReliableResult(i))
		{
			return true;
		}
	}

	return false;
}

/**
 * Check possible packing
 * @return detection level of possible packing
 */
Packed ToolInformation::isPacked() const
{
	bool detectedPacker = false;
	DetectionStrength strength = DetectionStrength::LOW;

	for (const auto &tool : detectedTools)
	{
		if (tool.isPacker())
		{
			detectedPacker = true;
			strength = strength > tool.strength ? strength : tool.strength;
		}
	}

	if (!detectedPacker)
	{
		/// @todo add entropy computation
		return Packed::PROBABLY_NO;
	}

	switch (strength)
	{
		case DetectionStrength::LOW:
			return Packed::PROBABLY_YES;

		case DetectionStrength::MEDIUM:
		case DetectionStrength::HIGH:
		case DetectionStrength::SURE:
		/* fall-thru */

		default:
			return Packed::PACKED;
	}
}

/**
 * Constructor of Similarity structure
 */
Similarity::Similarity() : same(0), total(0), ratio(0.0)
{

}

/**
 * Destructor of Similarity structure
 */
Similarity::~Similarity()
{

}

/**
 * Get detection method name as string
 * @param method method type
 * @return method name
 */
std::string detectionMetodToString(DetectionMethod method)
{
	switch (method) {
		case DetectionMethod::SIGNATURE:
			return "signature";

		case DetectionMethod::COMBINED:
			return "combined heuristic";

		case DetectionMethod::DWARF_DEBUG_H:
			return "DWARF heuristic";

		case DetectionMethod::SECTION_TABLE_H:
			return "section table heuristic";

		case DetectionMethod::IMPORT_TABLE_H:
			return "import table heuristic";

		case DetectionMethod::EXPORT_TABLE_H:
			return "export table heuristic";

		case DetectionMethod::SYMBOL_TABLE_H:
			return "symbol table heuristic";

		case DetectionMethod::LINKER_VERSION_H:
			return "linker version heuristic";

		case DetectionMethod::LINKED_LIBRARIES_H:
			return "linker libraries heuristic";

		case DetectionMethod::STRING_SEARCH_H:
			return "strings heuristic";

		case DetectionMethod::DYNAMIC_ENTRIES_H:
			return ".dynamic section heuristic";

		case DetectionMethod::COMMENT_H:
			return ".comment section heuristic";

		case DetectionMethod::NOTE_H:
			return ".note section heuristic";

		case DetectionMethod::MANIFEST_H:
			return "manifest heuristic";

		case DetectionMethod::OTHER_H:
			return "heuristic";

		case DetectionMethod::UNKNOWN:
			/* fall-thru */

		default:
			return "unknown detection method";
	}
}

/**
 * Get tool type name from type
 * @param toolType type
 * @return type as string
 */
std::string toolTypeToString(ToolType toolType)
{
	switch (toolType) {
		case ToolType::COMPILER:
			return "compiler";

		case ToolType::PACKER:
			return "packer";

		case ToolType::INSTALLER:
			return "installer";

		case ToolType::LINKER:
			return "linker";

		case ToolType::OTHER:
			return "other tool";

		case ToolType::UNKNOWN:
			/* fall-thru */

		default:
			return "unknown";
	}
}

/**
 * Get packing info string from packing info
 * @param packed packings info
 * @return packing info as string
 */
std::string packedToString(Packed packed)
{
	switch (packed) {
		case Packed::NOT_PACKED:
			return "No";

		case Packed::PACKED:
			return "Yes";

		case Packed::PROBABLY_YES:
			return "Probably yes";

		case Packed::PROBABLY_NO:
			/* fall-thru */

		default:
			return "Probably no";
	}
}

} // namespace cpdetect
} // namespace retdec
