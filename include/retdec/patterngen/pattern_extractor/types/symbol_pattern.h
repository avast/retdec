/**
 * @file include/retdec/patterngen/pattern_extractor/types/symbol_pattern.h
 * @brief Class representing pattern of one function.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PATTERNGEN_PATTERN_EXTRACTOR_TYPES_SYMBOL_PATTERN_H
#define RETDEC_PATTERNGEN_PATTERN_EXTRACTOR_TYPES_SYMBOL_PATTERN_H

#include <ostream>
#include <string>
#include <vector>

#include "yaramod/builder/yara_hex_string_builder.h"

// Forward declarations.
namespace yaramod {
	class YaraFileBuilder;
} // namespace yaramod

namespace retdec {
namespace patterngen {

using Meta = std::pair<std::string, std::string>;

/**
 * Pattern for one symbol.
 */
class SymbolPattern
{
	private:
		/**
		 * Internal structure representing one reference/relocation.
		 */
		struct Reference
		{
			std::string name;               ///< Name of referenced symbol.
			std::size_t offset;             ///< Offset to symbol data.
			std::vector<std::uint8_t> mask; ///< Relocation mask.
		};

		// Raw data.
		bool isLittle;                  ///< Endianness.
		std::size_t bitWidth;           ///< Word length.
		std::vector<Reference> refs;    ///< References.
		std::vector<std::uint8_t> data; ///< Symbol data.

		// String metas.
		std::string symbolName;  ///< Symbol name.
		std::string ruleName;    ///< Rule name.
		std::vector<Meta> metas; ///< Other optional metas.

		/// @brief Data formatting methods.
		/// @{
		std::string getReferenceString() const;
		std::shared_ptr<yaramod::HexString> getHexPattern() const;
		void createBytePattern(std::uint8_t mask, std::uint8_t byte,
				yaramod::YaraHexStringBuilder &builder) const;
		/// @}

	public:
		/// @brief Constructors and destructor.
		/// @{
		SymbolPattern(bool isLittleEndian, std::size_t wordBitWidth);
		~SymbolPattern();
		/// @}

		/// @brief Setters.
		/// @{
		void setName(const std::string &symbolName);
		void setRuleName(const std::string &ruleName);
		void setSourcePath(const std::string &filePath);
		void setArchitectureName(const std::string &archName);
		/// @}

		/// @brief Loading methods.
		/// @{
		void loadData(std::vector<unsigned char> &&symbolData);
		void loadData(const std::vector<unsigned char> &symbolData);
		void addReference(const std::string &refName, const std::size_t &offset,
			const std::vector<std::uint8_t> &mask);
		/// @}

		/// @brief Output methods.
		/// @{
		void printYaraRule(std::ostream &outputStream,
			const std::string &withNote = "") const;
		void addRuleToBuilder(yaramod::YaraFileBuilder &yaraBuilder,
			const std::string &withNote = "") const;
		/// @}
};

} // namespace patterngen
} // namespace retdec

#endif
