/**
 * @file src/patterngen/pattern_extractor/types/symbol_pattern.cpp
 * @brief Class representing pattern of one symbol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <set>

#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/patterngen/pattern_extractor/types/symbol_pattern.h"
#include "yaramod/builder/yara_expression_builder.h"
#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/builder/yara_rule_builder.h"

using namespace retdec::utils;
using namespace yaramod;

namespace retdec {
namespace patterngen {

/**
 * Format string of references as offset-name pairs.
 *
 * @return string with references
 */
std::string SymbolPattern::getReferenceString() const
{
	std::string result;
	std::vector<std::string> used;
	for (const auto &ref : refs) {
		// Accept only valid C language identifiers.
		if (!ref.name.empty() && isPrintable(ref.name)) {
			// Only first reference is printed.
			if (!hasItem(used, ref.name)) {
				result += toHex(ref.offset, false, 4) + " " + ref.name + " ";
				used.push_back(ref.name);
			}
		}
	}
	if (!result.empty()) {
		// Pop space after last reference name.
		result.pop_back();
	}

	return result;
}

/**
 * Get hexadecimal pattern.
 *
 * @return shared pointer to HexString pattern
 */
std::shared_ptr<HexString> SymbolPattern::getHexPattern() const
{
	YaraHexStringBuilder patternBuilder;

	// Create relocation map (no relocations by default - 0x00).
	std::vector<std::uint8_t> relocMap(data.size(), 0x00);
	for (const auto &r : refs) {
		for (std::size_t i = 0, e = r.mask.size(); i < e; ++i) {
			// We have to read mask in reverse order if big endian.
			relocMap[r.offset + i] |= isLittle ? r.mask[i] : r.mask[e - i - 1];
		}
	}

	// Create hexadecimal pattern.
	for (std::size_t i = 0, e = data.size(); i < e; ++i) {
		createBytePattern(relocMap[i], data[i], patternBuilder);
	}

	return patternBuilder.get();
}

/**
 * Create pattern for one byte.
 *
 * @param mask relocation mask
 * @param byte source byte
 * @param builder builder to add byte pattern to
 */
void SymbolPattern::createBytePattern(
	std::uint8_t mask,
	std::uint8_t byte,
	YaraHexStringBuilder &builder) const
{
	if (!mask) {
		// No mask - no relocation.
		builder.add(byte);
		return;
	}

	if (mask & 0xF0) {
		if (mask & 0x0F) {
			// Both high and low nibbles are relocated - full wildcard.
			builder.add(wildcard());
		}
		else {
			// Only high nibble is affected.
			builder.add(wildcardHigh(byte & 0x0F));
		}
	}
	else {
		// Only low nibble is affected.
		builder.add(wildcardLow((byte & 0xF0) >> 4));
	}
}

/**
 * Default constructor.
 *
 * @param isLittleEndian byte endianness
 * @param wordBitWidth word length in bits
 */
SymbolPattern::SymbolPattern(
	bool isLittleEndian,
	std::size_t wordBitWidth)
	: isLittle(isLittleEndian), bitWidth(wordBitWidth)
{
}

/**
 * Default destructor.
 */
SymbolPattern::~SymbolPattern()
{
}

/**
 * Set symbol name.
 *
 * If not provided, string 'unknown_symbol' is used.
 *
 * @param symbolName name of symbol
 */
void SymbolPattern::setName(
	const std::string &symbolName)
{
	this->symbolName = symbolName;
}

/**
 * Set rule name.
 *
 * If not provided, string 'unknown_rule' is used. Only alpha-numeric chars are
 * allowed, others are replaced with underscore.
 *
 * @param ruleName name of rule
 */
void SymbolPattern::setRuleName(
	const std::string &ruleName)
{
	this->ruleName = replaceNonalnumCharsWith(ruleName, '_');
}

/**
 * Set source path.
 *
 * If not provided, attribute is omitted.
 *
 * @param filePath path to source file
 */
void SymbolPattern::setSourcePath(
	const std::string &filePath)
{
	metas.emplace_back("source", filePath);
}

/**
 * Set architecture name path.
 *
 * If not provided, attribute is omitted.
 *
 * @param archName architecture name
 */
void SymbolPattern::setArchitectureName(
	const std::string &archName)
{
	metas.emplace_back("architecture", archName);
}

/**
 * Load symbol data by move.
 *
 * @param symbolData symbol data
 */
void SymbolPattern::loadData(
	std::vector<unsigned char> &&symbolData)
{
	data = std::move(symbolData);
}

/**
 * Load symbol data.
 *
 * @param symbolData symbol data
 */
void SymbolPattern::loadData(
	const std::vector<unsigned char> &symbolData)
{
	data = symbolData;
}

/**
 * Add one symbol relocation/reference.
 *
 * @param refName name of referenced symbol
 * @param offset offset of reference in symbol data
 * @param mask relocation mask vector
 */
void SymbolPattern::addReference(
	const std::string &refName,
	const std::size_t &offset,
	const std::vector<std::uint8_t> &mask)
{
	refs.push_back(Reference{refName, offset, mask});
}

/**
 * Print pattern as YARA rule to stream.
 *
 * @param outputStream stream to print information to
 * @param withNote optional note that will be added to the rule
 */
void SymbolPattern::printYaraRule(
	std::ostream &outputStream,
	const std::string &withNote) const
{
	if (data.empty()) {
		return;
	}

	YaraFileBuilder newFile;
	addRuleToBuilder(newFile, withNote);

	outputStream << newFile.get(false)->getText() << "\n";
}

/**
 * Add pattern to yaramod file builder.
 *
 * @param yaraBuilder builder to add rule to
 * @param withNote optional note that will be added to the rule
 */
void SymbolPattern::addRuleToBuilder(
	YaraFileBuilder &yaraBuilder,
	const std::string &withNote) const
{
	YaraRuleBuilder ruleBuilder;

	// Names.
	ruleBuilder.withName(ruleName.empty() ? "unknown_rule" : ruleName);
	ruleBuilder.withStringMeta("name",
		symbolName.empty() ? "unknown_symbol" : symbolName);

	// Basic architecture info.
	ruleBuilder.withIntMeta("size", data.size());
	ruleBuilder.withIntMeta("bitWidth", bitWidth);
	ruleBuilder.withStringMeta("endianness", isLittle ? "little" : "big");

	// Optional metas.
	for (const auto &meta : metas) {
		ruleBuilder.withStringMeta(meta.first, meta.second);
	}

	// Optional notes.
	if (!withNote.empty()) {
		ruleBuilder.withStringMeta("notes", withNote);
	}

	// Condition.
	ruleBuilder.withHexString("$1", getHexPattern());
	ruleBuilder.withCondition(stringRef("$1").get());

	// References.
	auto refList = getReferenceString();
	if (!refList.empty()) {
		ruleBuilder.withStringMeta("refs", refList);
	}

	yaraBuilder.withRule(ruleBuilder.get());
}

} // namespace patterngen
} // namespace retdec
