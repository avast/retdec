/**
 * @file src/pat2yara/modifications.h
 * @brief Rule manipulation functions for yara patterns filter.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef PAT2YARA_MODIFICATIONS_H
#define PAT2YARA_MODIFICATIONS_H

#include <memory>

// Forward declarations.
namespace yaramod {

	class HexString;
	class Rule;
	class YaraRuleBuilder;
	class YaraFileBuilder;

} // namespace yaramod

class RuleRelations;

/**
 * Yara buffer limit.
 */
constexpr std::size_t YARA_BUF_SIZE = 8000;

std::unique_ptr<yaramod::Rule> createArchitectureRule(
	const yaramod::Rule* rule);

std::unique_ptr<yaramod::Rule> createLogRule(
	const yaramod::Rule* rule,
	const std::string &reason);

std::shared_ptr<yaramod::HexString> cutHexString(
	const std::shared_ptr<yaramod::HexString> &hexString,
	std::size_t limit);

std::string cutStringWhitespace(
	const std::string &inputString,
	std::size_t limit);

void filterMetaSection(
	yaramod::YaraRuleBuilder &builder,
	const yaramod::Rule* rule);

void copyRuleToBuilder(
	yaramod::YaraRuleBuilder &builder,
	const yaramod::Rule* rule);

void packDelhpi(
	yaramod::YaraFileBuilder &builder,
	const RuleRelations &alternativeRules);

#endif
