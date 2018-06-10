/**
 * @file src/pat2yara/modifications.cpp
 * @brief Rule manipulation functions for yara patterns filter.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <set>

#include "pat2yara/compare.h"
#include "pat2yara/modifications.h"
#include "pat2yara/utils.h"
#include "yaramod/builder/yara_expression_builder.h"
#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/types/rule.h"

using namespace yaramod;

namespace
{

/**
 * Delphi (template) function represenation.
 *
 * E.g. Class<Type>.Method will be stored as class-method pair, ignoring type,
 * if funtion is template function Function<Type> it will be stored as Function
 * with '<' character in method position to differ with non-template functions.
 */
using TemplatePair = std::pair<std::string, std::string>;

/**
 * Split (template) function definition to TemplatePair type.
 *
 * @param name function definition (name attribute)
 *
 * @return new TemplatePair
 */
TemplatePair getTemplatePair(
	const std::string &name)
{
	const auto first = name.find_first_of('<');
	const auto last = name.find_last_of('>');

	if (first == std::string::npos || last == std::string::npos) {
		// Simple non-template function.
		return TemplatePair(name, "");
	}

	std::string firstName = name.substr(0, first);
	if (last == name.size() - 1) {
		// Rightmost '>' is last character - template function.
		return TemplatePair(firstName, "<");
	}

	// Skip dot symbol too so +2.
	return TemplatePair(firstName, name.substr(last + 2, std::string::npos));
}

} // anonymous namespace

/**
 * Create architecture rule from another rule.
 *
 * @param rule source rule (usually first rule from input file)
 *
 * @return private empty rule with architecture information only
 */
std::unique_ptr<Rule> createArchitectureRule(
	const yaramod::Rule* rule)
{
	YaraRuleBuilder builder;
	builder.withName("architecture");
	builder.withModifier(Rule::Modifier::Private);

	for (const Meta &meta : rule->getMetas()) {
		const auto &key = meta.getKey();
		const auto &value = meta.getValue().getPureText();

		if (key == "architecture") {
			builder.withStringMeta("architecture", value);
			continue;
		}
		if (key == "endianness") {
			builder.withStringMeta("endianness", value);
			continue;
		}
		if (key == "bitWidth") {
			const auto width = std::stoi(meta.getValue().getText());
			builder.withIntMeta("bits", width);
		}
	}

	return builder.get();
}

/**
 * Create log-file rule from another rule.
 *
 * @param rule source rule (usually rule that is being removed)
 * @param reason reason of rule being removed
 *
 * @return rule for log-file
 */
std::unique_ptr<Rule> createLogRule(
	const yaramod::Rule *rule,
	const std::string &reason = "")
{
	YaraRuleBuilder ruleBuilder;
	ruleBuilder.withName(rule->getName());

	for (const Meta &meta : rule->getMetas()) {
		const auto &key = meta.getKey();
		const auto &value = meta.getValue().getPureText();

		if (key == "name") {
			ruleBuilder.withStringMeta("name", value);
			continue;
		}
		if (key == "refs") {
			ruleBuilder.withStringMeta("refs", value);
			continue;
		}
		if (key == "source") {
			ruleBuilder.withStringMeta("source", value);
		}
	}
	if (!reason.empty()) {
		ruleBuilder.withStringMeta("reason", reason);
	}
	ruleBuilder.withHexString("$1", getHexPattern(rule, "$1"));
	ruleBuilder.withCondition(boolVal(false).get());

	return ruleBuilder.get();
}

/**
 * Create new HexString with limited size.
 *
 * @param hexString original HexString
 * @param limit maximal size in bytes
 *
 * @return shortened HexString
 */
std::shared_ptr<HexString> cutHexString(
	const std::shared_ptr<HexString> &hexString,
	std::size_t limit)
{
	// Multiply limit by two as HexString works with nibbles.
	std::size_t nibbleLimit = limit * 2;

	if (hexString->getLength() > nibbleLimit) {
		const auto old = hexString->getUnits();
		std::vector<std::shared_ptr<HexStringUnit>> newUnits(old.begin(),
			old.begin() + nibbleLimit);

		// Create new hexadecimal string.
		return std::make_shared<HexString>(newUnits);
	}

	// String is already shorter than limit.
	return hexString;
}

/**
 * Cut string before limit but on whitespace.
 *
 * @param inputString original string
 * @param limit maximal string size
 *
 * @return shortened string
 */
std::string cutStringWhitespace(
	const std::string &inputString,
	std::size_t limit)
{
	if (inputString.size() < limit) {
		// No cut necessary.
		return inputString;
	}

	const auto last = inputString.find_last_of(' ', limit);
	if (last == std::string::npos) {
		// Cut anyway (should not happend in correct input).
		return inputString.substr(0, limit);
	}

	// Cut on position of last within limit.
	return inputString.substr(0, last);
}

/**
 * Add necessary meta attributes to new rule builder.
 *
 * @param builder target rule builder
 * @param rule source rule
 */
void filterMetaSection(
	YaraRuleBuilder &builder,
	const Rule* rule)
{
	for (const Meta &meta : rule->getMetas()) {
		const auto &key = meta.getKey();
		const auto &value = meta.getValue().getPureText();

		if (key == "name") {
			builder.withStringMeta("name", value);
			continue;
		}
		if (key == "note") {
			builder.withStringMeta("note", value);
			continue;
		}
		if (key == "refs") {
			builder.withStringMeta("refs",
				cutStringWhitespace(value, YARA_BUF_SIZE));
			continue;
		}
		if (key == "size") {
			builder.withIntMeta("size", std::stoi(meta.getValue().getText()));
		}
	}
}

/**
 * Copy rule to new builder.
 *
 * Only metas copied are name, size, note and references (cut to refs).
 *
 * @param builder target rule builder
 * @param rule source rule
 */
void copyRuleToBuilder(
	YaraRuleBuilder &builder,
	const Rule* rule)
{
	filterMetaSection(builder, rule);
	builder.withName(rule->getName());
	builder.withHexString("$1", getHexPattern(rule, "$1"));
	builder.withCondition(stringRef("$1").get());
}

/**
 * Pack Delphi template names to simple format Class<T>.Method or similar.
 * @param builder target for final rule
 * @param alternativeRules rule with name and its alternatives
 */
void packDelhpi(
	yaramod::YaraFileBuilder &builder,
	const RuleRelations &alternativeRules)
{
	if (!alternativeRules.hasEquals()) {
		return;
	}

	// Pointer to main rule.
	const auto* mainRule = alternativeRules.getRule();

	// Strip types from templates.
	std::set<TemplatePair> templates;
	templates.insert(getTemplatePair(getName(mainRule)));
	for (const auto &rule : alternativeRules.getEquals()) {
		templates.insert(getTemplatePair(getName(rule)));
	}

	// Create declarations.
	std::vector<std::string> functions;
	for (auto it = templates.cbegin(), e = templates.cend(); it != e; ++it) {
		if (it->second.empty()) {
			functions.emplace_back(it->first);
		}
		else if (it->second == "<") {
			functions.emplace_back(it->first + "<T>");
		}
		else {
			functions.emplace_back(it->first + "<T>." + it->second);
		}
	}

	YaraRuleBuilder newRule;
	newRule.withName(mainRule->getName());
	newRule.withStringMeta("name", functions[0]);

	// Copy meta section but without name.
	for (const Meta &meta : mainRule->getMetas()) {
		const auto &key = meta.getKey();
		const auto &value = meta.getValue().getPureText();

		if (key == "note") {
			newRule.withStringMeta("note", value);
			continue;
		}
		if (key == "refs") {
			// Already shortened - no cut necessary.
			newRule.withStringMeta("refs", value);
			continue;
		}
		if (key == "size") {
			newRule.withIntMeta("size", std::stoi(meta.getValue().getText()));
		}
	}
	newRule.withHexString("$1", getHexPattern(mainRule, "$1"));
	newRule.withCondition(mainRule->getCondition());

	// Collect alternative templates if any.
	std::string alternatives;
	for (std::size_t i = 1; i < functions.size(); ++i) {
		alternatives += functions[i] + " ";
	}

	if (!alternatives.empty()) {
		alternatives.pop_back();
		newRule.withStringMeta("altNames",
			cutStringWhitespace(alternatives, YARA_BUF_SIZE));
	}

	builder.withRule(newRule.get());
}
