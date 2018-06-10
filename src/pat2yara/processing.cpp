/**
 * @file src/pat2yara/processing.cpp
 * @brief File processing.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "pat2yara/compare.h"
#include "pat2yara/logic.h"
#include "pat2yara/modifications.h"
#include "pat2yara/processing.h"
#include "pat2yara/utils.h"
#include "yaramod/builder/yara_expression_builder.h"
#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/yaramod.h"

using namespace yaramod;

namespace
{

// Yara library pattern size limit.
const std::size_t YARA_PATTERN_LIMIT = 4096;

/**
 * Filter rules from file.
 *
 * @param file input YaraFile
 * @param fIndex input file index
 * @param options filter options
 * @param logBuilder log-file builder
 * @param rules container for results
 */
void filterRulesFromFile(
	const std::unique_ptr<YaraFile> &file,
	const std::size_t fIndex,
	const ProcessingOptions &options,
	YaraFileBuilder &logBuilder,
	std::vector<std::unique_ptr<Rule>> &rules)
{
	for (const auto &rule : file->getRules())
	{
		// Get function pattern from rule.
		const auto hPattern = getHexPattern(rule.get(), "$1");
		if (!hPattern) {
			if (options.logOn) {
				logBuilder.withRule(createLogRule(rule.get(),
					"missing pattern"));
			}
			continue;
		}

		// Consider possible NOPs.
		std::size_t trailing = 0;
		if (options.ignoreNops) {
			trailing = getTrailingNopSize(hPattern, options.nopOpcode);
		}

		// Check for minimal size restriction.
		if (options.minSize &&
				getHexStringSize(hPattern) - trailing < options.minSize) {
			if (options.logOn) {
				logBuilder.withRule(createLogRule(rule.get(),
					"pattern too small"));
			}
			continue;
		}

		// Check pure information length limit.
		std::size_t pureSize = getPureInformationSize(hPattern);
		std::size_t relocationInfo = getNamedRelocationCount(rule.get()) * 4;

		if (pureSize < 4) {
			// Rules with almost no invariable bytes.
			if (options.logOn) {
				logBuilder.withRule(createLogRule(rule.get(),
					"not enough pure information"));
			}
			continue;
		}

		if (pureSize + relocationInfo < options.minPure + trailing) {
			if (options.logOn) {
				logBuilder.withRule(createLogRule(rule.get(),
					"not enough pure information"));
			}
			continue;
		}

		// Filter out functions with problematic names.
		if (nameFilter(rule.get())) {
			if (options.logOn) {
				logBuilder.withRule(createLogRule(rule.get(),
					"problematic function name"));
			}
			continue;
		}

		// Create builder and copy name.
		YaraRuleBuilder ruleBuilder;
		ruleBuilder.withName(rule->getName() + "_" + std::to_string(fIndex));
		filterMetaSection(ruleBuilder, rule.get());

		// Cut hex strings that are too long.
		ruleBuilder.withHexString("$1",
			cutHexString(hPattern, options.maxSize));
		ruleBuilder.withCondition(stringRef("$1").get());

		// Add new rule.
		rules.emplace_back(ruleBuilder.get());
	}
}

} // anonymous namespace

/**
 * Validate user options.
 *
 * @param error will be set to error message if options are invalid
 *
 * @return @c true if options are valid, @c false otherwise
 */
bool ProcessingOptions::validate(
	std::string &error)
{
	if (!maxSize || maxSize > YARA_PATTERN_LIMIT) {
		// Rule bigger than Yara limit will not work.
		maxSize = YARA_PATTERN_LIMIT;
	}

	if (input.empty()) {
		error = "no input file";
		return false;
	}
	if (minSize > maxSize) {
		error = "--min-size value is greater than --max-size value";
		return false;
	}
	if (minPure > maxSize) {
		error = "--min-pure value is greater than --max-size value";
		return false;
	}

	return true;
}

/**
 * Process all input files.
 *
 * @param fileBuilder output file builder
 * @param logBuilder log-file builder
 * @param options filter options
 */
void processFiles(
	YaraFileBuilder &fileBuilder,
	YaraFileBuilder &logBuilder,
	const ProcessingOptions &options)
{
	bool firstFile = true;
	std::vector<std::unique_ptr<Rule>> rules;

	std::size_t counter = 0;
	for (const auto &file : options.input) {
		// Parse file.
		auto yaraFile = parseFile(file);

		// Add architecture info rule.
		if (firstFile) {
			auto &originalRules = yaraFile->getRules();
			if (!originalRules.empty()) {
				fileBuilder.withRule(createArchitectureRule(originalRules[0].get()));
				firstFile = false;
			}
		}

		// Filter out input rules.
		filterRulesFromFile(yaraFile, counter++, options, logBuilder, rules);
	}

	for (const auto &ruleRelations : getRuleRelationsFromRules(rules)) {
		if (ruleRelations.hasEquals()) {
			if (options.isDelphi) {
				// Special aproach for Delphi.
				packDelhpi(fileBuilder, ruleRelations);
			}
			else {
				YaraRuleBuilder newRule;
				copyRuleToBuilder(newRule, ruleRelations.getRule());
				std::string names = collectNames(ruleRelations.getEquals());
				newRule.withStringMeta("altNames",
					cutStringWhitespace(names, YARA_BUF_SIZE));
				fileBuilder.withRule(newRule.get());
			}
		}
		else {
			fileBuilder.withRule(std::move(*(ruleRelations.getRule())));
		}

		// Add alternatives.
		for (auto *alternative : ruleRelations.getAlternatives()) {
			fileBuilder.withRule(std::move(*(alternative)));
		}
	}
}
