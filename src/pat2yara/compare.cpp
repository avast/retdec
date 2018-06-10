/**
 * @file src/pat2yara/compare.cpp
 * @brief Functions for rules comparison.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "pat2yara/compare.h"
#include "pat2yara/utils.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/rule.h"

using namespace yaramod;

namespace {

/**
 * Compare references.
 *
 * @param first first reference string
 * @param other other reference string
 *
 * @return @c true if references are same, @c false otherwise
 */
bool compareReferences(
	const std::string &first,
	const std::string &other)
{
	auto size = first.size() < other.size() ? first.size() : other.size();

	for (std::size_t i = 0; i < size; ++i) {
		if (first[i] != other[i]) {
			// Difference found.
			return false;
		}
	}

	// References are equal or one is prefix of the other.
	return true;
}

/**
 * Compare two rules by their references.
 *
 * If references are missing in one of the patterns function returns @c true as
 * static code detection by references cannot be used.
 *
 * @param firstRule first rule
 * @param otherRule other rule
 *
 * @return @c true if rules have same references, @c false otherwise
 */
bool compareRuleByReferences(
	const Rule* firstRule,
	const Rule* otherRule)
{
	const auto* firstMeta = firstRule->getMetaWithName("refs");
	const auto* otherMeta = otherRule->getMetaWithName("refs");

	if (firstMeta == nullptr || otherMeta == nullptr) {
		return true;
	}

	return compareReferences(firstMeta->getValue().getPureText(),
		otherMeta->getValue().getPureText());
}

/**
 * Compare two patterns in static code detection context.
 *
 * Warning: this is not byte by byte comparison! Wild-cards always match and
 * function also returns @c true when shorter pattern is prefix of longer one.
 *
 * @param firstPattern first pattern
 * @param otherPattern other pattern
 *
 * @return @c true if patterns are same, @c false otherwise
 */
bool comparePatterns(
	const std::shared_ptr<HexString> &firstPattern,
	const std::shared_ptr<HexString> &otherPattern)
{
	const auto &first = firstPattern->getUnits();
	const auto &other = otherPattern->getUnits();

	// Get size of shorter pattern.
	auto size = first.size() < other.size() ? first.size() : other.size();

	for (std::size_t i = 0; i < size; ++i) {
		// Wild-cards do always match.
		if (first[i]->isWildcard() || other[i]->isWildcard()) {
			continue;
		}

		// Application works with input that should not contain jumps nor ORs.
		assert((!first[i]->isJump() && !other[i]->isJump())
			&& "jump in pattern (should not appear in bin2pat output)");
		assert((!first[i]->isOr() && !other[i]->isOr())
			&& "OR in pattern (should not appear in bin2pat output)");

		if (std::static_pointer_cast<HexStringNibble>(first[i])->getValue() !=
			std::static_pointer_cast<HexStringNibble>(other[i])->getValue()) {
			return false;
		}
	}

	// Patterns are equal or the shorter is prefix of the longer pattern.
	// In context of static code detection both cases are equal.
	return true;
}

/**
 * Compare two rules by their pattern.
 *
 * If patterns are missing in both rules, function returns @c true.
 *
 * @param firstRule first rule
 * @param otherRule other rule
 *
 * @return @c true if rules have same patterns, @c false otherwise
 */
bool compareRuleByPatterns(
	const Rule* firstRule,
	const Rule* otherRule)
{
	const auto firstPattern = getHexPattern(firstRule, "$1");
	const auto otherPattern = getHexPattern(otherRule, "$1");

	if (!firstPattern) {
		if (!otherPattern) {
			// Both patterns are undefined.
			return true;
		}
		// Only first pattern is undefined.
		return false;
	}
	if (!otherPattern) {
		// Only second pattern is undefined.
		return false;
	}

	return comparePatterns(firstPattern, otherPattern);
}

/**
 * Compare rules by names.
 *
 * Warning: experiemntal.
 *
 * @param firstRule first rule
 * @param otherRule other rule
 *
 * @return @c true if rules have same names, @c false otherwise
 */
bool compareNames(
	const Rule* firstRule,
	const Rule* otherRule)
{
	const auto* firstMeta = firstRule->getMetaWithName("name");
	const auto* otherMeta = otherRule->getMetaWithName("name");

	if (firstMeta == nullptr || otherMeta == nullptr) {
		return false;
	}

	const auto &first = firstMeta->getValue().getPureText();
	const auto &other = otherMeta->getValue().getPureText();
	return first == other;
}

/**
 * Sort names prediacate.
 *
 * @param firstRule first rule
 * @param otherRule other rule
 *
 * @return @c true if first is less than other, @c false otherwise
 */
bool sortNamesPredicate(
	const Rule* firstRule,
	const Rule* otherRule)
{
	const auto* firstMeta = firstRule->getMetaWithName("name");
	const auto* otherMeta = otherRule->getMetaWithName("name");

	if (firstMeta == nullptr || otherMeta == nullptr) {
		return false;
	}

	const auto &first = firstMeta->getValue().getPureText();
	const auto &other = otherMeta->getValue().getPureText();
	return first < other;
}

} // anonymous namespace

/**
 * Constructor.
 * @param rule base rule
 */
RuleRelations::RuleRelations(
	Rule* rule) : rule(rule)
{
}

/**
 * Get base rule.
 *
 * @return base rule pointer
 */
Rule* RuleRelations::getRule() const
{
	return rule;
}

/**
 * Get equals.
 *
 * @return vector of pointers to rule's equals
 */
std::vector<Rule*> RuleRelations::getEquals() const
{
	return equals;
}

/**
 * Get alternatives.
 *
 * @return vector of pointers to rule's alternatives
 */
std::vector<Rule*> RuleRelations::getAlternatives() const
{
	return alternatives;
}

/**
 * Check whether rule has any equals.
 *
 * @return @c true if rule has equals, @c false otherwise
 */
bool RuleRelations::hasEquals() const
{
	return !equals.empty();
}

/**
 * Check whether rule has any alternatives.
 *
 * @return @c true if rule has alternatives, @c false otherwise
 */
bool RuleRelations::hasAlternatives() const
{
	return !alternatives.empty();
}

/**
 * Check whether rule is equal.
 *
 * @param otherRule rule to compare with
 *
 * @return @c true if @p otherRule is equal, @c false otherwise
 */
bool RuleRelations::isEqual(
	const Rule* otherRule) const
{
	return compareRuleByPatterns(rule, otherRule)
		&& compareRuleByReferences(rule, otherRule);
}

/**
 * Check whether rule is alternative.
 *
 * @param otherRule rule to compare with
 *
 * @return @c true if @p otherRule is alternative, @c false otherwise
 */
bool RuleRelations::isAlternative(
	const Rule* otherRule) const
{
	return compareRuleByPatterns(rule, otherRule)
		&& !compareRuleByReferences(rule, otherRule);
}

/**
 * Check whether rule is related.
 *
 * @param otherRule rule to compare with
 *
 * @return @c true if @p otherRule is related, @c false otherwise
 */
bool RuleRelations::isEqualOrAlternative(
	const Rule* otherRule) const
{
	return compareRuleByPatterns(rule, otherRule);
}

/**
 * Filter out duplicates in alternatives.
 */
void RuleRelations::makeAlternativesUniq()
{
	std::sort(alternatives.begin(), alternatives.end(), sortNamesPredicate);
	auto it = std::unique(alternatives.begin(), alternatives.end(),
		[](Rule* first, Rule* other) {
			return compareNames(first, other)
				&& compareRuleByReferences(first, other);
		});

	alternatives.resize(std::distance(alternatives.begin(), it));
}

/**
 * Add new relation for rule.
 *
 * If rule is unrelated add nothing and return false.
 *
 * @param otherRule rule to add if related
 *
 * @return @c true if rule is related and was added, @c false otherwise
 */
bool RuleRelations::add(
	Rule* otherRule)
{
	if (compareRuleByPatterns(rule, otherRule)) {
		// Patterns are same.
		if (compareRuleByReferences(rule, otherRule)) {
			if (!compareNames(rule, otherRule)) {
				// Add to equals only if names are different.
				equals.push_back(otherRule);
			}
		}
		else {
			alternatives.push_back(otherRule);
		}

		return true;
	}

	return false;
}

/**
 * Create vector of relations from rules.
 *
 * @param rules input rules
 *
 * @return vector of rule relations
 */
std::vector<RuleRelations> getRuleRelationsFromRules(
	const std::vector<std::unique_ptr<Rule>> &rules)
{
	std::vector<RuleRelations> results;

	for (const auto &rule : rules) {
		// Look for related rules.
		bool foundRelation = false;
		for (auto &relation : results) {
			if (relation.add(rule.get())) {
				// Related rule was found.
				foundRelation = true;
				break;
			}
		}

		// Create new entry if no related rule was found.
		if (!foundRelation) {
			results.emplace_back(RuleRelations(rule.get()));
		}
	}

	for (auto &result : results) {
		result.makeAlternativesUniq();
	}

	return results;
}
