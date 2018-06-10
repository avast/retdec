/**
 * @file src/pat2yara/utils.cpp
 * @brief Auxiliary functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <set>

#include "pat2yara/utils.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/rule.h"

using namespace yaramod;

/**
 * Get hexadecimal pattern from rule.
 *
 * @param rule input rule
 * @param name name of pattern
 *
 * @return pointer to hexadecimal pattern
 */
std::shared_ptr<HexString> getHexPattern(
	const Rule* rule,
	const std::string &name)
{
	std::shared_ptr<String> pattern;

	if (rule->getStringsTrie()->find(name , pattern) && pattern->isHex()) {
		return std::static_pointer_cast<HexString>(pattern);
	}

	return std::shared_ptr<HexString>(nullptr);
}

/**
 * Get function name from rule.
 *
 * @param rule input rule
 *
 * @return string with function name
 */
std::string getName(
		const Rule *rule)
{
	auto* nameMeta = rule->getMetaWithName("name");
	if (nameMeta) {
		return nameMeta->getValue().getPureText();
	}

	return std::string();
}

/**
 * Collect names of rules into a string.
 *
 * @param rules input rules
 *
 * @return string with names of input rules
 */
std::string collectNames(
	const std::vector<Rule*>& rules)
{
	std::set<std::string> names;
	for (const Rule* rule : rules) {
		auto* nameMeta = rule->getMetaWithName("name");
		if (nameMeta) {
			names.insert(nameMeta->getValue().getPureText());
		}
	}

	std::string result;
	for (const auto &name : names) {
		result += name + " ";
	}

	// Pop last space.
	if (!result.empty()) {
		result.pop_back();
	}

	return result;
}
