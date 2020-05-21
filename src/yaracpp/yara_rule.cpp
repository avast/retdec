/**
 * @file src/yaracpp/yara_rule.cpp
 * @brief Library representation of one YARA rule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/yaracpp/yara_rule.h"

#include <ostream>

namespace retdec {
namespace yaracpp {

/**
 * Get name related to this rule
 * @return Name of rule
 */
const std::string &YaraRule::getName() const
{
	return name;
}

/**
 * Get selected meta related to this rule
 * @param id Name of selected meta
 * @return Pointer to selected meta or @c nullptr if such meta is not found
 */
const YaraMeta* YaraRule::getMeta(const std::string &id) const
{
	for(const auto &meta : metas)
	{
		if(meta.getId() == id)
		{
			return &meta;
		}
	}

	return nullptr;
}

/**
 * Get selected match of this rule
 * @param index Index of selected match (indexed from 0)
 * @return Pointer to selected match or @c nullptr if such match is not found
 */
const YaraMatch* YaraRule::getMatch(std::size_t index) const
{
	return ((index < matches.size()) ? &matches[index] : nullptr);
}

/**
 * Get first match of this rule
 * @return Pointer to first match or @c nullptr if rule has no matches
 */
const YaraMatch* YaraRule::getFirstMatch() const
{
	return getMatch(0);
}

/**
 * Get all metas
 * @return All metas related to this rule
 */
const std::vector<YaraMeta>& YaraRule::getMetas() const
{
	return metas;
}

/**
 * Get all matches
 * @return All matches related to this rule
 */
const std::vector<YaraMatch>& YaraRule::getMatches() const
{
	return matches;
}

/**
 * Get number of stored metas
 * @return Number of stored metas
 */
std::size_t YaraRule::getNumberOfMetas() const
{
	return metas.size();
}

/**
 * Get number of stored matches
 * @return Number of stored matches
 */
std::size_t YaraRule::getNumberOfMatches() const
{
	return matches.size();
}

/**
 * Get selected meta related to this rule
 * @param id Name of selected meta
 * @return Pointer to selected meta or @c nullptr if such meta is not found
 */
YaraMeta* YaraRule::getMeta(const std::string &id)
{
	return const_cast<YaraMeta*>(
			static_cast<const YaraRule*>(this)->getMeta(id)
	);
}

/**
 * Get selected match of this rule
 * @param index Index of selected match (indexed from 0)
 * @return Pointer to selected match or @c nullptr if such match is not found
 */
YaraMatch* YaraRule::getMatch(std::size_t index)
{
	return ((index < matches.size()) ? &matches[index] : nullptr);
}

/**
 * Get first match of this rule
 * @return Pointer to first match or @c nullptr if rule has no matches
 */
YaraMatch* YaraRule::getFirstMatch()
{
	return const_cast<YaraMatch*>(
			static_cast<const YaraRule*>(this)->getFirstMatch()
	);
}

/**
 * Set name of rule
 * @param ruleName Name of rule
 */
void YaraRule::setName(const std::string &ruleName)
{
	name = ruleName;
}

/**
 * Add meta
 * @param meta Meta related to this rule
 */
void YaraRule::addMeta(const YaraMeta &meta)
{
	metas.push_back(meta);
}

/**
 * Add match
 * @param match Match related to this rule
 */
void YaraRule::addMatch(const YaraMatch &match)
{
	matches.push_back(match);
}

/**
 * Overload to print rule's name
 * @param o output stream
 * @param rule rule being printed
 * @return output stream for chaining operators
 */
std::ostream& operator<<(std::ostream& o, const YaraRule& rule)
{
	o << rule.name;
	return o;
}

} // namespace yaracpp
} // namespace retdec
