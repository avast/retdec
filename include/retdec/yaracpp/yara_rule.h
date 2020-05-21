/**
 * @file include/retdec/yaracpp/yara_rule.h
 * @brief Library representation of one YARA rule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_YARACPP_YARA_RULE_H
#define RETDEC_YARACPP_YARA_RULE_H

#include <iosfwd>
#include <vector>

#include "retdec/yaracpp/yara_match.h"
#include "retdec/yaracpp/yara_meta.h"

namespace retdec {
namespace yaracpp {

/**
 * Representation of one YARA rule
 */
class YaraRule
{
	private:
		std::string name;
		std::vector<YaraMeta> metas;
		std::vector<YaraMatch> matches;
	public:
		/// @name Const getters
		/// @{
		const std::string &getName() const;
		const YaraMeta* getMeta(const std::string &id) const;
		const YaraMatch* getMatch(std::size_t index) const;
		const YaraMatch* getFirstMatch() const;
		const std::vector<YaraMeta>& getMetas() const;
		const std::vector<YaraMatch>& getMatches() const;
		std::size_t getNumberOfMetas() const;
		std::size_t getNumberOfMatches() const;
		/// @}

		/// @name Getters
		/// @{
		YaraMeta* getMeta(const std::string &id);
		YaraMatch* getMatch(std::size_t index);
		YaraMatch* getFirstMatch();
		/// @}

		/// @name Setters
		/// @{
		void setName(const std::string &ruleName);
		/// @}

		/// @name Other methods
		/// @{
		void addMeta(const YaraMeta &meta);
		void addMatch(const YaraMatch &match);
		/// @}

		// @name Utility operator overloads
		// @{
		friend std::ostream& operator<<(std::ostream& o, const YaraRule& rule);
		// @}
};

} // namespace yaracpp
} // namespace retdec

#endif
