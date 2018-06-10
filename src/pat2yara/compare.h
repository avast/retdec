/**
 * @file src/pat2yara/compare.h
 * @brief Functions for rules comparison.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef PAT2YARA_COMPARE_H
#define PAT2YARA_COMPARE_H

#include <memory>
#include <vector>

// Forward declarations.
namespace yaramod {
	class Rule;
} // namespace yaramod

/**
 * Class representing relations of given rule with other rules.
 */
class RuleRelations
{
	public:
		/// @name Constructors.
		/// @{
		RuleRelations(yaramod::Rule* rule);
		/// @}

		/// @name Getters.
		/// @{
		yaramod::Rule *getRule() const;
		std::vector<yaramod::Rule*> getEquals() const;
		std::vector<yaramod::Rule*> getAlternatives() const;
		/// @}

		/// @name Queries.
		/// @{
		bool hasEquals() const;
		bool hasAlternatives() const;
		/// @}

		/// @name Comparisons.
		/// @{
		bool add(yaramod::Rule* otherRule);
		bool isEqual(const yaramod::Rule* otherRule) const;
		bool isAlternative(const yaramod::Rule* otherRule) const;
		bool isEqualOrAlternative(const yaramod::Rule* otherRule) const;
		/// @}

		/// @name Auxiliary.
		/// @{
		void makeAlternativesUniq();
		/// @}

	private:
		yaramod::Rule* rule; ///< Base rule.

		/**
		 * Rules with both same patterns and same references.
		 *
		 * These rules will have to be removed as it is impossible to
		 * detect them correctly in later stages of static code detection.
		 */
		std::vector<yaramod::Rule*> equals;

		/**
		 * Rules with same patterns but different references.
		 *
		 * These rules can be used later in static code detection, but
		 * can be stored more effectively in output file.
		 */
		std::vector<yaramod::Rule*> alternatives;
};

std::vector<RuleRelations> getRuleRelationsFromRules(
	const std::vector<std::unique_ptr<yaramod::Rule>> &rules);

#endif
