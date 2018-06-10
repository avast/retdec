/**
 * @file src/pat2yara/utils.h
 * @brief Auxiliary functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef PAT2YARA_UTILS_H
#define PAT2YARA_UTILS_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Forward declarations.
namespace yaramod
{

	class HexString;
	class Rule;

} // namespace yaramod

std::shared_ptr<yaramod::HexString> getHexPattern(
	const yaramod::Rule* rule,
	const std::string &name);

std::string getName(
	const yaramod::Rule *rule);

std::string collectNames(
	const std::vector<yaramod::Rule*>& rules);

#endif
