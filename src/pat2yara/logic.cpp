/**
 * @file src/pat2yara/logic.cpp
 * @brief Logic for yara patterns filter.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cctype>
#include <regex>

#include "pat2yara/logic.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/rule.h"

using namespace yaramod;

/**
 * Get size of pure information (no wild-cards etc.) in HexString in bytes.
 *
 * @param pattern input pattern
 *
 * @return amount of pure information in pattern
 */
std::size_t getPureInformationSize(
	const std::shared_ptr<HexString> &pattern)
{
	std::size_t nibbleCount = 0;

	if (pattern) {
		for (const auto &unit : pattern->getUnits()) {
			if (unit->isNibble()) {
				nibbleCount++;
			}
		}
	}

	// Convert size from nibbles to bytes.
	return nibbleCount / 2;
}

/**
 * Check if pattern has enough pure information.
 *
 * @param pattern input pattern
 * @param pureMinimum pure information requirement
 *
 * @return @c true if pattern has enough pure information, @c false otherwise
 */
bool hasEnoughPureInformation(
	const std::shared_ptr<HexString> &pattern,
	std::size_t pureMinimum)
{
	std::size_t count = 0;
	std::size_t minimum = pureMinimum * 2;

	if (pattern) {
		for (const auto &unit : pattern->getUnits()) {
			if (unit->isNibble()) {
				count++;
			}
			if (count == minimum) {
				return true;
			}
		}
	}

	return count >= minimum;
}

/**
 * Get HexString size in bytes.
 *
 * @param pattern input pattern
 *
 * @return length of input pattern
 */
std::size_t getHexStringSize(
	const std::shared_ptr<HexString> &pattern)
{
	// Convert size from nibbles to bytes.
	return pattern->getLength() / 2;
}

/**
 * Get number of trailing NOP instructions used to align functions.
 *
 * @param pattern input pattern
 * @param nopOpCode code for NOP instruction
 *
 * @return number of trailing bytes of NOPs
 */
std::size_t getTrailingNopSize(
	const std::shared_ptr<HexString> &pattern,
	const std::uint8_t nopOpCode)
{
	std::size_t counter = 0;
	const auto &units = pattern->getUnits();

	// Reverse iteration by two units.
	for (auto i = units.size() - 1; i > 1; i -= 2) {
		const auto &lowUnit = units[i];
		const auto &highUnit = units[i-1];
		if (!lowUnit->isNibble() || !lowUnit->isNibble()) {
			// Cannot be NOP byte.
			return counter;
		}

		auto low = std::static_pointer_cast<HexStringNibble>(lowUnit)->getValue();
		auto high = std::static_pointer_cast<HexStringNibble>(highUnit)->getValue();
		if (nopOpCode == ((high << 4) | low)) {
			counter++;
		}
		else {
			// Not a NOP - return.
			return counter;
		}
	}

	return counter;
}

/**
 * Get number of named relocations.
 *
 * @param rule input rule
 *
 * @return number of named relocations
 */
std::size_t getNamedRelocationCount(
	const Rule *rule)
{
	const auto* meta = rule->getMetaWithName("refs");
	if (meta == nullptr) {
		return 0;
	}

	// Just count spaces and derive size from result.
	const std::string &refs = meta->getValue().getPureText();
	std::size_t spaceCount = std::count(refs.begin(), refs.end(), ' ');

	// There are two spaces for every entry except for the last one.
	return refs.empty() ? 0 : spaceCount / 2 + 1;
}

/**
 * Check if this rule should be removed because of its name.
 *
 * @param rule input rule
 *
 * @return @c true if rule should be removed, @c false otherwise
 */
bool nameFilter(
	const Rule *rule)
{
	const auto* meta = rule->getMetaWithName("name");
	if (meta) {
		const std::string &name = meta->getValue().getPureText();
		if (name.empty()) {
			return false;
		}

		// Functions that start with number appear in MSVC ARM libraries.
		if (std::isdigit(name[0])) {
			return true;
		}
		// T.XX functions appear in Mingw ARM libraries.
		if (std::regex_search(name, std::regex("^T\\."))) {
			return true;
		}
		// Temp.XXXXXXXX functions appear in MSVC ARM libraries.
		if (std::regex_search(name, std::regex("^Temp\\."))) {
			return true;
		}
		// Lambda functions appear in MSVC libraries.
		if (std::regex_search(name, std::regex("lambda_"))) {
			return true;
		}

		// Name is OK.
		return false;
	}

	// No name - remove rule.
	return true;
}
