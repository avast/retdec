/**
 * @file src/pat2yara/logic.h
 * @brief Logic for yara patterns filter.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef PAT2YARA_LOGIC_H
#define PAT2YARA_LOGIC_H

#include <memory>
#include <string>

// Forward declarations.
namespace yaramod {

	class HexString;
	class Rule;
} // namespace yaramod

std::size_t getPureInformationSize(
	const std::shared_ptr<yaramod::HexString> &pattern);

bool hasEnoughPureInformation(
	const std::shared_ptr<yaramod::HexString> &pattern,
	std::size_t pureMinimum);

std::size_t getHexStringSize(
	const std::shared_ptr<yaramod::HexString> &pattern);

std::size_t getTrailingNopSize(
	const std::shared_ptr<yaramod::HexString> &pattern,
	const std::uint8_t nopOpCode);

std::size_t getNamedRelocationCount(
	const yaramod::Rule* rule);

bool nameFilter(
	const yaramod::Rule* rule);

#endif
