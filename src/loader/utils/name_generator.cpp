/**
 * @file src/loader/utils/name_generator.cpp
 * @brief Definition of name generator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <sstream>

#include "retdec/loader/utils/name_generator.h"

namespace retdec {
namespace loader {

/**
 * Creates name generator with no prefix and optionally can be given fill character and number width.
 *
 * @param fill The character that is used to fill the width of number.
 * @param numWidth The width of the number.
 */
NameGenerator::NameGenerator(char fill/* = '0'*/, std::uint32_t numWidth/* = 0*/) : NameGenerator("", fill, numWidth)
{
}

/**
 * Creates name generator with specified prefix and optionally can be given fill character and number width.
 *
 * @param prefix The prefix of the name.
 * @param fill The character that is used to fill the width of number.
 * @param numWidth The width of the number.
 */
NameGenerator::NameGenerator(const std::string& prefix, char fill/* = ' '*/, std::uint32_t numWidth/* = 0*/) : _prefix(prefix), _fill(fill), _numWidth(numWidth), _counter(0)
{
}

/**
 * Returns the next name from the sequence. Name is of string type and in format
 *   @code
 *     prefix + number from sequence
 *   @endcode
 *
 * @return The next name.
 */
std::string NameGenerator::getNextName()
{
	std::stringstream ss;
	ss << _prefix << std::setfill(_fill) << std::setw(_numWidth) << _counter++;
	return ss.str();
}

} // namespace loader
} // namespace retdec
