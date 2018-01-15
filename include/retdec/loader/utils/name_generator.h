/**
 * @file include/retdec/loader/utils/name_generator.h
 * @brief Declaration of name generator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_UTILS_NAME_GENERATOR_H
#define RETDEC_LOADER_UTILS_NAME_GENERATOR_H

#include <cstdint>
#include <string>

namespace retdec {
namespace loader {

/**
 * This class represents the unique name generator, where uniqueness is achieved
 * through increasing sequence of numbers starting from 0. Name generator can be given
 * prefix string, which is prepended to numbers from sequence.
 */
class NameGenerator
{
public:
	NameGenerator(char fill = '0', std::uint32_t numWidth = 0);
	NameGenerator(const std::string& prefix, char fill = ' ', std::uint32_t numWidth = 0);

	std::string getNextName();

private:
	std::string _prefix;
	char _fill;
	std::uint32_t _numWidth;
	std::uint32_t _counter;
};

} // namespace loader
} // namespace retdec

#endif
