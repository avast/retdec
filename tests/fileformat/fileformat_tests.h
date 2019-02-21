/**
* @file tests/fileformat/fileformat_tests.h
* @brief Tests for the @c FileFormat module.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef TESTS_FILEFORMAT_FILEFORMAT_TESTS_H
#define TESTS_FILEFORMAT_FILEFORMAT_TESTS_H

#include <cstdint>
#include <vector>

namespace retdec {
namespace fileformat {
namespace tests {

extern const std::vector<uint8_t> coffBytes;
extern const std::vector<uint8_t> elfBytes;
extern const std::vector<uint8_t> machoBytes;
extern const std::vector<uint8_t> peBytes;
extern const std::string ihexBytes;
extern const std::string rawBytes;

} // namespace tests
} // namespace fileformat
} // namespace retdec

#endif
