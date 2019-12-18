/**
* @file tests/fileformat/coff_format_tests.cpp
* @brief Tests for the @c coff_format module.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/fileformat/utils/format_detection.h"
#include "fileformat/fileformat_tests.h"

using namespace ::testing;

namespace retdec {
namespace fileformat {
namespace tests {

extern const std::vector<uint8_t> coffBytes;
extern const std::vector<uint8_t> elfBytes;
extern const std::vector<uint8_t> machoBytes;
extern const std::vector<uint8_t> peBytes;
extern const std::string ihexBytes;
extern const std::string rawBytes;

/**
 * Tests for the @c coff_format module - using istream constructor.
 */
class FileFormatDetectionTests : public Test
{

};

TEST_F(FileFormatDetectionTests, DetectCoff_istream)
{
	std::stringstream stream;
	stream << std::string(coffBytes.begin(), coffBytes.end());
	EXPECT_EQ(Format::COFF, detectFileFormat(stream));
}

TEST_F(FileFormatDetectionTests, DetectCoff_data)
{
	EXPECT_EQ(
			Format::COFF,
			detectFileFormat(coffBytes.data(), coffBytes.size()));
}

TEST_F(FileFormatDetectionTests, DetectElf_istream)
{
	std::stringstream stream;
	stream << std::string(elfBytes.begin(), elfBytes.end());
	EXPECT_EQ(Format::ELF, detectFileFormat(stream));
}

TEST_F(FileFormatDetectionTests, DetectElf_data)
{
	EXPECT_EQ(
			Format::ELF,
			detectFileFormat(elfBytes.data(), elfBytes.size()));
}

TEST_F(FileFormatDetectionTests, DetectMacho_istream)
{
	std::stringstream stream;
	stream << std::string(machoBytes.begin(), machoBytes.end());
	EXPECT_EQ(Format::MACHO, detectFileFormat(stream));
}

TEST_F(FileFormatDetectionTests, DetectMacho_data)
{
	EXPECT_EQ(
			Format::MACHO,
			detectFileFormat(machoBytes.data(), machoBytes.size()));
}

TEST_F(FileFormatDetectionTests, DetectPe_istream)
{
	std::stringstream stream;
	stream << std::string(peBytes.begin(), peBytes.end());
	EXPECT_EQ(Format::PE, detectFileFormat(stream));
}

TEST_F(FileFormatDetectionTests, DetectPe_data)
{
	EXPECT_EQ(
			Format::PE,
			detectFileFormat(peBytes.data(), peBytes.size()));
}

TEST_F(FileFormatDetectionTests, DetectIhex_istream)
{
	std::stringstream stream;
	stream << std::string(ihexBytes.begin(), ihexBytes.end());
	EXPECT_EQ(Format::INTEL_HEX, detectFileFormat(stream));
}

TEST_F(FileFormatDetectionTests, DetectIhex_data)
{
	EXPECT_EQ(
			Format::INTEL_HEX,
			detectFileFormat(
					reinterpret_cast<const uint8_t*>(ihexBytes.data()),
					ihexBytes.size()));
}

TEST_F(FileFormatDetectionTests, DetectRaw_istream)
{
	std::stringstream stream;
	stream << std::string(rawBytes.begin(), rawBytes.end());
	EXPECT_EQ(Format::RAW_DATA, detectFileFormat(stream, true));
}

TEST_F(FileFormatDetectionTests, DetectRaw_data)
{
	EXPECT_EQ(
			Format::RAW_DATA,
			detectFileFormat(
					reinterpret_cast<const uint8_t*>(rawBytes.data()),
					rawBytes.size(),
					true));
}

} // namespace tests
} // namespace fileformat
} // namespace retdec
