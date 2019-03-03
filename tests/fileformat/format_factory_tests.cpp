/**
* @file tests/fileformat/format_factory_tests.cpp
* @brief Tests for the @c fileformat factory module.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/fileformat/fileformat.h"
#include "retdec/fileformat/format_factory.h"
#include "fileformat/fileformat_tests.h"

using namespace ::testing;
using namespace retdec::utils;

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
class FileFormatFactoryTests : public Test
{

};

TEST_F(FileFormatFactoryTests, CreateCoff_istream)
{
	std::stringstream stream;
	stream << std::string(coffBytes.begin(), coffBytes.end());
	EXPECT_TRUE(dynamic_cast<CoffFormat*>(createFileFormat(stream).get()));

}

TEST_F(FileFormatFactoryTests, CreateCoff_data)
{
	EXPECT_TRUE(dynamic_cast<CoffFormat*>(
			createFileFormat(coffBytes.data(), coffBytes.size()).get()));
}

TEST_F(FileFormatFactoryTests, CreateElf_istream)
{
	std::stringstream stream;
	stream << std::string(elfBytes.begin(), elfBytes.end());
	EXPECT_TRUE(dynamic_cast<ElfFormat*>(createFileFormat(stream).get()));

}

TEST_F(FileFormatFactoryTests, CreateElf_data)
{
	EXPECT_TRUE(dynamic_cast<ElfFormat*>(
			createFileFormat(elfBytes.data(), elfBytes.size()).get()));
}

TEST_F(FileFormatFactoryTests, CreateMacho_istream)
{
	std::stringstream stream;
	stream << std::string(machoBytes.begin(), machoBytes.end());
	EXPECT_TRUE(dynamic_cast<MachOFormat*>(createFileFormat(stream).get()));

}

TEST_F(FileFormatFactoryTests, CreateMacho_data)
{
	EXPECT_TRUE(dynamic_cast<MachOFormat*>(
			createFileFormat(machoBytes.data(), machoBytes.size()).get()));
}

TEST_F(FileFormatFactoryTests, CreatePe_istream)
{
	std::stringstream stream;
	stream << std::string(peBytes.begin(), peBytes.end());
	EXPECT_TRUE(dynamic_cast<PeFormat*>(createFileFormat(stream).get()));

}

TEST_F(FileFormatFactoryTests, CreatePe_data)
{
	EXPECT_TRUE(dynamic_cast<PeFormat*>(
			createFileFormat(peBytes.data(), peBytes.size()).get()));
}

TEST_F(FileFormatFactoryTests, CreateIhex_istream)
{
	std::stringstream stream;
	stream << std::string(ihexBytes.begin(), ihexBytes.end());
	EXPECT_TRUE(dynamic_cast<IntelHexFormat*>(createFileFormat(stream).get()));

}

TEST_F(FileFormatFactoryTests, CreateIhex_data)
{
	EXPECT_TRUE(dynamic_cast<IntelHexFormat*>(
			createFileFormat(
					reinterpret_cast<const uint8_t*>(ihexBytes.data()),
					ihexBytes.size()).get()));
}

TEST_F(FileFormatFactoryTests, CreateRaw_istream)
{
	std::stringstream stream;
	stream << std::string(rawBytes.begin(), rawBytes.end());
	EXPECT_TRUE(dynamic_cast<RawDataFormat*>(
			createFileFormat(stream, true).get()));

}

TEST_F(FileFormatFactoryTests, CreateRaw_data)
{
	EXPECT_TRUE(dynamic_cast<RawDataFormat*>(
			createFileFormat(
					reinterpret_cast<const uint8_t*>(rawBytes.data()),
					rawBytes.size(),
					true).get()));
}

} // namespace tests
} // namespace fileformat
} // namespace retdec
