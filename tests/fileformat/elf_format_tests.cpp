/**
* @file tests/fileformat/elf_format_tests.cpp
* @brief Tests for the @c elf_format module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>

#include "retdec/fileformat/file_format/elf/elf_format.h"
#include "fileformat/fileformat_tests.h"

using namespace ::testing;
using namespace retdec::utils;

namespace retdec {
namespace fileformat {
namespace tests {

const std::vector<uint8_t> elfBytes = {
	0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x48, 0x69, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x0a,
	0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x80, 0x04, 0x08, 0x34, 0x00, 0x00, 0x00,
	0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x02, 0x00, 0x28, 0x00,
	0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x04, 0x08,
	0x00, 0x80, 0x04, 0x08, 0xa2, 0x00, 0x00, 0x00, 0xa2, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00, 0x00, 0xa4, 0x90, 0x04, 0x08,
	0xa4, 0x90, 0x04, 0x08, 0x09, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xba, 0x09, 0x00, 0x00, 0x00, 0xb9, 0x07, 0x90, 0x04, 0x08, 0xbb, 0x01, 0x00, 0x00, 0x00, 0xb8,
	0x04, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00,
	0xcd, 0x80, 0x00, 0x00
};

/**
 * Tests for the @c elf_format module - using istream constructor.
 */
class ElfFormatTests_istream : public Test
{
	private:
		std::stringstream elfStringStream;
	protected:
		std::unique_ptr<ElfFormat> parser;
	public:
		ElfFormatTests_istream()
		{
			elfStringStream << std::string(elfBytes.begin(), elfBytes.end());
			parser = std::make_unique<ElfFormat>(elfStringStream);
		}
};

TEST_F(ElfFormatTests_istream, CorrectParsing)
{
	EXPECT_EQ(true, parser->isInValidState());
	EXPECT_EQ(0, parser->getNumberOfSections());
	EXPECT_EQ(2, parser->getNumberOfSegments());
}

TEST_F(ElfFormatTests_istream, DataInterpretationDefault)
{
	std::uint64_t res;
	EXPECT_EQ(true, parser->get1Byte(0x8048000, res));
	EXPECT_EQ(0x7f, res);
	EXPECT_EQ(true, parser->get2Byte(0x8048000, res));
	EXPECT_EQ(0x457f, res);
	EXPECT_EQ(true, parser->get4Byte(0x8048000, res));
	EXPECT_EQ(0x464c457f, res);
	EXPECT_EQ(true, parser->get8Byte(0x8048000, res));
	EXPECT_EQ(0x48010101464c457f, res);
}

TEST_F(ElfFormatTests_istream, DataInterpretationBig)
{
	std::uint64_t res;
	EXPECT_EQ(true, parser->get1Byte(0x8048000, res, Endianness::BIG));
	EXPECT_EQ(0x7f, res);
	EXPECT_EQ(true, parser->get2Byte(0x8048000, res, Endianness::BIG));
	EXPECT_EQ(0x7f45, res);
	EXPECT_EQ(true, parser->get4Byte(0x8048000, res, Endianness::BIG));
	EXPECT_EQ(0x7f454c46, res);
	EXPECT_EQ(true, parser->get8Byte(0x8048000, res, Endianness::BIG));
	EXPECT_EQ(0x7f454c4601010148, res);
}

/**
 * Tests for the @c elf_format module - using binary data constructor.
 */
class ElfFormatTests_data : public Test
{
	protected:
		std::unique_ptr<ElfFormat> parser;
	public:
		ElfFormatTests_data()
		{
			parser = std::make_unique<ElfFormat>(elfBytes.data(), elfBytes.size());
		}
};

TEST_F(ElfFormatTests_data, CorrectParsing)
{
	EXPECT_EQ(true, parser->isInValidState());
	EXPECT_EQ(0, parser->getNumberOfSections());
	EXPECT_EQ(2, parser->getNumberOfSegments());
}

TEST_F(ElfFormatTests_data, DataInterpretationDefault)
{
	std::uint64_t res;
	EXPECT_EQ(true, parser->get1Byte(0x8048000, res));
	EXPECT_EQ(0x7f, res);
	EXPECT_EQ(true, parser->get2Byte(0x8048000, res));
	EXPECT_EQ(0x457f, res);
	EXPECT_EQ(true, parser->get4Byte(0x8048000, res));
	EXPECT_EQ(0x464c457f, res);
	EXPECT_EQ(true, parser->get8Byte(0x8048000, res));
	EXPECT_EQ(0x48010101464c457f, res);
}

} // namespace tests
} // namespace fileformat
} // namespace retdec
