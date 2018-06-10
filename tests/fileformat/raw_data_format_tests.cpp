/**
* @file tests/fileformat/raw_data_format_tests.cpp
* @brief Tests for the @c raw_data_format module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"

using namespace ::testing;
using namespace retdec::utils;

namespace {

const std::string input = "0123456789";

} // anonymous namespace

namespace retdec {
namespace fileformat {
namespace tests {

/**
 * Tests for the @c raw_data module
 */
class RawDataFormatTests : public Test
{
	protected:
		std::unique_ptr<RawDataFormat> parser;

	public:
		RawDataFormatTests()
		{
			inputstream << input;
			parser = std::make_unique<RawDataFormat>(inputstream);
		}

		~RawDataFormatTests()
		{
		}

	private:
		std::stringstream inputstream;
};

TEST_F(RawDataFormatTests, CorrectLoading)
{
	EXPECT_EQ(true, parser->isInValidState());
	EXPECT_EQ(1, parser->getNumberOfSections());
	EXPECT_EQ(10, parser->getLoadedBytes().size());
}

TEST_F(RawDataFormatTests, TestSettersGetters)
{
	parser->setTargetArchitecture(Architecture::ARM);
	parser->setEndianness(Endianness::LITTLE);
	parser->setBytesPerWord(4);
	parser->setEntryPoint(0x8002);
	parser->setBaseAddress(0x8000);

	EXPECT_EQ(0x8000, parser->getSections()[0]->getAddress());
	unsigned long long result = 0;
	EXPECT_EQ(true, parser->getEpOffset(result));
	EXPECT_EQ(0x2, result);
	EXPECT_EQ(true, parser->getEpAddress(result));
	EXPECT_EQ(0x8002, result);
	EXPECT_EQ(Architecture::ARM, parser->getTargetArchitecture());
	EXPECT_EQ(Endianness::LITTLE, parser->getEndianness());
	EXPECT_EQ(4, parser->getBytesPerWord());
}

TEST_F(RawDataFormatTests, TestInvalidEP)
{
	unsigned long long result;
	parser->setBaseAddress(0x8000);

	parser->setEntryPoint(0x800B);
	EXPECT_EQ(true, parser->getEpOffset(result));
	EXPECT_EQ(0x00, result);
	EXPECT_EQ(true, parser->getEpAddress(result));
	EXPECT_EQ(0x8000, result);

	parser->setEntryPoint(0x7FFF);
	EXPECT_EQ(true, parser->getEpOffset(result));
	EXPECT_EQ(0x00, result);
	EXPECT_EQ(true, parser->getEpAddress(result));
	EXPECT_EQ(0x8000, result);
}

} // namespace tests
} // namespace fileformat
} // namespace retdec
