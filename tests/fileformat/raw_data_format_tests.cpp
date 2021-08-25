/**
* @file tests/fileformat/raw_data_format_tests.cpp
* @brief Tests for the @c raw_data_format module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "fileformat/fileformat_tests.h"

using namespace ::testing;
using namespace retdec::utils;

namespace retdec {
namespace fileformat {
namespace tests {

const std::string rawBytes = "0123456789";

/**
 * Tests for the @c raw_data module - using istream constructor.
 */
class RawDataFormatTests_istream : public Test
{
	protected:
		std::unique_ptr<RawDataFormat> parser;

	public:
		RawDataFormatTests_istream()
		{
			inputstream << rawBytes;
			parser = std::make_unique<RawDataFormat>(inputstream);
		}

	private:
		std::stringstream inputstream;
};

TEST_F(RawDataFormatTests_istream, CorrectLoading)
{
	EXPECT_EQ(true, parser->isInValidState());
	EXPECT_EQ(1, parser->getNumberOfSections());
	EXPECT_EQ(10, parser->getLoadedBytes().size());
}

TEST_F(RawDataFormatTests_istream, TestSettersGetters)
{
	parser->setTargetArchitecture(Architecture::ARM);
	parser->setEndianness(Endianness::LITTLE);
	parser->setBytesPerWord(4);
	parser->setEntryPoint(0x8002);
	parser->setBaseAddress(0x8000);

	EXPECT_EQ(0x8000, parser->getSections()[0]->getAddress());
	std::uint64_t result = 0;
	EXPECT_EQ(true, parser->getEpOffset(result));
	EXPECT_EQ(0x2, result);
	EXPECT_EQ(true, parser->getEpAddress(result));
	EXPECT_EQ(0x8002, result);
	EXPECT_EQ(Architecture::ARM, parser->getTargetArchitecture());
	EXPECT_EQ(Endianness::LITTLE, parser->getEndianness());
	EXPECT_EQ(4, parser->getBytesPerWord());
}

TEST_F(RawDataFormatTests_istream, TestInvalidEP)
{
	std::uint64_t result;
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

/**
 * Tests for the @c raw_data module - using istream constructor.
 */
class RawDataFormatTests_data : public Test
{
	protected:
		std::unique_ptr<RawDataFormat> parser;

	public:
		RawDataFormatTests_data()
		{
			parser = std::make_unique<RawDataFormat>(
					reinterpret_cast<const std::uint8_t*>(rawBytes.data()),
					rawBytes.size());
		}
};

TEST_F(RawDataFormatTests_data, CorrectLoading)
{
	EXPECT_EQ(true, parser->isInValidState());
	EXPECT_EQ(1, parser->getNumberOfSections());
	EXPECT_EQ(10, parser->getLoadedBytes().size());
}

TEST_F(RawDataFormatTests_data, TestInvalidEP)
{
	std::uint64_t result;
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
