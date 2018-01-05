/**
* @file tests/fileformat/intel_hex_format_20bit_tests.cpp
* @brief Tests for the @c intel_hex_format module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "retdec/fileformat/file_format/intel_hex/intel_hex_format.h"

using namespace ::testing;

namespace {

const std::string intel_hex_example_20bit =
	":020000021200EA\n\r"
	":10010000214601360121470136007EFE09D2190140\n\r"
	":100110002146017E17C20001FF5F16002148011928\n\r"
	":0400000312000105E1\n\r"
	":00000001FF\n\r";

} // anonymous namespace

namespace retdec {
namespace fileformat {
namespace tests {

/**
 * Tests for the @c intel_hex module
 */
class IntelHexFormat20BitTests : public Test
{
	protected:
		std::unique_ptr<IntelHexFormat> parser;
	public:
		IntelHexFormat20BitTests()
		{
			ihexStream << intel_hex_example_20bit;
			parser = std::make_unique<IntelHexFormat>(ihexStream);
		}

		~IntelHexFormat20BitTests()
		{

		}
	private:
		std::stringstream ihexStream;
};

TEST_F(IntelHexFormat20BitTests, CorrectParsing)
{
	EXPECT_EQ(true, parser->isInValidState());
	EXPECT_EQ(1, parser->getNumberOfSections());
}

TEST_F(IntelHexFormat20BitTests, CorrectSection)
{
	auto section = parser->getSectionFromAddress(0x12100);
	ASSERT_NE(nullptr, section);
	EXPECT_EQ(0x00, section->getOffset());
	EXPECT_EQ(0x20, section->getLoadedSize());
	EXPECT_EQ(0x20, section->getSizeInFile());
}

TEST_F(IntelHexFormat20BitTests, CorrectInfo)
{
	unsigned long long res;
	EXPECT_EQ(true, parser->getEpOffset(res));
	EXPECT_EQ(0x05, res);
	EXPECT_EQ(true, parser->getEpAddress(res));
	EXPECT_EQ(0x12105, res);
	EXPECT_EQ(0x20, parser->getLoadedBytes().size());
}

} // namespace tests
} // namespace fileformat
} // namespace retdec
