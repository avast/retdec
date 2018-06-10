/**
* @file tests/fileformat/intel_hex_format_tests.cpp
* @brief Tests for the @c intel_hex_format module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "retdec/fileformat/file_format/intel_hex/intel_hex_format.h"

using namespace ::testing;
using namespace retdec::utils;

namespace {

const std::string intel_hex_example =
	":02000004FFFFFC\n"
	":10010000214601360121470136007efe09d2190140\n"
	":100110002146017E17C20001FF5F16002148011928\n"
	":10012000194E79234623965778239EDA3F01B2caa7\n"
	":100130003F0156702B5E712B722B732146013421C7\n"
	":03000000020023D8\n"
	":10000300E50B250DF509E50A350CF5081200132259\n"
	":10001300AC12AD13AE10AF1112002F8E0E8F0F2244\n"
	":04000005FFFF0001F8\n"
	":00000001FF\n";

const std::string intel_hex_invalid_no_semicolon = "00000001FF\n";
const std::string intel_hex_invalid_address = ":0000PP01FF\n";
const std::string intel_hex_invalid_rectype = ":000000XXFF\n";
const std::string intel_hex_invalid_size = ":@$000001FF\n";
const std::string intel_hex_invalid_data = ":04000005FFFF!!01F8\n";
const std::string intel_hex_invalid_csum = ":04000005FFFF0001F9\n";
const std::string intel_hex_invalid_nl = ":04000005FFFF0001F80000";

} // anonymous namespace

namespace retdec {
namespace fileformat {
namespace tests {

/**
 * Tests for the @c intel_hex module
 */
class IntelHexFormatTests : public Test
{
	protected:
		std::unique_ptr<IntelHexFormat> parser;
	public:
		IntelHexFormatTests()
		{
			ihexStream << intel_hex_example;
			parser = std::make_unique<IntelHexFormat>(ihexStream);
		}

		~IntelHexFormatTests()
		{

		}

		void loadOtherString(const std::string &str)
		{
			ihexStream.str(str);
			ihexStream.clear();
			parser = std::make_unique<IntelHexFormat>(ihexStream);
		}
	private:
		std::stringstream ihexStream;
};

TEST_F(IntelHexFormatTests, CorrectParsing)
{
	EXPECT_EQ(true, parser->isInValidState());
	EXPECT_EQ(2, parser->getNumberOfSections());
}

TEST_F(IntelHexFormatTests, CorrectSections)
{
	unsigned long long res;
	EXPECT_EQ(true, parser->getEpAddress(res));
	EXPECT_EQ(2, parser->getDeclaredNumberOfSections());
	EXPECT_EQ(0xffff0001, res);

	auto section = parser->getSectionFromAddress(0xffff0000);
	ASSERT_NE(nullptr, section);
	EXPECT_EQ(0x00, section->getOffset());
	EXPECT_EQ(0x23, section->getLoadedSize());
	EXPECT_EQ(0x23, section->getSizeInFile());

	section = parser->getSectionFromAddress(0xffff0100);
	ASSERT_NE(nullptr, section);
	EXPECT_EQ(0x23, section->getOffset());
	EXPECT_EQ(0x40, section->getLoadedSize());
	EXPECT_EQ(0x40, section->getSizeInFile());
}

TEST_F(IntelHexFormatTests, CorrectSerialization)
{
	unsigned long long res;
	EXPECT_EQ(true, parser->getEpOffset(res));
	EXPECT_EQ(0x01, res);
	EXPECT_EQ(0x63, parser->getLoadedBytes().size());
}

TEST_F(IntelHexFormatTests, CorrectFileInfo)
{
	unsigned long long res;
	EXPECT_EQ(330, parser->getFileLength());
	EXPECT_EQ(99, parser->getDeclaredFileLength());
	EXPECT_EQ(parser->getLoadedFileLength(), parser->getDeclaredFileLength());
	EXPECT_EQ(true, parser->areSectionsValid());
	EXPECT_EQ(false, parser->isObjectFile());
	EXPECT_EQ(false, parser->isDll());
	EXPECT_EQ(true, parser->isExecutable());
	EXPECT_EQ(false, parser->getMachineCode(res));
	EXPECT_EQ(false, parser->getAbiVersion(res));
	EXPECT_EQ(false, parser->getImageBaseAddress(res));
	EXPECT_EQ(0, parser->getDeclaredNumberOfSegments());
	EXPECT_EQ("Intel HEX", parser->getFileFormatName());
}

TEST_F(IntelHexFormatTests, CorrectSetters)
{
	parser->setTargetArchitecture(Architecture::X86);
	parser->setEndianness(Endianness::LITTLE);
	parser->setBytesPerWord(4);
	EXPECT_EQ(Architecture::X86, parser->getTargetArchitecture());
	EXPECT_EQ(Endianness::LITTLE, parser->getEndianness());
	EXPECT_EQ(4, parser->getBytesPerWord());
}

TEST_F(IntelHexFormatTests, InvalidRecords)
{
	loadOtherString(intel_hex_invalid_no_semicolon);
	EXPECT_EQ(false, parser->isInValidState());
	loadOtherString(intel_hex_invalid_address);
	EXPECT_EQ(false, parser->isInValidState());
	loadOtherString(intel_hex_invalid_rectype);
	EXPECT_EQ(false, parser->isInValidState());
	loadOtherString(intel_hex_invalid_size);
	EXPECT_EQ(false, parser->isInValidState());
	loadOtherString(intel_hex_invalid_data);
	EXPECT_EQ(false, parser->isInValidState());
	loadOtherString(intel_hex_invalid_csum);
	EXPECT_EQ(false, parser->isInValidState());
	loadOtherString(intel_hex_invalid_nl);
	EXPECT_EQ(false, parser->isInValidState());
	// Original.
	loadOtherString(intel_hex_example);
}

} // namespace tests
} // namespace fileformat
} // namespace retdec
