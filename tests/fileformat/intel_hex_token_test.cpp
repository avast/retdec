/**
* @file tests/fileformat/intel_hex_token_test.cpp
* @brief Tests for the @c intel_hex_format module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>

#include "retdec/fileformat/file_format/intel_hex/intel_hex_format.h"

using namespace ::testing;

namespace retdec {
namespace fileformat {
namespace tests {

/**
 * Tests for the @c intel_hex module
 */
class IntelHexTokenTests : public Test
{
	protected:
		IntelHexToken token;
	public:
		IntelHexTokenTests()
		{
			// Valid record :02000004FFFFFC
			token.byteCount = 0x02;
			token.recordType = 0x04;
			token.address.push_back('0');
			token.address.push_back('0');
			token.address.push_back('0');
			token.address.push_back('0');
			token.data.push_back('F');
			token.data.push_back('F');
			token.data.push_back('F');
			token.data.push_back('F');
			token.checksum.push_back('F');
			token.checksum.push_back('C');
		}

		~IntelHexTokenTests()
		{

		}
};

TEST_F(IntelHexTokenTests, ChecksumValid)
{
	token.controlChecksum();
	EXPECT_EQ(true, token.checksumValid);
}

TEST_F(IntelHexTokenTests, InvalidData)
{
	// Alter byteCount
	token.byteCount = 0x01;
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.byteCount = 0x03;
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.byteCount = 0x02; // Original value for further tesing (checksum is only partial SED)
	// Alter recordType
	token.recordType = 0x00;
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.recordType = 0x03;
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.recordType = 0x04; // Original value
	// Alter address
	token.address[1] = '1';
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.address[1] = 'D';
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.address[1] = '0'; // Original value
	// Alter data
	token.data[3] = '2';
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.address[3] = 'E';
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.address[3] = 'F'; // Original value

}

TEST_F(IntelHexTokenTests, InvalidChecksum)
{
	token.checksum[0] = 'E';
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.checksum[0] = 'F'; // Original value
	token.checksum[1] = '7';
	token.controlChecksum();
	EXPECT_EQ(false, token.checksumValid);
	token.checksum[1] = 'C'; // Original value
}

} // namespace tests
} // namespace fileformat
} // namespace retdec
