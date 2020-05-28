/**
* @file tests/utils/conversion_tests.cpp
* @brief Tests for the @c conversion module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/conversion.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c conversion module.
*/
class ConversionTests: public Test {};

//
// intToHexString()
//

TEST_F(ConversionTests,
ToHexCorrectConversionNoBase) {
	EXPECT_EQ("0", intToHexString(0x0, false));
	EXPECT_EQ("1", intToHexString(0x1, false));
	EXPECT_EQ("f", intToHexString(0xf, false));
	EXPECT_EQ("400", intToHexString(0x400, false));
	EXPECT_EQ("ffff", intToHexString(0xffff, false));
}

TEST_F(ConversionTests,
ToHexCorrectConversionWithBase) {
	EXPECT_EQ("0x0", intToHexString(0x0, true));
	EXPECT_EQ("0x1", intToHexString(0x1, true));
	EXPECT_EQ("0xf", intToHexString(0xf, true));
	EXPECT_EQ("0x400", intToHexString(0x400, true));
	EXPECT_EQ("0xffff", intToHexString(0xffff, true));
}

TEST_F(ConversionTests,
ToHexCorrectConversionWithFill) {
	EXPECT_EQ("0x0", intToHexString(0x0, true, 0));
	EXPECT_EQ("0", intToHexString(0x0, false, 0));
	EXPECT_EQ("0x0000", intToHexString(0x0, true, 4));
	EXPECT_EQ("0000", intToHexString(0x0, false, 4));
	EXPECT_EQ("0x1234", intToHexString(0x1234, true, 2));
	EXPECT_EQ("1234", intToHexString(0x1234, false, 2));
	EXPECT_EQ("0x1234", intToHexString(0x1234, true, 4));
	EXPECT_EQ("1234", intToHexString(0x1234, false, 4));
	EXPECT_EQ("0x00001234", intToHexString(0x1234, true, 8));
	EXPECT_EQ("00001234", intToHexString(0x1234, false, 8));
}

//
// strToNum()
//

TEST_F(ConversionTests,
StrToNumIntDecimalSuccess) {
	int out = 0;
	EXPECT_TRUE(strToNum("-100", out, std::dec));
	EXPECT_EQ(-100, out);

	out = 0;
	EXPECT_TRUE(strToNum("-1", out, std::dec));
	EXPECT_EQ(-1, out);

	out = 0;
	EXPECT_TRUE(strToNum("0", out, std::dec));
	EXPECT_EQ(0, out);

	out = 0;
	EXPECT_TRUE(strToNum("1", out, std::dec));
	EXPECT_EQ(1, out);

	out = 0;
	EXPECT_TRUE(strToNum("100", out, std::dec));
	EXPECT_EQ(100, out);

	out = 0;
	EXPECT_TRUE(strToNum("0000", out, std::dec));
	EXPECT_EQ(0, out);

	out = 0;
	EXPECT_TRUE(strToNum("0005", out, std::dec));
	EXPECT_EQ(5, out);

	// TODO How to test std::numeric_limit<int>::max?
}

TEST_F(ConversionTests,
StrToNumIntDecimalFailure) {
	int out = -1;
	EXPECT_FALSE(strToNum("", out, std::dec));
	EXPECT_EQ(-1, out);

	out = -1;
	EXPECT_FALSE(strToNum("xx", out, std::dec));
	EXPECT_EQ(-1, out);

	out = -1;
	EXPECT_FALSE(strToNum("12 bbb", out, std::dec));
	EXPECT_EQ(-1, out);

	out = -1;
	EXPECT_FALSE(strToNum("12bbb", out, std::dec));
	EXPECT_EQ(-1, out);

	// TODO How to test overflow?
}

TEST_F(ConversionTests,
StrToNumIntHexSuccess) {
	int out = 0;
	EXPECT_TRUE(strToNum("-0xFA", out, std::hex));
	EXPECT_EQ(-0xFA, out);

	out = 0;
	EXPECT_TRUE(strToNum("-0x1", out, std::hex));
	EXPECT_EQ(-0x1, out);

	out = 0;
	EXPECT_TRUE(strToNum("0x0", out, std::hex));
	EXPECT_EQ(0x0, out);

	out = 0;
	EXPECT_TRUE(strToNum("0x1", out, std::hex));
	EXPECT_EQ(0x1, out);

	out = 0;
	EXPECT_TRUE(strToNum("0xFA", out, std::hex));
	EXPECT_EQ(0xFA, out);

	out = 0;
	EXPECT_TRUE(strToNum("0x00F", out, std::hex));
	EXPECT_EQ(0x00F, out);
}

TEST_F(ConversionTests,
StrToNumIntHexFailure) {
	int out = -1;
	EXPECT_FALSE(strToNum("", out, std::hex));
	EXPECT_EQ(-1, out);

	out = -1;
	EXPECT_FALSE(strToNum("0x", out, std::hex));
	EXPECT_EQ(-1, out);

	out = -1;
	EXPECT_FALSE(strToNum("xx", out, std::hex));
	EXPECT_EQ(-1, out);

	out = -1;
	EXPECT_FALSE(strToNum("0xF bbb", out, std::hex));
	EXPECT_EQ(-1, out);

	out = -1;
	EXPECT_FALSE(strToNum("0xFwww", out, std::hex));
	EXPECT_EQ(-1, out);
}

TEST_F(ConversionTests,
StrToNumConversionFailsWhenConvertingNegativeNumberIntoUnsignedInt) {
	unsigned out = 0;
	EXPECT_FALSE(strToNum("-1", out, std::dec));
	EXPECT_EQ(0, out);

	out = 0;
	EXPECT_FALSE(strToNum("+-1", out, std::dec));
	EXPECT_EQ(0, out);
}

//
// bytesToBits()
//

TEST_F(ConversionTests,
BytesToBits) {
	std::vector<std::uint8_t> vec;
	EXPECT_EQ(bytesToBits(vec.data(), vec.size()), "");

	vec = { 0xAB };
	EXPECT_EQ(bytesToBits(vec.data(), vec.size()), "10101011");

	vec = { 0x11, 0x55, 0xFF };
	EXPECT_EQ(bytesToBits(vec.data(), vec.size()), "000100010101010111111111");

	std::vector<std::uint16_t> u16vec = { 0xDEAD, 0xBEEF };
	EXPECT_EQ(bytesToBits(u16vec), "1010110111101111");
}

//
// double10toDouble8()
//

TEST_F(ConversionTests,
double10ToDouble8Success) {
	std::vector<unsigned char> dest;
	std::vector<unsigned char> src = {0x60, 0xe5, 0xd0, 0x22, 0xdb, 0xf9, 0x7e, 0xf2, 0x00, 0x40}; // 80-bit double for 3.789
	std::vector<unsigned char> ok = {0x1c, 0x5a, 0x64, 0x3b, 0xdf, 0x4f, 0x0e, 0x40}; // 64-bit double for 3.789

	double10ToDouble8(dest, src);

	EXPECT_TRUE(dest == ok);
}

//
// byteSwap16()
//

TEST_F(ConversionTests,
byteSwap16Success) {
	EXPECT_EQ(0x0, byteSwap16(0x0));
	EXPECT_EQ(0x1200, byteSwap16(0x0012));
	EXPECT_EQ(0x0012, byteSwap16(0x1200));
	EXPECT_EQ(0x3412, byteSwap16(0x1234));
}

//
// byteSwap32()
//

TEST_F(ConversionTests,
byteSwap32Success) {
	EXPECT_EQ(0x0, byteSwap32(0x0));
	EXPECT_EQ(0x12000000, byteSwap32(0x00000012));
	EXPECT_EQ(0x12340000, byteSwap32(0x00003412));
	EXPECT_EQ(0x12345600, byteSwap32(0x00563412));
	EXPECT_EQ(0x12345678, byteSwap32(0x78563412));
}

//
// byteSwap16()
//

TEST_F(ConversionTests,
byteSwap16SSuccess) {
	EXPECT_EQ("0000000000000000", byteSwap16("0000000000000000"));
	EXPECT_EQ("1010101000000000", byteSwap16("0000000010101010"));
	EXPECT_EQ("0000000010101010", byteSwap16("1010101000000000"));
	EXPECT_EQ("1111111110101010", byteSwap16("1010101011111111"));
}

//
// byteSwap32()
//

TEST_F(ConversionTests,
byteSwap32SSuccess) {
	EXPECT_EQ("00000000000000000000000000000000", byteSwap32("00000000000000000000000000000000"));
	EXPECT_EQ("11111111000000000000000000000000", byteSwap32("00000000000000000000000011111111"));
	EXPECT_EQ("00000000111111110000000000000000", byteSwap32("00000000000000001111111100000000"));
	EXPECT_EQ("00000000000000001111111100000000", byteSwap32("00000000111111110000000000000000"));
	EXPECT_EQ("00000000000000000000000011111111", byteSwap32("11111111000000000000000000000000"));
}

//
// hexStringToBytes()
//

TEST_F(ConversionTests,
hexStringToBytesSuccess) {
	EXPECT_EQ(hexStringToBytes("0b84d1a0806040"), hexStringToBytes("0b 84 d1 a0 80 60 40"));
	std::vector<uint8_t> vres = {0x0b, 0x84, 0xd1, 0xa0, 0x80, 0x60, 0x40};
	EXPECT_EQ(vres, hexStringToBytes("0b 84 d1 a0 80 60 40"));
}

//
// bytesToHexString()
//

TEST_F(ConversionTests,
bytesToHexStringSuccess) {
	std::vector<uint8_t> vres = {0x0b, 0x84, 0xd1, 0xa0, 0x80, 0x60, 0x40};
	std::string res;
	bytesToHexString(vres, res, 0, 0, false, true);
	EXPECT_EQ("0b 84 d1 a0 80 60 40", res);
}

} // namespace tests
} // namespace utils
} // namespace retdec
