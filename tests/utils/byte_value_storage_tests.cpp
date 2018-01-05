/**
* @file tests/utils/byte_value_storage_tests.cpp
* @brief Tests for the @c ByteValueStorage module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "retdec/utils/byte_value_storage.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

class ByteValueStorageTests : public Test {};

class MockByteValueStorage : public ByteValueStorage
{
public:
	MOCK_CONST_METHOD0(getEndianness, Endianness());
	MOCK_CONST_METHOD0(getNibbleLength, std::size_t());
	MOCK_CONST_METHOD0(getByteLength, std::size_t());
	MOCK_CONST_METHOD0(getWordLength, std::size_t());
	MOCK_CONST_METHOD0(getBytesPerWord, std::size_t());
	MOCK_CONST_METHOD0(getNumberOfNibblesInByte, std::size_t());
	MOCK_CONST_METHOD0(hasMixedEndianForDouble, bool());

	MOCK_CONST_METHOD4(getXByte, bool(std::uint64_t,std::uint64_t,std::uint64_t&,Endianness));
	MOCK_CONST_METHOD3(getXBytes, bool(std::uint64_t,std::uint64_t,std::vector<std::uint8_t>&));

	MOCK_METHOD4(setXByte, bool(std::uint64_t,std::uint64_t,std::uint64_t,Endianness));
	MOCK_METHOD2(setXBytes, bool(std::uint64_t,const std::vector<std::uint8_t>&));
};

TEST_F(ByteValueStorageTests,
GetInverseEndiannessWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.Times(3)
		.WillOnce(Return(Endianness::BIG))
		.WillOnce(Return(Endianness::LITTLE))
		.WillOnce(Return(Endianness::UNKNOWN));

	EXPECT_EQ(Endianness::LITTLE, storage.getInverseEndianness());
	EXPECT_EQ(Endianness::BIG, storage.getInverseEndianness());
	EXPECT_EQ(Endianness::UNKNOWN, storage.getInverseEndianness());
}

TEST_F(ByteValueStorageTests,
IsLittleEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.Times(1)
		.WillOnce(Return(Endianness::LITTLE));

	EXPECT_TRUE(storage.isLittleEndian());
}

TEST_F(ByteValueStorageTests,
IsBigEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.Times(1)
		.WillOnce(Return(Endianness::BIG));

	EXPECT_TRUE(storage.isBigEndian());
}

TEST_F(ByteValueStorageTests,
IsUnknownEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.Times(1)
		.WillOnce(Return(Endianness::UNKNOWN));

	EXPECT_TRUE(storage.isUnknownEndian());
}

TEST_F(ByteValueStorageTests,
HexToBigFailsIfUnknownEndian) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.Times(1)
		.WillOnce(Return(Endianness::UNKNOWN));

	std::string dummy;
	EXPECT_FALSE(storage.hexToBig(dummy));
}

TEST_F(ByteValueStorageTests,
HexToBigIfAlreadyBigEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::BIG));

	std::string content = "0123456789ABCDEF";
	std::string expected = content;

	EXPECT_TRUE(storage.hexToBig(content));
	EXPECT_EQ(expected, content);
}

TEST_F(ByteValueStorageTests,
HexToBigFromLittleEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));
	EXPECT_CALL(storage, getBytesPerWord())
		.Times(1)
		.WillOnce(Return(4));
	EXPECT_CALL(storage, getNumberOfNibblesInByte())
		.Times(1)
		.WillOnce(Return(2));

	std::string content = "0123456789ABCDEF";
	std::string expected = "67452301EFCDAB89";

	EXPECT_TRUE(storage.hexToBig(content));
	EXPECT_EQ(expected, content);
}

TEST_F(ByteValueStorageTests,
HexToLittleFailsIfUnknownEndian) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.Times(1)
		.WillOnce(Return(Endianness::UNKNOWN));

	std::string dummy;
	EXPECT_FALSE(storage.hexToLittle(dummy));
}

TEST_F(ByteValueStorageTests,
HexToLittleIfAlreadyLittleEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));

	std::string content = "0123456789ABCDEF";
	std::string expected = content;

	EXPECT_TRUE(storage.hexToLittle(content));
	EXPECT_EQ(expected, content);
}

TEST_F(ByteValueStorageTests,
HexToLittleFromBigEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::BIG));
	EXPECT_CALL(storage, getBytesPerWord())
		.Times(1)
		.WillOnce(Return(4));
	EXPECT_CALL(storage, getNumberOfNibblesInByte())
		.Times(1)
		.WillOnce(Return(2));

	std::string content = "0123456789ABCDEF";
	std::string expected = "67452301EFCDAB89";

	EXPECT_TRUE(storage.hexToLittle(content));
	EXPECT_EQ(expected, content);
}

TEST_F(ByteValueStorageTests,
BitsToBigFailsIfUnknownEndian) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.Times(1)
		.WillOnce(Return(Endianness::UNKNOWN));

	std::string dummy;
	EXPECT_FALSE(storage.bitsToBig(dummy));
}

TEST_F(ByteValueStorageTests,
BitsToBigIfAlreadyBigEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::BIG));

	std::string content = "0111101001011100";
	std::string expected = content;

	EXPECT_TRUE(storage.bitsToBig(content));
	EXPECT_EQ(expected, content);
}

TEST_F(ByteValueStorageTests,
BitsToBigFromLittleEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));
	EXPECT_CALL(storage, getByteLength())
		.Times(1)
		.WillOnce(Return(8));

	std::string content = "0111101001011100";
	std::string expected = "0101111000111010";

	EXPECT_TRUE(storage.bitsToBig(content));
	EXPECT_EQ(expected, content);
}

TEST_F(ByteValueStorageTests,
BitsToLittleFailsIfUnknownEndian) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.Times(1)
		.WillOnce(Return(Endianness::UNKNOWN));

	std::string dummy;
	EXPECT_FALSE(storage.bitsToLittle(dummy));
}

TEST_F(ByteValueStorageTests,
BitsToLittleIfAlreadyLittleEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));

	std::string content = "0111101001011100";
	std::string expected = content;

	EXPECT_TRUE(storage.bitsToLittle(content));
	EXPECT_EQ(expected, content);
}

TEST_F(ByteValueStorageTests,
BitsToLittleFromBigEndianWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::BIG));
	EXPECT_CALL(storage, getByteLength())
		.Times(1)
		.WillOnce(Return(8));

	std::string content = "0111101001011100";
	std::string expected = "0101111000111010";

	EXPECT_TRUE(storage.bitsToLittle(content));
	EXPECT_EQ(expected, content);
}

TEST_F(ByteValueStorageTests,
GetNByteFailsIfGetXByteFails) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getXByte(_,_,_,_))
		.Times(4)
		.WillRepeatedly(Return(false));

	std::uint64_t dummy;
	EXPECT_FALSE(storage.get1Byte(0, dummy));
	EXPECT_FALSE(storage.get2Byte(0, dummy));
	EXPECT_FALSE(storage.get4Byte(0, dummy));
	EXPECT_FALSE(storage.get8Byte(0, dummy));
}

TEST_F(ByteValueStorageTests,
Get1ByteWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t width = 1;

	EXPECT_CALL(storage, getXByte(address,width,_,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(0x42), Return(true)));

	std::uint64_t val = 0;
	EXPECT_TRUE(storage.get1Byte(address, val));
	EXPECT_EQ(0x42, val);
}

TEST_F(ByteValueStorageTests,
Get2ByteWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t width = 2;

	EXPECT_CALL(storage, getXByte(address,width,_,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(0x4243), Return(true)));

	std::uint64_t val = 0;
	EXPECT_TRUE(storage.get2Byte(address, val));
	EXPECT_EQ(0x4243, val);
}

TEST_F(ByteValueStorageTests,
Get4ByteWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t width = 4;

	EXPECT_CALL(storage, getXByte(address,width,_,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(0xDEADBEEF), Return(true)));

	std::uint64_t val = 0;
	EXPECT_TRUE(storage.get4Byte(address, val));
	EXPECT_EQ(0xDEADBEEF, val);
}

TEST_F(ByteValueStorageTests,
Get8ByteWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t width = 8;

	EXPECT_CALL(storage, getXByte(address,width,_,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(0xDEADBEEFFEEDFACE), Return(true)));

	std::uint64_t val = 0;
	EXPECT_TRUE(storage.get8Byte(address, val));
	EXPECT_EQ(0xDEADBEEFFEEDFACE, val);
}

TEST_F(ByteValueStorageTests,
Get10ByteWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t size = 10;

	std::vector<std::uint8_t> rawData = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0xA0, 0xFD, 0x3F};
	EXPECT_CALL(storage, getXBytes(address,size,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(rawData), Return(true)));

	long double val = 0;
	EXPECT_TRUE(storage.get10Byte(address, val));
	EXPECT_DOUBLE_EQ(0.31348419189453125, val);
}

TEST_F(ByteValueStorageTests,
GetWordWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t width = 4;

	EXPECT_CALL(storage, getXByte(address,width,_,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(0xDEADBEEF), Return(true)));
	EXPECT_CALL(storage, getBytesPerWord())
		.Times(1)
		.WillOnce(Return(width));

	std::uint64_t val = 0;
	EXPECT_TRUE(storage.getWord(address, val));
	EXPECT_EQ(0xDEADBEEF, val);
}

TEST_F(ByteValueStorageTests,
GetFloatWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t size = 4;

	std::vector<std::uint8_t> rawData = {0xFA, 0x80, 0xA0, 0x3E};
	EXPECT_CALL(storage, getXBytes(address,size,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(rawData), Return(true)));

	float val = 0;
	EXPECT_TRUE(storage.getFloat(address, val));
	EXPECT_FLOAT_EQ(0.313484f, val);
}

TEST_F(ByteValueStorageTests,
GetDoubleWithoutMixedEndianWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t size = 8;

	std::vector<std::uint8_t> rawData = {0xD2, 0x6E, 0xF4, 0x31, 0x1F, 0x10, 0xD4, 0x3F};
	EXPECT_CALL(storage, getXBytes(address,size,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(rawData), Return(true)));
	EXPECT_CALL(storage, hasMixedEndianForDouble())
		.Times(1)
		.WillOnce(Return(false));

	double val = 0;
	EXPECT_TRUE(storage.getDouble(address, val));
	EXPECT_DOUBLE_EQ(0.313484, val);
}

TEST_F(ByteValueStorageTests,
GetDoubleWithMixedEndianWorks) {
	MockByteValueStorage storage;

	std::uint64_t address = 0;
	std::uint64_t size = 8;

	std::vector<std::uint8_t> rawData = {0x1F, 0x10, 0xD4, 0x3F, 0xD2, 0x6E, 0xF4, 0x31};
	EXPECT_CALL(storage, getXBytes(address,size,_))
		.Times(1)
		.WillOnce(DoAll(SetArgReferee<2>(rawData), Return(true)));
	EXPECT_CALL(storage, hasMixedEndianForDouble())
		.Times(1)
		.WillOnce(Return(true));

	double val = 0;
	EXPECT_TRUE(storage.getDouble(address, val));
	EXPECT_DOUBLE_EQ(0.313484, val);
}

TEST_F(ByteValueStorageTests,
GetNTBSWithUnlimitedSizeWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));
	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Le(5)),1,_,_))
		.Times(6)
		.WillOnce(DoAll(SetArgReferee<2>('a'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('b'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('c'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('d'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('e'), Return(true)))
		.WillRepeatedly(DoAll(SetArgReferee<2>(0x00), Return(true)));

	std::string loaded;
	EXPECT_TRUE(storage.getNTBS(0, loaded));
	EXPECT_EQ("abcde", loaded);
}

TEST_F(ByteValueStorageTests,
GetNTBSWithLimitedSizeWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));
	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Le(5)),1,_,_))
		.Times(5)
		.WillOnce(DoAll(SetArgReferee<2>('a'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('b'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('c'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('d'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('e'), Return(true)));

	std::string loaded;
	EXPECT_TRUE(storage.getNTBS(0, loaded, 5));
	EXPECT_EQ("abcde", loaded);
}

TEST_F(ByteValueStorageTests,
GetNTWSWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));
	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Lt(8)),2,_,_))
		.Times(4)
		.WillOnce(DoAll(SetArgReferee<2>(0xC2E1), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0xC2E9), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0xC2ED), Return(true)))
		.WillRepeatedly(DoAll(SetArgReferee<2>(0x0), Return(true)));

	std::vector<std::uint64_t> expected = { 0xC2E1, 0xC2E9, 0xC2ED, 0x0000 };

	std::vector<std::uint64_t> loaded;
	EXPECT_TRUE(storage.getNTWS(0, 2, loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(ByteValueStorageTests,
GetNTWSWithNonNiceCharacterFails) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));
	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Le(6)),2,_,_))
		.Times(3)
		.WillOnce(DoAll(SetArgReferee<2>('a'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('b'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0xC2ED), Return(true)));

	std::vector<std::uint64_t> dummy;
	EXPECT_FALSE(storage.getNTWSNice(0, 2, dummy));
}

TEST_F(ByteValueStorageTests,
GetNTWSNiceWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getEndianness())
		.WillRepeatedly(Return(Endianness::LITTLE));
	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Le(8)),2,_,_))
		.Times(4)
		.WillOnce(DoAll(SetArgReferee<2>('a'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('b'), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>('\n'), Return(true)))
		.WillRepeatedly(DoAll(SetArgReferee<2>(0x00), Return(true)));

	std::vector<std::uint64_t> expected = { 'a', 'b', '\n', 0x00 };

	std::vector<std::uint64_t> loaded;
	EXPECT_TRUE(storage.getNTWSNice(0, 2, loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(ByteValueStorageTests,
GetNByteArrayFailsIfGetXByteFails) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getXByte(_,_,_,_))
		.Times(4)
		.WillRepeatedly(Return(false));

	std::vector<std::uint64_t> dummy;
	EXPECT_FALSE(storage.get1ByteArray(0, dummy, 5));
	EXPECT_FALSE(storage.get2ByteArray(0, dummy, 5));
	EXPECT_FALSE(storage.get4ByteArray(0, dummy, 5));
	EXPECT_FALSE(storage.get8ByteArray(0, dummy, 5));
}

TEST_F(ByteValueStorageTests,
Get1ByteArrayWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Le(4)),1,_,_))
		.Times(4)
		.WillOnce(DoAll(SetArgReferee<2>(0x10), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x20), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x30), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x40), Return(true)));

	std::vector<std::uint64_t> expected = { 0x10, 0x20, 0x30, 0x40 };

	std::vector<std::uint64_t> loaded;
	EXPECT_TRUE(storage.get1ByteArray(0, loaded, 4));
	EXPECT_EQ(expected, loaded);
}

TEST_F(ByteValueStorageTests,
Get2ByteArrayWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Le(8)),2,_,_))
		.Times(4)
		.WillOnce(DoAll(SetArgReferee<2>(0x1000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x2000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x3000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x4000), Return(true)));

	std::vector<std::uint64_t> expected = { 0x1000, 0x2000, 0x3000, 0x4000 };

	std::vector<std::uint64_t> loaded;
	EXPECT_TRUE(storage.get2ByteArray(0, loaded, 4));
	EXPECT_EQ(expected, loaded);
}

TEST_F(ByteValueStorageTests,
Get4ByteArrayWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Le(16)),4,_,_))
		.Times(4)
		.WillOnce(DoAll(SetArgReferee<2>(0x10001000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x20002000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x30003000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x40004000), Return(true)));

	std::vector<std::uint64_t> expected = { 0x10001000, 0x20002000, 0x30003000, 0x40004000 };

	std::vector<std::uint64_t> loaded;
	EXPECT_TRUE(storage.get4ByteArray(0, loaded, 4));
	EXPECT_EQ(expected, loaded);
}

TEST_F(ByteValueStorageTests,
Get8ByteArrayWorks) {
	MockByteValueStorage storage;

	EXPECT_CALL(storage, getXByte(AllOf(Ge(0),Le(32)),8,_,_))
		.Times(4)
		.WillOnce(DoAll(SetArgReferee<2>(0x1000100010001000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x2000200020002000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x3000300030003000), Return(true)))
		.WillOnce(DoAll(SetArgReferee<2>(0x4000400040004000), Return(true)));

	std::vector<std::uint64_t> expected = { 0x1000100010001000, 0x2000200020002000, 0x3000300030003000, 0x4000400040004000 };

	std::vector<std::uint64_t> loaded;
	EXPECT_TRUE(storage.get8ByteArray(0, loaded, 4));
	EXPECT_EQ(expected, loaded);
}

} // namespace tests
} // namespace utils
} // namespace retdec
