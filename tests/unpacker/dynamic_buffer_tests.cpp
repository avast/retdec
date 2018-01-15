/**
* @file tests/unpacker/dynamic_buffer_tests.cpp
* @brief Tests for the @c dynamic_buffer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <vector>

#include <gtest/gtest.h>

#include "retdec/fileformat/fftypes.h"
#include "retdec/unpacker/dynamic_buffer.h"

using namespace ::testing;
using namespace retdec::utils;

namespace retdec {
namespace unpacker {
namespace tests {

class DynamicBufferTests : public Test {};

TEST_F(DynamicBufferTests,
DefaultInitializationWorks) {
	DynamicBuffer buffer;

	EXPECT_EQ(Endianness::LITTLE, buffer.getEndianness());
	EXPECT_EQ(0, buffer.getCapacity());
	EXPECT_EQ(0, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
CapacityInitializationWorks) {
	DynamicBuffer buffer(5);

	EXPECT_EQ(5, buffer.getCapacity());
	EXPECT_EQ(0, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
DataInitializationWorks) {
	std::vector<uint8_t> data = { 0x01, 0x02, 0x03, 0x04 };
	DynamicBuffer buffer(data);

	EXPECT_EQ(4, buffer.getCapacity());
	EXPECT_EQ(4, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
CopyInitializationWorks) {
	std::vector<uint8_t> data = { 0xFF, 0xFF };
	DynamicBuffer buffer(data, Endianness::BIG);
	DynamicBuffer copiedBuffer(buffer);

	EXPECT_EQ(buffer.getEndianness(), copiedBuffer.getEndianness());
	EXPECT_EQ(buffer.getCapacity(), copiedBuffer.getCapacity());
	EXPECT_EQ(buffer.getRealDataSize(), copiedBuffer.getRealDataSize());
	EXPECT_EQ(buffer.getBuffer(), copiedBuffer.getBuffer());
}

TEST_F(DynamicBufferTests,
PartialCopyInitializationWorks) {
	std::vector<uint8_t> data = { 0x13, 0x37, 0x42, 0x24 };
	DynamicBuffer buffer(data, Endianness::BIG);
	DynamicBuffer copiedBuffer(buffer, 1, 2);

	EXPECT_EQ(buffer.getEndianness(), copiedBuffer.getEndianness());
	EXPECT_EQ(2, copiedBuffer.getCapacity());
	EXPECT_EQ(2, copiedBuffer.getRealDataSize());
	EXPECT_EQ(std::vector<uint8_t>({ 0x37, 0x42 }), copiedBuffer.getBuffer());
}

TEST_F(DynamicBufferTests,
AssignOperatorWorks) {
	std::vector<uint8_t> data = { 0x24, 0x42, 0x37, 0x13 };
	DynamicBuffer buffer(data, Endianness::BIG);
	DynamicBuffer copiedBuffer = buffer;

	EXPECT_EQ(buffer.getEndianness(), copiedBuffer.getEndianness());
	EXPECT_EQ(buffer.getCapacity(), copiedBuffer.getCapacity());
	EXPECT_EQ(buffer.getRealDataSize(), copiedBuffer.getRealDataSize());
	EXPECT_EQ(buffer.getBuffer(), copiedBuffer.getBuffer());
}

TEST_F(DynamicBufferTests,
GetEndiannessWorks) {
	DynamicBuffer beBuffer(Endianness::BIG);
	DynamicBuffer leBuffer(Endianness::LITTLE);

	EXPECT_EQ(Endianness::BIG, beBuffer.getEndianness());
	EXPECT_EQ(Endianness::LITTLE, leBuffer.getEndianness());
}

TEST_F(DynamicBufferTests,
SetEndiannessWorks) {
	DynamicBuffer buffer(Endianness::BIG);
	buffer.setEndianness(Endianness::LITTLE);

	EXPECT_EQ(Endianness::LITTLE, buffer.getEndianness());
}

TEST_F(DynamicBufferTests,
GetCapacityWorks) {
	DynamicBuffer buffer(42);

	EXPECT_EQ(42, buffer.getCapacity());
}

TEST_F(DynamicBufferTests,
SetCapacityWorks) {
	DynamicBuffer buffer;
	buffer.setCapacity(24);

	EXPECT_EQ(24, buffer.getCapacity());
}

TEST_F(DynamicBufferTests,
EraseWorks) {
	std::vector<uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	DynamicBuffer buffer(data);
	buffer.erase(1, 2);

	EXPECT_EQ(2, buffer.getRealDataSize());
	EXPECT_EQ(4, buffer.getCapacity());
	EXPECT_EQ(std::vector<uint8_t>({ 0x10, 0x13 }), buffer.getBuffer());
}

TEST_F(DynamicBufferTests,
ErasePartiallyOutOfBoundsForbidden) {
	std::vector<uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	DynamicBuffer buffer(data);
	buffer.erase(2, 5);

	EXPECT_EQ(2, buffer.getRealDataSize());
	EXPECT_EQ(4, buffer.getCapacity());
	EXPECT_EQ(std::vector<uint8_t>({ 0x10, 0x11 }), buffer.getBuffer());
}

TEST_F(DynamicBufferTests,
EraseOutOfBoundsForbidden) {
	std::vector<uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	DynamicBuffer buffer(data);
	buffer.erase(5, 5);

	EXPECT_EQ(4, buffer.getRealDataSize());
	EXPECT_EQ(4, buffer.getCapacity());
	EXPECT_EQ(std::vector<uint8_t>({ 0x10, 0x11, 0x12, 0x13 }), buffer.getBuffer());
}

TEST_F(DynamicBufferTests,
GetBufferWorks) {
	std::vector<uint8_t> data = { 0x20, 0x21, 0x22 };
	DynamicBuffer buffer(data);

	EXPECT_EQ(data, buffer.getBuffer());
}

TEST_F(DynamicBufferTests,
GetRawBufferWorks) {
	std::vector<uint8_t> data = { 0x30, 0x31, 0x32 };
	DynamicBuffer buffer(data);

	const uint8_t* rawData = buffer.getRawBuffer();
	EXPECT_EQ(data[0], rawData[0]);
	EXPECT_EQ(data[1], rawData[1]);
	EXPECT_EQ(data[2], rawData[2]);
}

TEST_F(DynamicBufferTests,
SingleByteReadWorks) {
	std::vector<uint8_t> data = { 0x40, 0x41, 0x42 };
	DynamicBuffer buffer(data);

	EXPECT_EQ(data[1], buffer.read<uint8_t>(1));
}

TEST_F(DynamicBufferTests,
MultiByteLittleEndianReadWorks) {
	std::vector<uint8_t> data = { 0x50, 0x51, 0x52, 0x53 };
	DynamicBuffer buffer(data, Endianness::LITTLE);

	EXPECT_EQ(0x53525150, buffer.read<uint32_t>(0));
}

TEST_F(DynamicBufferTests,
MultiByteBigEndianReadWorks) {
	std::vector<uint8_t> data = { 0x50, 0x51, 0x52, 0x53 };
	DynamicBuffer buffer(data, Endianness::BIG);

	EXPECT_EQ(0x50515253, buffer.read<uint32_t>(0));
}

TEST_F(DynamicBufferTests,
ReadBeyondRealDataSizeWorks) {
	std::vector<uint8_t> data = { 0x60 };
	DynamicBuffer buffer(data);
	buffer.setCapacity(3);

	EXPECT_EQ(0x0, buffer.read<uint8_t>(2));
	EXPECT_EQ(1, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
ReadBeyondCapacityeWorks) {
	std::vector<uint8_t> data = { 0x60 };
	DynamicBuffer buffer(data);

	EXPECT_EQ(0x0, buffer.read<uint8_t>(2));
	EXPECT_EQ(1, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
PartialReadBeyondRealDataSizeWorks) {
	std::vector<uint8_t> data = { 0x60, 0x61 };
	DynamicBuffer buffer(data, Endianness::LITTLE);
	buffer.setCapacity(5);

	EXPECT_EQ(0x0061, buffer.read<uint16_t>(1));
	EXPECT_EQ(2, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
PartialReadBeyondCapacityWorks) {
	std::vector<uint8_t> data = { 0x60, 0x61 };
	DynamicBuffer buffer(data, Endianness::LITTLE);

	EXPECT_EQ(0x0061, buffer.read<uint16_t>(1));
	EXPECT_EQ(2, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
ReadNullTerminatedStringWorks) {
	std::vector<uint8_t> strData = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x48 };
	DynamicBuffer buffer(strData);

	EXPECT_EQ("Hello", buffer.readString(0));
}

TEST_F(DynamicBufferTests,
ReadLengthTerminatedStringWorks) {
	std::vector<uint8_t> strData = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x48 };
	DynamicBuffer buffer(strData);

	EXPECT_EQ("Hell", buffer.readString(0, 4));
}

TEST_F(DynamicBufferTests,
LittleEndianReadOnBigEndianBufferWorks) {
	std::vector<uint8_t> data = { 0xB0, 0xB1, 0xB2, 0xB3 };
	DynamicBuffer buffer(data, Endianness::BIG);

	EXPECT_EQ(0xB3B2B1B0, buffer.read<uint32_t>(0, Endianness::LITTLE));
}

TEST_F(DynamicBufferTests,
BigEndianReadOnLittleEndianBufferWorks) {
	std::vector<uint8_t> data = { 0xB0, 0xB1, 0xB2, 0xB3 };
	DynamicBuffer buffer(data, Endianness::LITTLE);

	EXPECT_EQ(0xB0B1B2B3, buffer.read<uint32_t>(0, Endianness::BIG));
}

TEST_F(DynamicBufferTests,
SingleByteWriteWorks) {
	DynamicBuffer buffer(1);
	buffer.write<uint8_t>(0x42, 0);

	uint8_t valueWritten = buffer.read<uint8_t>(0);
	EXPECT_EQ(0x42, valueWritten);
	EXPECT_EQ(1, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
MultiByteLittleEndianWriteWorks) {
	DynamicBuffer buffer(4, Endianness::LITTLE);
	buffer.write<uint32_t>(0x73727170, 0);

	EXPECT_EQ(std::vector<uint8_t>({ 0x70, 0x71, 0x72, 0x73 }), buffer.getBuffer());
	EXPECT_EQ(4, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
MultiByteBigEndianWriteWorks) {
	DynamicBuffer buffer(4, Endianness::BIG);
	buffer.write<uint32_t>(0x73727170, 0);

	EXPECT_EQ(std::vector<uint8_t>({{ 0x73, 0x72, 0x71, 0x70 }}), buffer.getBuffer());
	EXPECT_EQ(4, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
SparseWriteWorks) {
	DynamicBuffer buffer(2);
	buffer.write<uint8_t>(0x80, 1);

	uint8_t sparseValue = buffer.read<uint8_t>(0);
	EXPECT_EQ(0x0, sparseValue);
}

TEST_F(DynamicBufferTests,
WriteBeyondCapacityWorks) {
	std::vector<uint8_t> data = { 0x90, 0x91 };
	DynamicBuffer buffer(data);
	buffer.write<uint8_t>(0x92, 2);

	EXPECT_EQ(data, buffer.getBuffer());
	EXPECT_EQ(2, buffer.getCapacity());
	EXPECT_EQ(2, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
PartialWriteBeyondCapacityWorks) {
	std::vector<uint8_t> data = { 0xA0, 0xA1 };
	DynamicBuffer buffer(data);
	buffer.write<uint16_t>(0xAEAF, 1);

	EXPECT_EQ(std::vector<uint8_t>({ 0xA0, 0xAF }), buffer.getBuffer());
	EXPECT_EQ(2, buffer.getCapacity());
	EXPECT_EQ(2, buffer.getRealDataSize());
}

TEST_F(DynamicBufferTests,
LittleEndianWriteOnBigEndianBufferWorks) {
	DynamicBuffer buffer(4, Endianness::BIG);
	buffer.write<uint32_t>(0xC3C2C1C0, 0, Endianness::LITTLE);

	EXPECT_EQ(std::vector<uint8_t>({ 0xC0, 0xC1, 0xC2, 0xC3 }), buffer.getBuffer());
}

TEST_F(DynamicBufferTests,
BigEndianWriteOnLittleEndianBufferWorks) {
	DynamicBuffer buffer(4, Endianness::LITTLE);
	buffer.write<uint32_t>(0xC3C2C1C0, 0, Endianness::BIG);

	EXPECT_EQ(std::vector<uint8_t>({ 0xC3, 0xC2, 0xC1, 0xC0 }), buffer.getBuffer());
}

TEST_F(DynamicBufferTests,
ForEachWorks) {
	uint8_t count = 0;
	DynamicBuffer buffer({ 0xD0, 0xD1, 0xD2, 0xD3, 0xD4 });
	buffer.forEach([&count](uint8_t& byte) {
			if (count == 2)
			{
				byte = 0x00;
				return;
			}

			count++;
			byte += 1;
		});

	EXPECT_EQ(std::vector<uint8_t>({ 0xD1, 0xD2, 0x00, 0x00, 0x00 }), buffer.getBuffer());
}

TEST_F(DynamicBufferTests,
ForEachReverseWorks) {
	uint8_t count = 0;
	DynamicBuffer buffer({ 0xD0, 0xD1, 0xD2, 0xD3, 0xD4 });
	buffer.forEachReverse([&count](uint8_t& byte) {
			if (count == 2)
			{
				byte = 0x00;
				return;
			}

			count++;
			byte += 1;
		});

	EXPECT_EQ(std::vector<uint8_t>({ 0x00, 0x00, 0x00, 0xD4, 0xD5 }), buffer.getBuffer());
}

} // namespace unpacker
} // namespace retdec
} // namespace tests
