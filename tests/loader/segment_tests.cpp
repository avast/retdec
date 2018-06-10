/**
 * @file tests/loader/segment_tests.cpp
 * @brief Tests for the @c segment module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/loader/loader/segment.h"

using namespace ::testing;

namespace retdec {
namespace loader {
namespace tests {

class SegmentTests : public Test
{
public:
	std::unique_ptr<SegmentDataSource> makeDataSource(const std::vector<std::uint8_t>& data)
	{
		llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
		return std::make_unique<SegmentDataSource>(dataRef);
	}
};

TEST_F(SegmentTests,
InitializationWorks) {
	Segment seg(nullptr, 0x1000, 0x200, nullptr);
	seg.setName("segment0");

	EXPECT_EQ(0x1000, seg.getAddress());
	EXPECT_EQ(0x1200, seg.getEndAddress());
	EXPECT_EQ(0x200, seg.getSize());
	EXPECT_EQ("segment0", seg.getName());
}

TEST_F(SegmentTests,
CopyInitializationWorks) {
	Segment seg(nullptr, 0x1000, 0x200, nullptr);
	seg.setName("segment0");

	Segment copy(seg);

	EXPECT_EQ(0x1000, copy.getAddress());
	EXPECT_EQ(0x1200, copy.getEndAddress());
	EXPECT_EQ(0x200, copy.getSize());
	EXPECT_EQ("segment0", copy.getName());
}

TEST_F(SegmentTests,
GetAddressWorks) {
	Segment seg(nullptr, 0x1000, 0x200, nullptr);

	EXPECT_EQ(0x1000, seg.getAddress());
}

TEST_F(SegmentTests,
GetEndAddressWorks) {
	Segment seg(nullptr, 0x1000, 0x200, nullptr);

	EXPECT_EQ(0x1200, seg.getEndAddress());
}

TEST_F(SegmentTests,
GetPhysicalEndAddressWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, 0x100, makeDataSource(mockFileData));

	EXPECT_EQ(0x1007, seg.getPhysicalEndAddress());
}

TEST_F(SegmentTests,
GetPhysicalEndAddressInPureVirtualSegmentWorks) {
	Segment seg(nullptr, 0x1000, 0x100, nullptr);

	EXPECT_EQ(0x1001, seg.getPhysicalEndAddress());
}

TEST_F(SegmentTests,
GetSizeWorks) {
	Segment seg(nullptr, 0x1000, 0x200, nullptr);

	EXPECT_EQ(0x200, seg.getSize());
}

TEST_F(SegmentTests,
GetPhysicalSizeWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, 0x100, makeDataSource(mockFileData));

	EXPECT_EQ(0x7, seg.getPhysicalSize());
}

TEST_F(SegmentTests,
GetPhysicalSizeInPureVirtualSegmentWorks) {
	Segment seg(nullptr, 0x1000, 0x100, nullptr);

	EXPECT_EQ(0x0, seg.getPhysicalSize());
}

TEST_F(SegmentTests,
ContainsAddressWorks) {
	Segment seg(nullptr, 0x1000, 0x100, nullptr);

	EXPECT_TRUE(seg.containsAddress(0x1000));
	EXPECT_TRUE(seg.containsAddress(0x1080));
	EXPECT_TRUE(seg.containsAddress(0x10FF));
	EXPECT_FALSE(seg.containsAddress(0x1200));
	EXPECT_FALSE(seg.containsAddress(0x1500));
}

TEST_F(SegmentTests,
GetAddressRangeWorks) {
	Segment seg(nullptr, 0x1000, 0x100, nullptr);

	retdec::utils::Range<std::uint64_t> range = seg.getAddressRange();

	EXPECT_EQ(0x1000, range.getStart());
	EXPECT_EQ(0x1100, range.getEnd());
}

TEST_F(SegmentTests,
HasNameWorks) {
	Segment namelessSeg(nullptr, 0x1000, 0x100, nullptr);
	Segment namedSeg(nullptr, 0x1000, 0x100, nullptr);
	namedSeg.setName("segment0");

	EXPECT_FALSE(namelessSeg.hasName());
	EXPECT_TRUE(namedSeg.hasName());
}

TEST_F(SegmentTests,
GetBytesWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = mockFileData;
	std::vector<std::uint8_t> loaded;

	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
GetBytesWithOffsetAndSizeWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = { 0x12, 0x13, 0x14, 0x15 };
	std::vector<std::uint8_t> loaded;

	EXPECT_TRUE(seg.getBytes(loaded, 2, 4));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
GetBytesOutOfBoundsWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected;
	std::vector<std::uint8_t> loaded;

	EXPECT_FALSE(seg.getBytes(loaded, 50, 5));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
GetBytesPartiallyOutOfBoundsWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = { 0x15, 0x16 };
	std::vector<std::uint8_t> loaded;

	EXPECT_TRUE(seg.getBytes(loaded, 5, 5));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
GetBytesPartiallyOutOfBoundsWithGreaterMemorySizeWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, 0x100, makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = { 0x14, 0x15, 0x16, 0x00, 0x00 };
	std::vector<std::uint8_t> loaded;

	EXPECT_TRUE(seg.getBytes(loaded, 4, 5));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
GetBytesOutOfBoundsWithGreaterMemorySizeWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, 0x100, makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = { 0x00, 0x00, 0x00, 0x00 };
	std::vector<std::uint8_t> loaded;

	EXPECT_TRUE(seg.getBytes(loaded, 0x50, 4));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
SetBytesWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> value = { 0x20, 0x21, 0x22 };
	std::vector<std::uint8_t> expected = { 0x10, 0x20, 0x21, 0x22, 0x14, 0x15, 0x16 };
	std::vector<std::uint8_t> loaded;

	EXPECT_TRUE(seg.setBytes(value, 1));
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
SetBytesOutOfBoundsWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> value = { 0x20, 0x21, 0x22 };
	std::vector<std::uint8_t> expected = mockFileData;
	std::vector<std::uint8_t> loaded;

	EXPECT_FALSE(seg.setBytes(value, 10));
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
SetBytesPartiallyOutOfBoundsWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> value = { 0x20, 0x21, 0x22 };
	std::vector<std::uint8_t> expected = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x20 };
	std::vector<std::uint8_t> loaded;

	EXPECT_TRUE(seg.setBytes(value, 6));
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
GetBitsWorks) {
	std::vector<std::uint8_t> mockFileData = { 0xAB, 0xCD, 0xEF };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::string expected = "101010111100110111101111";
	std::string loaded;

	EXPECT_TRUE(seg.getBits(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
GetBitsOutOfBoundsWorks) {
	std::vector<std::uint8_t> mockFileData = { 0xAB, 0xCD, 0xEF };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::string dummy;
	EXPECT_FALSE(seg.getBits(dummy, 0x2000, 0x7));
}

TEST_F(SegmentTests,
ResizeToLesserSizeWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = { 0x10, 0x11 };
	std::vector<std::uint8_t> loaded;

	seg.resize(2);

	EXPECT_EQ(0x1000, seg.getAddress());
	EXPECT_EQ(2, seg.getSize());
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
ResizeToBiggerSizeWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x00, 0x00 };
	std::vector<std::uint8_t> loaded;

	seg.resize(9);

	EXPECT_EQ(0x1000, seg.getAddress());
	EXPECT_EQ(9, seg.getSize());
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
ShrinkWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = { 0x12, 0x13, 0x14 };
	std::vector<std::uint8_t> loaded;

	seg.shrink(0x1002, 3);

	EXPECT_EQ(0x1002, seg.getAddress());
	EXPECT_EQ(3, seg.getSize());
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
ShrinkToBiggerSizeForbiddenWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = mockFileData;
	std::vector<std::uint8_t> loaded;

	seg.shrink(0x1002, 50);

	EXPECT_EQ(0x1000, seg.getAddress());
	EXPECT_EQ(mockFileData.size(), seg.getSize());
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
ShrinkToAddressOutOfBoundsWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = mockFileData;
	std::vector<std::uint8_t> loaded;

	seg.shrink(0x800, 5);

	EXPECT_EQ(0x1000, seg.getAddress());
	EXPECT_EQ(mockFileData.size(), seg.getSize());
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
ShrinkWithAddressWithinRangeButInvalidSizeForbiddenWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, mockFileData.size(), makeDataSource(mockFileData));

	std::vector<std::uint8_t> expected = mockFileData;
	std::vector<std::uint8_t> loaded;

	seg.shrink(0x1005, 3);

	EXPECT_EQ(0x1000, seg.getAddress());
	EXPECT_EQ(mockFileData.size(), seg.getSize());
	EXPECT_TRUE(seg.getBytes(loaded));
	EXPECT_EQ(expected, loaded);
}

TEST_F(SegmentTests,
GetRawDataWorks) {
	std::vector<std::uint8_t> mockFileData = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

	Segment seg(nullptr, 0x1000, 0x100, makeDataSource(mockFileData));

	auto rawData = seg.getRawData();

	EXPECT_EQ(mockFileData.data(), rawData.first);
	EXPECT_EQ(7, rawData.second);
}

TEST_F(SegmentTests,
GetRawDataWithNoDataSegmentWorks) {
	Segment seg(nullptr, 0x1000, 0x100, nullptr);

	auto rawData = seg.getRawData();

	EXPECT_EQ(nullptr, rawData.first);
	EXPECT_EQ(0, rawData.second);
}

} // namespace loader
} // namespace retdec
} // namespace tests
