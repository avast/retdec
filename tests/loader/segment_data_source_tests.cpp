/**
 * @file tests/loader/segment_data_source_tests.cpp
 * @brief Tests for the @c segment_data_source module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/loader/loader/segment_data_source.h"

using namespace ::testing;

namespace retdec {
namespace loader {
namespace tests {

#define EXPECT_ITERABLE_EQ(expected, actual, count) { \
	for (std::size_t i = 0; i < count; ++i) \
		EXPECT_EQ(expected[i], actual[i]); \
}

class SegmentDataSourceTests : public Test {};

TEST_F(SegmentDataSourceTests,
DefaultInitializationWorks) {
	SegmentDataSource dataSource;

	EXPECT_FALSE(dataSource.isDataSet());
}

TEST_F(SegmentDataSourceTests,
CustomInitializationWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	EXPECT_EQ(data.size(), dataSource.getDataSize());
	EXPECT_ITERABLE_EQ(data, dataSource.getData(), data.size());
}

TEST_F(SegmentDataSourceTests,
CopyInitializationWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);
	SegmentDataSource dataSourceCopy(dataSource);

	EXPECT_EQ(dataSource.getData(), dataSourceCopy.getData());
	EXPECT_EQ(dataSource.getDataSize(), dataSourceCopy.getDataSize());
}

TEST_F(SegmentDataSourceTests,
IsDataSetWorks) {
	std::vector<std::uint8_t> data  = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSetSource(dataRef);
	llvm::StringRef dataRef2 = llvm::StringRef(nullptr, 0);
	SegmentDataSource dataNotSetSource(dataRef2);

	EXPECT_TRUE(dataSetSource.isDataSet());
	EXPECT_FALSE(dataNotSetSource.isDataSet());
}

TEST_F(SegmentDataSourceTests,
GetDataWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	EXPECT_EQ(data.data(), dataSource.getData());
}

TEST_F(SegmentDataSourceTests,
GetDataSizeWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	EXPECT_EQ(data.size(), dataSource.getDataSize());
}

TEST_F(SegmentDataSourceTests,
ResizeToBiggerSizeForbiddenWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	dataSource.resize(10);

	EXPECT_EQ(data.size(), dataSource.getDataSize());
}

TEST_F(SegmentDataSourceTests,
ResizeToLowerSizeWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	dataSource.resize(2);

	EXPECT_EQ(2, dataSource.getDataSize());
}

TEST_F(SegmentDataSourceTests,
ShrinkChangingOnlySizeWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	EXPECT_TRUE(dataSource.shrink(0, 2));
	EXPECT_EQ(2, dataSource.getDataSize());
	EXPECT_ITERABLE_EQ(data, dataSource.getData(), dataSource.getDataSize());
}

TEST_F(SegmentDataSourceTests,
ShrinkChangingOnlyOffsetWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> expected(data.begin() + 2, data.end());

	EXPECT_TRUE(dataSource.shrink(2, data.size()));
	EXPECT_EQ(2, dataSource.getDataSize());
	EXPECT_ITERABLE_EQ(expected, dataSource.getData(), dataSource.getDataSize());
}

TEST_F(SegmentDataSourceTests,
ShrinkChangingOffsetAndSizeWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> expected(data.begin() + 2, data.end());

	EXPECT_TRUE(dataSource.shrink(2, 2));
	EXPECT_EQ(2, dataSource.getDataSize());
	EXPECT_ITERABLE_EQ(expected, dataSource.getData(), dataSource.getDataSize());
}

TEST_F(SegmentDataSourceTests,
ShrinkToBiggerSizeForbiddenWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	EXPECT_FALSE(dataSource.shrink(1, 5));
	EXPECT_EQ(data.size(), dataSource.getDataSize());
	EXPECT_ITERABLE_EQ(data, dataSource.getData(), dataSource.getDataSize());
}

TEST_F(SegmentDataSourceTests,
ShrinkToOffsetOutOfBoundsWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> expected = {};

	EXPECT_TRUE(dataSource.shrink(10, data.size()));
	EXPECT_EQ(0, dataSource.getDataSize());
	EXPECT_FALSE(dataSource.isDataSet());
}

TEST_F(SegmentDataSourceTests,
LoadDataWithUnsetDataWorks) {
	llvm::StringRef emptyRef = llvm::StringRef(nullptr, 0);
	SegmentDataSource dataSource(emptyRef);

	std::vector<std::uint8_t> result;
	EXPECT_FALSE(dataSource.isDataSet());
	EXPECT_FALSE(dataSource.loadData(0, 4, result));
}

TEST_F(SegmentDataSourceTests,
LoadDataFromOffsetOutOfBoundsWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> result;
	EXPECT_FALSE(dataSource.loadData(5, 1, result));
}

TEST_F(SegmentDataSourceTests,
LoadDataPartiallyExceedingSizeWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> expected = { 0x12, 0x13 };

	std::vector<std::uint8_t> result;
	EXPECT_TRUE(dataSource.loadData(2, 3, result));
	EXPECT_EQ(expected, result);
}

TEST_F(SegmentDataSourceTests,
LoadDataWithCorrectOffsetAndSizeWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> expected = { 0x11, 0x12 };

	std::vector<std::uint8_t> result;
	EXPECT_TRUE(dataSource.loadData(1, 2, result));
	EXPECT_EQ(expected, result);
}

TEST_F(SegmentDataSourceTests,
SaveDataWithUnsetDataWorks) {
	llvm::StringRef emptyRef = llvm::StringRef(nullptr, 0);
	SegmentDataSource dataSource(emptyRef);

	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12 };
	EXPECT_FALSE(dataSource.isDataSet());
	EXPECT_FALSE(dataSource.saveData(0, data.size(), data));
}

TEST_F(SegmentDataSourceTests,
SaveDataWithOffsetOutOfBoundsWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> value = { 0x20, 0x21, 0x22 };
	EXPECT_FALSE(dataSource.saveData(5, value.size(), value));
}

TEST_F(SegmentDataSourceTests,
SaveDataPartiallyExceedingSizeWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> result;
	std::vector<std::uint8_t> expected = { 0x10, 0x11, 0x20, 0x21 };

	std::vector<std::uint8_t> value = { 0x20, 0x21, 0x22 };
	EXPECT_TRUE(dataSource.saveData(2, value.size(), value));
	EXPECT_TRUE(dataSource.loadData(0, data.size(), result));
	EXPECT_EQ(data.size(), dataSource.getDataSize());
	EXPECT_EQ(expected, result);
}

TEST_F(SegmentDataSourceTests,
SaveDataWithCorrectOffsetAndSizeWorks) {
	std::vector<std::uint8_t> data = { 0x10, 0x11, 0x12, 0x13 };
	llvm::StringRef dataRef = llvm::StringRef(reinterpret_cast<const char*>(data.data()), data.size());
	SegmentDataSource dataSource(dataRef);

	std::vector<std::uint8_t> result;
	std::vector<std::uint8_t> expected = { 0x10, 0x20, 0x21, 0x22 };

	std::vector<std::uint8_t> value = { 0x20, 0x21, 0x22 };
	EXPECT_TRUE(dataSource.saveData(1, value.size(), value));
	EXPECT_TRUE(dataSource.loadData(0, data.size(), result));
	EXPECT_EQ(data.size(), dataSource.getDataSize());
	EXPECT_EQ(expected, result);
}

} // namespace loader
} // namespace retdec
} // namespace tests
