/**
 * @file include/retdec/loader/loader/segment_data_source.h
 * @brief Declaration of segment data source class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_RETDEC_LOADER_SEGMENT_DATA_SOURCE_H
#define RETDEC_LOADER_RETDEC_LOADER_SEGMENT_DATA_SOURCE_H

#include <cstdint>
#include <string>
#include <vector>

#include <llvm/ADT/StringRef.h>

namespace retdec {
namespace loader {

class SegmentDataSource
{
public:
	SegmentDataSource();
	SegmentDataSource(const llvm::StringRef& data);
	SegmentDataSource(const SegmentDataSource& dataLoader);
	virtual ~SegmentDataSource();

	bool isDataSet() const;

	const std::uint8_t* getData() const;
	std::uint64_t getDataSize() const;

	void resize(std::uint64_t newSize);
	bool shrink(std::uint64_t newOffset, std::uint64_t newSize);

	bool loadData(std::uint64_t loadOffset, std::uint64_t loadSize, std::vector<std::uint8_t>& data) const;
	bool saveData(std::uint64_t saveOffset, std::uint64_t saveSize, const std::vector<std::uint8_t>& data);

private:
	llvm::StringRef _data;
};

} // namespace loader
} // namespace retdec

#endif
