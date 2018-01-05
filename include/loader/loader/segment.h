/**
 * @file include/loader/loader/segment.h
 * @brief Declaration of segment class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_LOADER_SEGMENT_H
#define LOADER_LOADER_SEGMENT_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "tl-cpputils/range.h"
#include "fileformat/fftypes.h"
#include "fileformat/types/sec_seg/sec_seg.h"
#include "loader/loader/segment_data_source.h"
#include "loader/utils/range.h"

namespace loader {

class Segment
{
public:
	Segment(const fileformat::SecSeg* secSeg, std::uint64_t address, std::uint64_t size, std::unique_ptr<SegmentDataSource>&& dataSource);
	Segment(const Segment& segment);
	~Segment();

	const fileformat::SecSeg* getSecSeg() const;

	bool containsAddress(std::uint64_t address) const;
	std::uint64_t getAddress() const;
	std::uint64_t getEndAddress() const;
	std::uint64_t getPhysicalEndAddress() const;
	std::uint64_t getSize() const;
	std::uint64_t getPhysicalSize() const;
	tl_cpputils::Range<std::uint64_t> getAddressRange() const;
	tl_cpputils::Range<std::uint64_t> getPhysicalAddressRange() const;
	const tl_cpputils::RangeContainer<std::uint64_t>& getNonDecodableAddressRanges() const;

	bool hasName() const;
	const std::string& getName() const;
	void setName(const std::string& name);

	bool getBytes(std::vector<unsigned char>& result) const;
	bool getBytes(std::vector<unsigned char>& result, std::uint64_t addressOffset, std::uint64_t size) const;
	bool getBits(std::string& result) const;
	bool getBits(std::string& result, std::uint64_t addressOffset, std::uint64_t bytesCount) const;

	bool setBytes(const std::vector<unsigned char>& value, std::uint64_t addressOffset);

	void resize(std::uint64_t newSize);
	void shrink(std::uint64_t shrinkOffset, std::uint64_t newSize);

	void addNonDecodableRange(tl_cpputils::Range<std::uint64_t> range);

private:
	const fileformat::SecSeg* _secSeg;
	std::uint64_t _address;
	std::uint64_t _size;
	std::unique_ptr<SegmentDataSource> _dataSource;
	std::string _name;
	tl_cpputils::RangeContainer<std::uint64_t> _nonDecodableRanges;
};

} // namespace loader

#endif
