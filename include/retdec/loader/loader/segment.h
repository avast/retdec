/**
 * @file include/retdec/loader/loader/segment.h
 * @brief Declaration of segment class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_RETDEC_LOADER_SEGMENT_H
#define RETDEC_LOADER_RETDEC_LOADER_SEGMENT_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "retdec/utils/range.h"
#include "retdec/fileformat/fftypes.h"
#include "retdec/fileformat/types/sec_seg/sec_seg.h"
#include "retdec/loader/loader/segment_data_source.h"
#include "retdec/loader/utils/range.h"

namespace retdec {
namespace loader {

class Segment
{
public:
	Segment(const retdec::fileformat::SecSeg* secSeg, std::uint64_t address, std::uint64_t size, std::unique_ptr<SegmentDataSource>&& dataSource);
	Segment(const Segment& segment);
	~Segment();

	const retdec::fileformat::SecSeg* getSecSeg() const;

	bool containsAddress(std::uint64_t address) const;
	std::uint64_t getAddress() const;
	std::uint64_t getEndAddress() const;
	std::uint64_t getPhysicalEndAddress() const;
	std::uint64_t getSize() const;
	std::uint64_t getPhysicalSize() const;
	retdec::utils::Range<std::uint64_t> getAddressRange() const;
	retdec::utils::Range<std::uint64_t> getPhysicalAddressRange() const;
	const retdec::utils::RangeContainer<std::uint64_t>& getNonDecodableAddressRanges() const;
	std::pair<const std::uint8_t*, std::uint64_t> getRawData() const;

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

	void addNonDecodableRange(retdec::utils::Range<std::uint64_t> range);

private:
	const retdec::fileformat::SecSeg* _secSeg;
	std::uint64_t _address;
	std::uint64_t _size;
	std::unique_ptr<SegmentDataSource> _dataSource;
	std::string _name;
	retdec::utils::RangeContainer<std::uint64_t> _nonDecodableRanges;
};

} // namespace loader
} // namespace retdec

#endif
