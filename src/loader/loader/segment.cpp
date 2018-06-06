/**
 * @file src/loader/loader/segment.cpp
 * @brief Implementation of segment class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cstring>

#include "retdec/utils/conversion.h"
#include "retdec/loader/loader/segment.h"

namespace retdec {
namespace loader {

Segment::Segment(const retdec::fileformat::SecSeg* secSeg, std::uint64_t address, std::uint64_t size, std::unique_ptr<SegmentDataSource>&& dataSource)
	: _secSeg(secSeg), _address(address), _size(size), _dataSource(std::move(dataSource)), _name("")
{
}

Segment::Segment(const Segment& segment) : _secSeg(segment._secSeg), _address(segment._address), _size(segment._size),
	_dataSource(segment._dataSource ? std::make_unique<SegmentDataSource>(*segment._dataSource.get()) : nullptr), _name(segment._name)
{
}

Segment::~Segment()
{
}

/**
 * Returns associated section or segment, which was used for loading of this segment.
 *
 * @return Associated section or segment. If no section or segment is associated, returns nullptr.
 */
const retdec::fileformat::SecSeg* Segment::getSecSeg() const
{
	return _secSeg;
}

/**
 * Returns an address the segment is loaded at.
 *
 * @return Address of the segment.
 */
std::uint64_t Segment::getAddress() const
{
	return _address;
}

/**
 * Returns the last valid address of the segment.
 *
 * @return End address of the segment.
 */
std::uint64_t Segment::getEndAddress() const
{
	return getSize() ? getAddress() + getSize() : getAddress() + 1;
}

/**
 * Returns the last address of the segment that contains physical data from the file.
 *
 * @return End address of the physical data of the segment.
 */
std::uint64_t Segment::getPhysicalEndAddress() const
{
	return getPhysicalSize() ? getAddress() + getPhysicalSize() : getAddress() + 1;
}

/**
 * Returns the loaded size of the segment.
 *
 * @return The size of the segment.
 */
std::uint64_t Segment::getSize() const
{
	return _size;
}

/**
 * Returns the size of the physical data that is loaded for the file. If the physical size is greater than virtual,
 * virtual is returned instead.
 *
 * @return The physical size of the segment.
 */
std::uint64_t Segment::getPhysicalSize() const
{
	return _dataSource ? std::min(_dataSource->getDataSize(), getSize()) : 0;
}

/**
 * Returns the address range. Range goes <getAddress(), getEndAddress()>.
 *
 * @return Address range.
 */
retdec::utils::Range<std::uint64_t> Segment::getAddressRange() const
{
	return retdec::utils::Range<std::uint64_t>(getAddress(), getEndAddress());
}

/**
 * Returns the address range. Range goes <getAddress(), getEndAddress()>.
 *
 * @return Address range.
 */
retdec::utils::Range<std::uint64_t> Segment::getPhysicalAddressRange() const
{
	return retdec::utils::Range<std::uint64_t>(getAddress(), getPhysicalEndAddress());
}

/**
 * Returns the list of address ranges which should be ignored during instruction decoding.
 *
 * @return List of address ranges.
 */
const retdec::utils::RangeContainer<std::uint64_t>& Segment::getNonDecodableAddressRanges() const
{
	return _nonDecodableRanges;
}

/**
 * Returns the raw data of the segment in its size. Returns null pointer and 0 for segments
 * without any source of phyiscal data.
 *
 * @return Raw data pointer and size.
 */
std::pair<const std::uint8_t*, std::uint64_t> Segment::getRawData() const
{
	return _dataSource ? std::make_pair(_dataSource->getData(), getPhysicalSize()) : std::make_pair(nullptr, 0) ;
}

/**
 * Returns whether the segment is named segment.
 *
 * @return True if set, otherwise false.
 */
bool Segment::hasName() const
{
	return getName() != "";
}

/**
 * Returns the name of the segment, if it has one.
 *
 * @return Name of the segment.
 */
const std::string& Segment::getName() const
{
	return _name;
}

/**
 * Sets the name to the segment.
 *
 * @param name New name of the segment.
 */
void Segment::setName(const std::string& name)
{
	_name = name;
}

/**
 * Returns whether the segment contains specified address.
 *
 * @param address The address to check.
 *
 * @return True if contains, otherwise false.
 */
bool Segment::containsAddress(std::uint64_t address) const
{
	return ((getAddress() <= address) && (address < getEndAddress()));
}

/**
 * Get the whole content of segment as bytes.
 *
 * @param result Read bytes in integer representation.
 *
 * @return True if read was successful, otherwise false.
 */
bool Segment::getBytes(std::vector<unsigned char>& result) const
{
	return getBytes(result, 0, getSize());
}

/**
 * Get content of segment as bytes.
 *
 * @param result Read bytes in integer representation.
 * @param addressOffset First byte of the segment to be read (0 means first byte of segment).
 * @param size Number of bytes for read.
 *
 * @return True if read was successful, otherwise false.
 */
bool Segment::getBytes(std::vector<unsigned char>& result, std::uint64_t addressOffset, std::uint64_t size) const
{
	if (addressOffset >= getSize())
		return false;

	result.clear();

	if (_dataSource)
		_dataSource->loadData(addressOffset, size, result);

	// Data source may contain less data than we are representing with this segment
	//   so we just fill the rest with zeroes.
	size = addressOffset + size >= getSize() ? getSize() - addressOffset : size;
	if (result.size() < size)
		result.resize(size, 0);

	return true;
}

/**
 * Get content of segment as bits in string representation.
 *
 * @param result Bits in string representation.
 *
 * @return True if read was successful, otherwise false.
 */
bool Segment::getBits(std::string& result) const
{
	return getBits(result, 0, getSize());
}

/**
 * Get content of segment as bits in string representation.
 *
 * @param result Bits in string representation.
 * @param addressOffset First byte of the segment to be read (0 means first byte of segment).
 * @param bytesCount Number of bytes for read.
 *
 * @return True if read was successful, otherwise false.
 */
bool Segment::getBits(std::string& result, std::uint64_t addressOffset, std::uint64_t bytesCount) const
{
	std::vector<std::uint8_t> bytes;
	if (!getBytes(bytes, addressOffset, bytesCount))
		return false;

	result = retdec::utils::bytesToBits(bytes);
	return true;
}

bool Segment::setBytes(const std::vector<unsigned char>& value, std::uint64_t addressOffset)
{
	if (addressOffset >= getSize())
		return false;

	std::size_t size = addressOffset + value.size() > getSize() ? getSize() - addressOffset : value.size();
	if (_dataSource != nullptr)
		_dataSource->saveData(addressOffset, size, value);

	return true;
}

/**
 * Resizes segment to a given size.
 *
 * @param newSize The new size of segment.
 */
void Segment::resize(std::uint64_t newSize)
{
	_size = newSize;

	if (_dataSource != nullptr)
		_dataSource->resize(newSize);
}

/**
 * Shrinks the segment to start from the new given address and has new given size.
 * The address must already be valid address in the segment and size cannot exceed
 * the current upper bound of the segment.
 *
 * @param newAddress The new address of segment.
 * @param newSize The new size of segment.
 */
void Segment::shrink(std::uint64_t newAddress, std::uint64_t newSize)
{
	if (!containsAddress(newAddress))
		return;

	if (newSize > getSize())
		return;

	if (newAddress + newSize > getAddress() + getSize())
		return;

	// Store the offset in the segment where the shrinking starts til we known the old address
	std::uint64_t shrinkOffset = newAddress - _address;

	_address = newAddress;
	_size = newSize;

	if (_dataSource != nullptr)
		_dataSource->shrink(shrinkOffset, newSize);
}

/**
 * Adds address range which should be ignored during the instruction decoding.
 *
 * @param range Range to add.
 */
void Segment::addNonDecodableRange(retdec::utils::Range<std::uint64_t> range)
{
	retdec::utils::Range<std::uint64_t> secRange(getAddress(), getPhysicalEndAddress());
	if (!secRange.overlaps(range))
		return;

	range.setStartEnd(
			std::max(range.getStart(), secRange.getStart()),
			std::min(range.getEnd(), secRange.getEnd()));

	_nonDecodableRanges.addRange(std::move(range));
}

} // namespace loader
} // namespace retdec
