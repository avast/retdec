/**
 * @file src/unpacker/signature.cpp
 * @brief Declaration of class for matching signatures in executable files and buffers.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/unpacker/signature.h"

namespace retdec {
namespace unpacker {

/**
 * Initializer list constructor.
 *
 * @param initList Initializer list containing Signature::Byte objects.
 */
Signature::Signature(const std::initializer_list<Signature::Byte>& initList)
{
	_buffer.resize(initList.size());
	std::copy(initList.begin(), initList.end(), _buffer.begin());
}

/**
 * Copy constructor.
 *
 * @param signature Another signature.
 */
Signature::Signature(const Signature& signature) : _buffer(signature._buffer)
{
}

/**
 * Destructor.
 */
Signature::~Signature()
{
}

/**
 * Assignment operator allowing initializer list assignment.
 *
 * @param initList Initializer list containg Signature::Byte objects.
 *
 * @return Newly created Signature object.
 */
Signature& Signature::operator =(const std::initializer_list<Signature::Byte>& initList)
{
	_buffer = std::vector<Signature::Byte>(initList);
	return *this;
}

/**
 * Returns the number of bytes in the signature.
 *
 * @return Number of bytes in the signature.
 */
uint64_t Signature::getSize() const
{
	return _buffer.size();
}

/**
 * Returns the number of bytes in the signature that has Signature::Byte::Type::CAPTURE type.
 *
 * @return Number of capture bytes.
 */
uint64_t Signature::getCaptureSize() const
{
	uint64_t count = 0;
	for (uint64_t i = 0; i < getSize(); ++i)
	{
		if (_buffer[i].getType() == Signature::Byte::Type::CAPTURE)
			count++;
	}

	return count;
}

/**
 * Matches the signature against the file using the specified settings. Matching is being done on section or segment which contains entry point.
 *
 * @param settings Match settings.
 * @param file Input file.
 *
 * @return True if the signature matched successfuly, otherwise false.
 */
bool Signature::match(const Signature::MatchSettings& settings, retdec::loader::Image* file) const
{
	const retdec::loader::Segment* seg = file->getEpSegment();
	if (seg == nullptr)
		return false;

	std::vector<uint8_t> bytesToMatch;
	seg->getBytes(bytesToMatch, settings.getOffset(), getSize() + settings.getSearchDistance());

	if (settings.isSearch())
		return searchMatchImpl(bytesToMatch, 0, settings.getSearchDistance(), nullptr);

	return (matchImpl(bytesToMatch, 0, nullptr) == static_cast<int64_t>(getSize()));
}

/**
 * Matches the signature against the data buffer using the specified settings.
 *
 * @param settings Match settings.
 * @param data Input data buffer.
 *
 * @return True if the signature matched successfuly, otherwise false.
 */
bool Signature::match(const Signature::MatchSettings& settings, const DynamicBuffer& data) const
{
	if (settings.isSearch())
		return searchMatchImpl(data.getBuffer(), settings.getOffset(), settings.getSearchDistance(), nullptr);

	return (matchImpl(data.getBuffer(), settings.getOffset(), nullptr) == static_cast<int64_t>(getSize()));
}

/**
 * Matches the signature against the file using the specified settings and captures all capture bytes into DynamicBuffer.
 * Matching is being done on section or segment which contains entry point.
 *
 * @param settings Match settings.
 * @param file Input file.
 * @param capturedData Buffer where to capture the capture bytes.
 *
 * @return True if the signature matched successfuly, otherwise false.
 */
bool Signature::match(const Signature::MatchSettings& settings, retdec::loader::Image* file, DynamicBuffer& capturedData) const
{
	const retdec::loader::Segment* seg = file->getEpSegment();
	if (seg == nullptr)
		return false;

	std::vector<uint8_t> bytesToMatch;
	seg->getBytes(bytesToMatch, settings.getOffset(), getSize() + settings.getSearchDistance());

	if (settings.isSearch())
		return searchMatchImpl(bytesToMatch, 0, settings.getSearchDistance(), &capturedData);

	return (matchImpl(bytesToMatch, 0, &capturedData) == static_cast<int64_t>(getSize()));
}

/**
 * Matches the signature against the data buffer using the specified settings and captures all capture bytes into DynamicBuffer.
 *
 * @param settings Match settings.
 * @param data Input data buffer.
 * @param capturedData Buffer where to capture the capture bytes.
 *
 * @return True if the signature matched successfuly, otherwise false.
 */
bool Signature::match(const Signature::MatchSettings& settings, const DynamicBuffer& data, DynamicBuffer& capturedData) const
{
	if (settings.isSearch())
		return searchMatchImpl(data.getBuffer(), settings.getOffset(), settings.getSearchDistance(), &capturedData);

	return (matchImpl(data.getBuffer(), settings.getOffset(), &capturedData) == static_cast<int64_t>(getSize()));
}

bool Signature::searchMatchImpl(const std::vector<uint8_t>& bytesToMatch, uint64_t offset, uint64_t maxSearchDist, DynamicBuffer* capturedData) const
{
	// Boyer-Moore search over whole bytesToMatch buffer
	uint64_t searchOffset = 0;
	while (searchOffset < maxSearchDist)
	{
		// Reverse comparison for the first right-most mismatch position in needle
		int64_t mismatchPos = matchImpl(bytesToMatch, offset + searchOffset, capturedData);
		if (mismatchPos == -1)
			return false;

		if (mismatchPos == static_cast<int64_t>(getSize()))
			return true;

		// Look for the first right-most occurance of the haystack mismatched symbol in the needle
		uint8_t haystackSymbol = bytesToMatch[offset + searchOffset + mismatchPos];
		for (int64_t j = mismatchPos - 1; j >= 0; --j)
		{
			if (_buffer[j] == haystackSymbol)
				break;

			searchOffset++;
		}
		// One shift is implicit
		searchOffset++;
	}

	return false;
}

int64_t Signature::matchImpl(const std::vector<uint8_t>& bytesToMatch, uint64_t offset, DynamicBuffer* captureBuffer) const
{
	// Bytes to match are not big enough to match this signature
	if (bytesToMatch.size() - offset < getSize())
		return -1;

	if (captureBuffer != nullptr)
		captureBuffer->setCapacity(getCaptureSize());

	// Do reverse search because this one is used for Boyer-Moore search
	uint64_t captureWritePos = getCaptureSize() - 1;
	for (int64_t i = getSize() - 1; i >= 0; --i)
	{
		// No match, just end prematurely
		if (_buffer[i] != bytesToMatch[offset + i])
			return i;

		// Wildcard that matches any byte, but also put matched byte into capture buffer
		if (_buffer[i].getType() == Signature::Byte::Type::CAPTURE)
		{
			if (captureBuffer != nullptr)
				captureBuffer->write<uint8_t>(bytesToMatch[offset + i], captureWritePos--);
		}
	}

	return getSize();
}

// Signature::MatchSettings

/**
 * Constructor.
 *
 * @param offset The offset to set.
 * @param searchDistance Maximum search distance to sit.
 */
Signature::MatchSettings::MatchSettings(uint64_t offset /*= 0*/, uint64_t searchDistance /*= 0*/) : _offset(offset), _searchDistance(searchDistance)
{
}

/**
 * Destructor.
 */
Signature::MatchSettings::~MatchSettings()
{
}

/**
 * Returns the offset in the settings.
 *
 * @return The offset.
 */
uint64_t Signature::MatchSettings::getOffset() const
{
	return _offset;
}

/**
 * Sets the offset in the settings.
 *
 * @param offset The offset to set.
 */
void Signature::MatchSettings::setOffset(uint64_t offset)
{
	_offset = offset;
}

/**
 * Returns whether the settings are set to searching while matching.
 *
 * @return True if set to search matching, otherwise false.
 */
bool Signature::MatchSettings::isSearch() const
{
	return _searchDistance > 0;
}

/**
 * Returns the maximum searching distance while matching.
 *
 * @return The maximum searching distance.
 */
uint64_t Signature::MatchSettings::getSearchDistance() const
{
	return _searchDistance;
}

/**
 * Sets the maximum searching distance while matching.
 *
 * @param distance The maximum searching distance to set.
 */
void Signature::MatchSettings::setSearchDistance(uint64_t distance)
{
	_searchDistance = distance;
}

// Signature::Byte

/**
 * Default constructor. Initializes exact match byte with expected value 0.
 */
Signature::Byte::Byte() : Byte(Signature::Byte::Type::NORMAL, 0, 0)
{
}

/**
 * Single byte implicit constructor. Initializes exact match byte with specified expected value.
 *
 * @param byte Expected value of exact match byte.
 */
Signature::Byte::Byte(uint8_t byte) : Byte(Signature::Byte::Type::NORMAL, byte, 0)
{
}

/**
 * Explicit constructor. Initializes bytes according to all specified values.
 * In case of conflict between expectedValue and wildcardMask, all bits that are set to 1 in both are set back to 0 in expectedValue.
 *
 * @param type Type of the byte.
 * @param expectedValue Expected value of the byte.
 * @param wildcardMask Wildcard mask of the byte.
 */
Signature::Byte::Byte(Type type, uint8_t expectedValue, uint8_t wildcardMask) : _type(type), _expectedValue(expectedValue & ~wildcardMask), _wildcardMask(wildcardMask)
{
}

/**
 * Copy constructor.
 *
 * @param byte Another Signature::Byte object.
 */
Signature::Byte::Byte(const Byte& byte) : _type(byte._type), _expectedValue(byte._expectedValue), _wildcardMask(byte._wildcardMask)
{
}

/**
 * Destructor.
 */
Signature::Byte::~Byte()
{
}

/**
 * Returns the type of byte.
 *
 * @return The type of the byte.
 */
Signature::Byte::Type Signature::Byte::getType() const
{
	return _type;
}

/**
 * Returns the expected value of the byte.
 *
 * @return The expected value of the byte.
 */
uint8_t Signature::Byte::getExpectedValue() const
{
	return _expectedValue;
}

/**
 * Returns the wildcard mask of the byte.
 *
 * @return The wildcard mask of the byte.
 */
uint8_t Signature::Byte::getWildcardMask() const
{
	return _wildcardMask;
}

/**
 * Assignment operator for raw byte assignment. Initializes exact match byte.
 *
 * @param rhs Raw byte to assign.
 *
 * @return Newly created Signature::Byte object.
 */
Signature::Byte& Signature::Byte::operator =(uint8_t rhs)
{
	_type = Signature::Byte::Type::NORMAL;
	std::swap(_expectedValue, rhs);
	_wildcardMask = 0;
	return *this;
}

/**
 * Assigment operator for Signature::Byte assignment.
 *
 * @param rhs Signature::Byte object to copy.
 *
 * @return Newly created Signature::Byte object.
 */
Signature::Byte& Signature::Byte::operator =(Signature::Byte rhs)
{
	std::swap(_type, rhs._type);
	std::swap(_expectedValue, rhs._expectedValue);
	std::swap(_wildcardMask, rhs._wildcardMask);
	return *this;
}

/**
 * Equality operator for comparison with raw bytes.
 *
 * @param rhs Raw byte to compare with.
 *
 * @return True if the expected value equals or wildcard mask matches the specified bits, otherwise false.
 */
bool Signature::Byte::operator ==(uint8_t rhs) const
{
	if (getType() == Signature::Byte::Type::NORMAL)
		return _expectedValue == rhs;

	return (rhs & ~_wildcardMask) == _expectedValue;
}

/**
 * Equality operator for comparison with raw bytes.
 *
 * @param lhs Raw byte to compare with.
 * @param rhs Signature::Byte object to compare.
 *
 * @return True if the expected value equals or wildcard mask matches the specified bits, otherwise false.
 */
bool operator ==(uint8_t lhs, const Signature::Byte& rhs)
{
	return (rhs == lhs);
}

/**
 * Non-equality operator for comparison with raw bytes.
 *
 * @param rhs Raw byte to compare with.
 *
 * @return False if the expected value equals or wildcard mask matches the specified bits, otherwise true.
 */
bool Signature::Byte::operator !=(uint8_t rhs) const
{
	return !(*this == rhs);
}

/**
 * Non-equality operator for comparison with raw bytes.
 *
 * @param lhs Raw byte to compare with.
 * @param rhs Signature::Byte object to compare.
 *
 * @return False if the expected value equals or wildcard mask matches the specified bits, otherwise true.
 */
bool operator !=(uint8_t lhs, const Signature::Byte& rhs)
{
	return (rhs != lhs);
}

} // namespace unpacker
} // namespace retdec
