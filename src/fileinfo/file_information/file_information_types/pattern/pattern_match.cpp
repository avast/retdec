/**
 * @file src/fileinfo/file_information/file_information_types/pattern/pattern_match.cpp
 * @brief Information about pattern match.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <limits>

#include "fileinfo/file_information/file_information_types/pattern/pattern_match.h"

namespace fileinfo {

/**
 * Constructor
 */
PatternMatch::PatternMatch() : offset(std::numeric_limits<unsigned long long>::max()),
	address(std::numeric_limits<unsigned long long>::max()),
	dataSize(std::numeric_limits<unsigned long long>::max()),
	entrySize(std::numeric_limits<unsigned long long>::max()),
	integer(false),
	floatingPoint(false)
{

}

/**
 * Destructor
 */
PatternMatch::~PatternMatch()
{

}

bool PatternMatch::isInteger() const
{
	return integer;
}

bool PatternMatch::isFloatingPoint() const
{
	return floatingPoint;
}

bool PatternMatch::getOffset(unsigned long long &pRes) const
{
	if(offset != std::numeric_limits<unsigned long long>::max())
	{
		pRes = offset;
		return true;
	}

	return false;
}

bool PatternMatch::getAddress(unsigned long long &pRes) const
{
	if(address != std::numeric_limits<unsigned long long>::max())
	{
		pRes = address;
		return true;
	}

	return false;
}

bool PatternMatch::getDataSize(unsigned long long &pRes) const
{
	if(dataSize != std::numeric_limits<unsigned long long>::max())
	{
		pRes = dataSize;
		return true;
	}

	return false;
}

bool PatternMatch::getEntrySize(unsigned long long &pRes) const
{
	if(entrySize != std::numeric_limits<unsigned long long>::max())
	{
		pRes = entrySize;
		return true;
	}

	return false;
}

void PatternMatch::setOffset(unsigned long long pOffset)
{
	offset = pOffset;
}

void PatternMatch::setAddress(unsigned long long pAddress)
{
	address = pAddress;
}

void PatternMatch::setDataSize(unsigned long long pDataSize)
{
	dataSize = pDataSize;
}

void PatternMatch::setEntrySize(unsigned long long pEntrySize)
{
	entrySize = pEntrySize;
}

void PatternMatch::setInteger()
{
	integer = true;
	floatingPoint = false;
}

void PatternMatch::setFloatingPoint()
{
	integer = false;
	floatingPoint = true;
}

} // namespace fileinfo
