/**
 * @file src/fileinfo/file_information/file_information_types/loader_info.cpp
 * @brief Class for loader info.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/file_format/file_format.h"
#include "fileinfo/file_information/file_information_types/loader_info.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

LoadedSegment::LoadedSegment(unsigned long long index, std::string name, unsigned long long address, unsigned long long size)
	: _index(index), _name(std::move(name)), _address(address), _size(size)
{

}

LoadedSegment::LoadedSegment(const LoadedSegment& segment)
	: _index(segment._index), _name(segment._name), _address(segment._address), _size(segment._size)
{

}

LoadedSegment::LoadedSegment(LoadedSegment&& segment)
	: _index(segment._index), _name(std::move(segment._name)), _address(segment._address), _size(segment._size)
{

}

LoadedSegment::~LoadedSegment()
{

}

std::string LoadedSegment::getIndexStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(_index, format);
}

std::string LoadedSegment::getName() const
{
	return _name;
}

std::string LoadedSegment::getAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(_address, format);
}

std::string LoadedSegment::getSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(_size, format);
}

LoaderInfo::LoaderInfo() : _baseAddress(0), _loadedSegments(), _statusMessage()
{
}

LoaderInfo::~LoaderInfo()
{
}

std::string LoaderInfo::getBaseAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(_baseAddress, format);
}

std::string LoaderInfo::getNumberOfLoadedSegmentsStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(getNumberOfLoadedSegments(), format);
}

unsigned long long LoaderInfo::getNumberOfLoadedSegments() const
{
	return _loadedSegments.size();
}

const LoadedSegment& LoaderInfo::getLoadedSegment(unsigned long long index) const
{
	return _loadedSegments[index];
}

const std::string& LoaderInfo::getStatusMessage() const
{
	return _statusMessage;
}

const retdec::fileformat::LoaderErrorInfo & LoaderInfo::getLoaderErrorInfo() const
{
	return _ldrErrInfo;
}

void LoaderInfo::setBaseAddress(unsigned long long baseAddress)
{
	_baseAddress = baseAddress;
}

void LoaderInfo::setStatusMessage(const std::string& statusMessage)
{
	_statusMessage = statusMessage;
}

void LoaderInfo::setLoaderErrorInfo(const retdec::fileformat::LoaderErrorInfo & ldrErrInfo)
{
	_ldrErrInfo = ldrErrInfo;
}

void LoaderInfo::addLoadedSegment(const LoadedSegment& segment)
{
	_loadedSegments.push_back(segment);
}

} // namespace fileinfo
