/**
 * @file src/loader/loader/segment_data_source.cpp
 * @brief Definition of segment data source class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <iterator>

#include "retdec/loader/loader/segment_data_source.h"

namespace retdec {
namespace loader {

SegmentDataSource::SegmentDataSource() : _data(nullptr, 0)
{
}

SegmentDataSource::SegmentDataSource(const llvm::StringRef& data)
	: _data(data.data(), data.size())
{
}

SegmentDataSource::SegmentDataSource(const SegmentDataSource& dataSource)
	: _data(dataSource._data.data(), dataSource._data.size())
{
}

SegmentDataSource::~SegmentDataSource()
{
}

bool SegmentDataSource::isDataSet() const
{
	return !_data.empty();
}

const std::uint8_t* SegmentDataSource::getData() const
{
	return _data.bytes_begin();
}

std::uint64_t SegmentDataSource::getDataSize() const
{
	return _data.size();
}

void SegmentDataSource::resize(std::uint64_t newSize)
{
	_data = llvm::StringRef(_data.data(), std::min(getDataSize(), newSize));
}

bool SegmentDataSource::shrink(std::uint64_t newOffset, std::uint64_t newSize)
{
	if (newSize > getDataSize())
		return false;

	if (newOffset >= getDataSize())
	{
		_data = llvm::StringRef(nullptr, 0);
	}
	else if (newOffset + newSize > getDataSize())
	{
		_data = llvm::StringRef(_data.data() + newOffset, getDataSize() - newOffset);
	}
	else
	{
		_data = llvm::StringRef(_data.data() + newOffset, std::min(getDataSize(), newSize));
	}

	return true;
}

bool SegmentDataSource::loadData(std::uint64_t loadOffset, std::uint64_t loadSize, std::vector<std::uint8_t>& data) const
{
	data.clear();

	if (!isDataSet())
		return false;

	if (loadOffset >= getDataSize())
		return false;

	loadSize = loadOffset + loadSize >= getDataSize() ? getDataSize() - loadOffset : loadSize;
	std::copy(_data.data() + loadOffset, _data.data() + loadOffset + loadSize, std::back_inserter(data));
	return true;
}

bool SegmentDataSource::saveData(std::uint64_t saveOffset, std::uint64_t saveSize, const std::vector<std::uint8_t>& data)
{
	if (!isDataSet())
		return false;

	if (saveOffset >= getDataSize())
		return false;

	saveSize = saveOffset + saveSize > getDataSize() ? getDataSize() - saveOffset : saveSize;
	std::copy(data.data(), data.data() + saveSize, const_cast<char*>(_data.data()) + saveOffset);
	return true;
}

} // namespace loader
} // namespace retdec
