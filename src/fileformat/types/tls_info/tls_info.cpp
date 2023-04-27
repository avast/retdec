/**
 * @file src/fileformat/types/tls_info/tls_info.cpp
 * @brief Class for information about thread-local storage.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/fileformat/types/tls_info/tls_info.h"

namespace retdec {
namespace fileformat {

/**
 * Get start of raw data address
 * @param res Variable to store the result to
 * @return @c true on success, @c false otherwise
 */
bool TlsInfo::getRawDataStartAddr(std::uint64_t &res) const
{
	if (!rawDataStartAddrValid)
	{
		return false;
	}
	res = rawDataStartAddr;
	return true;
}

/**
 * Get end of raw data address
 * @param res Variable to store the result to
 * @return @c true on success, @c false otherwise
 */
bool TlsInfo::getRawDataEndAddr(std::uint64_t &res) const
{
	if (!rawDataEndAddrValid)
	{
		return false;
	}
	res = rawDataEndAddr;
	return true;
}

/**
 * Get address of index
 * @param res Variable to store the result to
 * @return @c true on success, @c false otherwise
 */
bool TlsInfo::getIndexAddr(std::uint64_t &res) const
{
	if (!indexAddrValid)
	{
		return false;
	}
	res = indexAddr;
	return true;
}

/**
 * Get address of callbacks
 * @param res Variable to store the result to
 * @return @c true on success, @c false otherwise
 */
bool TlsInfo::getCallBacksAddr(std::uint64_t &res) const
{
	if (!callBacksAddrValid)
	{
		return false;
	}
	res = callBacksAddr;
	return true;
}

/**
 * Get zero fill size
 * @param res Variable to store the result to
 * @return @c true on success, @c false otherwise
 */
bool TlsInfo::getZeroFillSize(std::uint32_t &res) const
{
	if (!zeroFillSizeValid)
	{
		return false;
	}
	res = zeroFillSize;
	return true;
}

/**
 * Get characteristics
 * @param res Variable to store the result to
 * @return @c true on success, @c false otherwise
 */
bool TlsInfo::getCharacteristics(std::uint32_t &res) const
{
	if (!characteristicsValid)
	{
		return false;
	}
	res = characteristics;
	return true;
}

/**
 * Get addresses of callbacks
 * @return Addresses of callbacks
 */
const std::vector<std::uint64_t> &TlsInfo::getCallBacks() const
{
	return callBacks;
}

/**
 * Set start of raw data address
 * @param sAddr start of raw data address to set
 */
void TlsInfo::setRawDataStartAddr(std::uint64_t sAddr)
{
	rawDataStartAddr = sAddr;
	rawDataStartAddrValid = true;
}

/**
 * Set end of raw data address
 * @param eAddr end of raw data address to set
 */
void TlsInfo::setRawDataEndAddr(std::uint64_t eAddr)
{
	rawDataEndAddr = eAddr;
	rawDataEndAddrValid = true;
}

/**
 * Set address of index
 * @param iAddr address of index to set
 */
void TlsInfo::setIndexAddr(std::uint64_t iAddr)
{
	indexAddr = iAddr;
	indexAddrValid = true;
}

/**
 * Set address of callbacks
 * @param cbAddr address of callbacks to set
 */
void TlsInfo::setCallBacksAddr(std::uint64_t cbAddr)
{
	callBacksAddr = cbAddr;
	callBacksAddrValid = true;
}

/**
* Set array of callbacks
* @param callbacks address of callbacks to set
*/
void TlsInfo::setCallBacks(const std::vector<std::uint64_t> & callbacks)
{
	callBacks = callbacks;
}

/**
 * Set zero fill size
 * @param zFill zero fill size to set
 */
void TlsInfo::setZeroFillSize(std::uint32_t zFill)
{
	zeroFillSize = zFill;
	zeroFillSizeValid = true;
}

/**
 * Set characteristics
 * @param chars characteristics to set
 */
void TlsInfo::setCharacteristics(std::uint32_t chars)
{
	characteristics = chars;
	characteristicsValid = true;
}

/**
 * Add callback
 * @param cb Callback to add
 */
void TlsInfo::addCallBack(std::uint64_t cb)
{
	callBacks.push_back(cb);
}

} // namespace fileformat
} // namespace retdec
