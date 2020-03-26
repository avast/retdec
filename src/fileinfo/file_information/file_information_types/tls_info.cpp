/**
 * @file src/fileinfo/file_information/file_information_types/tls_info.cpp
 * @brief TLS information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/tls_info.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace retdec {
namespace fileinfo {

/**
 * Get raw data start address
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Raw data start address
 */
std::string TlsInfo::getRawDataStartAddrStr(std::ios_base &(* format)(std::ios_base &)) const
{
	std::uint64_t val;
	return (tlsInfo && tlsInfo->getRawDataStartAddr(val)) ? getNumberAsString(val, format) : "";
}

/**
 * Get raw data end address
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Raw data end address
 */
std::string TlsInfo::getRawDataEndAddrStr(std::ios_base &(* format)(std::ios_base &)) const
{
	std::uint64_t val;
	return (tlsInfo && tlsInfo->getRawDataEndAddr(val)) ? getNumberAsString(val, format) : "";
}

/**
 * Get index address
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Index address
 */
std::string TlsInfo::getIndexAddrStr(std::ios_base &(* format)(std::ios_base &)) const
{
	std::uint64_t val;
	return (tlsInfo && tlsInfo->getIndexAddr(val)) ? getNumberAsString(val, format) : "";
}

/**
 * Get callbacks address
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Callbacks address
 */
std::string TlsInfo::getCallBacksAddrStr(std::ios_base &(* format)(std::ios_base &)) const
{
	std::uint64_t val;
	return (tlsInfo && tlsInfo->getCallBacksAddr(val)) ? getNumberAsString(val, format) : "";
}

/**
 * Get zero fill size
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Zero fill size
 */
std::string TlsInfo::getZeroFillSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	std::uint32_t val;
	return (tlsInfo && tlsInfo->getZeroFillSize(val)) ? getNumberAsString(val, format) : "";
}

/**
 * Get characteristics
 * @return Characteristics
 */
std::string TlsInfo::getCharacteristicsStr() const
{
	std::uint32_t val;
	return (tlsInfo && tlsInfo->getCharacteristics(val)) ? getBinaryRepresentation(val, 32) : "";
}

/**
 * Get number of callback addresses
 * @return Number of callback addresses
 */
std::size_t TlsInfo::getNumberOfCallBacks() const
{
	return tlsInfo ? tlsInfo->getCallBacks().size() : 0;
}

/**
 * Get callback address
 * @param position Index of selected callback (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Callback address
 */
std::string TlsInfo::getCallBackAddrStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	if (!tlsInfo || position >= getNumberOfCallBacks())
	{
		return "";
	}
	auto addr = tlsInfo->getCallBacks()[position];
	return getNumberAsString(addr, format);
}

/**
 * Set TLS info
 * @param info Instance of class with original information about TLS
 */
void TlsInfo::setTlsInfo(const retdec::fileformat::TlsInfo *info)
{
	tlsInfo = info;
}

/**
 * Check whether TLS is used
 * @return @c true if TLS is used, @c false otherwise
 */
bool TlsInfo::isUsed() const
{
	return tlsInfo != nullptr;
}

} // namespace fileinfo
} // namespace retdec
