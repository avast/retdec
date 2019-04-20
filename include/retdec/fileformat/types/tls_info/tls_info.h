/**
 * @file include/retdec/fileformat/types/tls_info/tls_info.h
 * @brief Class for information about thread-local storage.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_TLS_INFO_TLS_INFO_H
#define RETDEC_FILEFORMAT_TYPES_TLS_INFO_TLS_INFO_H

#include <string>
#include <vector>

namespace retdec {
namespace fileformat {

/**
 * Information about TLS
 */
class TlsInfo
{
	private:
		std::vector<std::uint64_t> callBacks;  ///< addresses of callback functions
		std::uint64_t rawDataStartAddr;        ///< start address of raw data
		std::uint64_t rawDataEndAddr;          ///< end address of raw data
		std::uint64_t indexAddr;               ///< address of index
		std::uint64_t callBacksAddr;           ///< address of array of callbacks
		std::uint32_t zeroFillSize;            ///< size of zero fill
		std::uint32_t characteristics;         ///< characteristics
		bool rawDataStartAddrValid;            ///< member validity flag
		bool rawDataEndAddrValid;              ///< member validity flag
		bool indexAddrValid;                   ///< member validity flag
		bool callBacksAddrValid;               ///< member validity flag
		bool zeroFillSizeValid;                ///< member validity flag
		bool characteristicsValid;             ///< member validity flag
	public:
		TlsInfo();
		~TlsInfo();

		/// @name Getters
		/// @{
		bool getRawDataStartAddr(std::uint64_t &res) const;
		bool getRawDataEndAddr(std::uint64_t &res) const;
		bool getIndexAddr(std::uint64_t &res) const;
		bool getCallBacksAddr(std::uint64_t &res) const;
		bool getZeroFillSize(std::uint32_t &res) const;
		bool getCharacteristics(std::uint32_t &res) const;
		const std::vector<std::uint64_t> &getCallBacks() const;
		/// @}

		/// @name Setters
		/// @{
		void setRawDataStartAddr(std::uint64_t sAddr);
		void setRawDataEndAddr(std::uint64_t eAddr);
		void setIndexAddr(std::uint64_t iAddr);
		void setCallBacksAddr(std::uint64_t cbAddr);
		void setZeroFillSize(std::uint32_t zFill);
		void setCharacteristics(std::uint32_t chars);
		/// @}

		/// @name Other methods
		/// @{
		void addCallBack(std::uint64_t cb);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
