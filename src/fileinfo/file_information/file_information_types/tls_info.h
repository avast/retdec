/**
 * @file src/fileinfo/file_information/file_information_types/tls_info.h
 * @brief TLS information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_TLS_INFO_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_TLS_INFO_H

#include "retdec/fileformat/types/tls_info/tls_info.h"

namespace retdec {
namespace fileinfo {

/**
 * Class for import table
 */
class TlsInfo
{
	private:
		const retdec::fileformat::TlsInfo *tlsInfo = nullptr;
	public:
		/// @name Getters
		/// @{
		std::string getRawDataStartAddrStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getRawDataEndAddrStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getIndexAddrStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getCallBacksAddrStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getZeroFillSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getCharacteristicsStr() const;
		std::size_t getNumberOfCallBacks() const;
		std::string getCallBackAddrStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const;
		/// @}

		/// @name Setters
		/// @{
		void setTlsInfo(const retdec::fileformat::TlsInfo *info);
		bool isUsed() const;
		/// @}
};

} // namespace fileinfo
} // namespace retdec

#endif
