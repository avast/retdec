/**
 * @file src/fileinfo/file_information/file_information_types/data_directory.h
 * @brief Class for data directory.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DATA_DIRECTORY_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DATA_DIRECTORY_H

#include <limits>
#include <string>

namespace retdec {
namespace fileinfo {

/**
 * Class for save information about data directory.
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for unsigned integer types.
 */
class DataDirectory
{
	private:
		/// type of directory
		std::string type;
		/// address in memory
		unsigned long long address = std::numeric_limits<unsigned long long>::max();
		/// size of directory
		unsigned long long size = std::numeric_limits<unsigned long long>::max();
	public:
		/// @name Getters
		/// @{
		std::string getType() const;
		std::string getAddressStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
		/// @}

		/// @name Setters
		/// @{
		void setType(std::string dirType);
		void setAddress(unsigned long long dirAddr);
		void setSize(unsigned long long dirSize);
		/// @}
};

} // namespace fileinfo
} // namespace retdec

#endif
