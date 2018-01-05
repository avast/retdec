/**
 * @file src/fileinfo/file_information/file_information_types/data_directory.h
 * @brief Class for data directory.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DATA_DIRECTORY_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DATA_DIRECTORY_H

#include <string>

namespace fileinfo {

/**
 * Class for save information about data directory.
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for unsigned integer types.
 */
class DataDirectory
{
	private:
		std::string type;           ///< type of directory
		unsigned long long address; ///< address in memory
		unsigned long long size;    ///< size of directory
	public:
		DataDirectory();
		~DataDirectory();

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

#endif
