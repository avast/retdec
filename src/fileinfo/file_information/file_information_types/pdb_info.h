/**
 * @file src/fileinfo/file_information/file_information_types/pdb_info.h
 * @brief Information about related PDB file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_PDB_INFO_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_PDB_INFO_H

#include <string>

namespace fileinfo {

/**
 * Class for information about related PDB file
 *
 * Value std::numeric_limits<std::size_t>::max() mean unspecified value or error for numeric types.
 */
class PdbInfo
{
	private:
		std::string type;      ///< type of PDB file
		std::string path;      ///< original path to PDB debug file
		std::string guid;      ///< GUID of PDB file
		std::size_t age;       ///< age of PDB file
		std::size_t timeStamp; ///< time and date that PDB file was created
	public:
		PdbInfo();
		~PdbInfo();

		/// @name Getters
		/// @{
		std::string getType() const;
		std::string getPath() const;
		std::string getGuid() const;
		std::string getAgeStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getTimeStampStr(std::ios_base &(* format)(std::ios_base &)) const;
		/// @}

		/// @name Setters
		/// @{
		void setType(std::string sType);
		void setPath(std::string sPath);
		void setGuid(std::string sGuid);
		void setAge(std::size_t sAge);
		void setTimeStamp(std::size_t sTimeStamp);
		/// @}
};

} // namespace fileinfo

#endif
