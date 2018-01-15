/**
 * @file src/fileinfo/file_information/file_information_types/resource_table/resource.h
 * @brief Class for one resource.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RESOURCE_TABLE_RESOURCE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RESOURCE_TABLE_RESOURCE_H

#include <string>

namespace fileinfo {

/**
 * One resource
 *
 * Value std::numeric_limits<std::size_t>::max() mean unspecified value or error for numeric types.
 */
class Resource
{
	private:
		std::string crc32;         ///< CRC32 of resource content
		std::string md5;           ///< MD5 of resource content
		std::string sha256;        ///< SHA256 of recource content
		std::string name;          ///< resource name
		std::string type;          ///< resource type
		std::string language;      ///< resource language
		std::size_t nameId;        ///< resource name identifier
		std::size_t typeId;        ///< resource type identifier
		std::size_t languageId;    ///< resource language identifier
		std::size_t sublanguageId; ///< resource sublanguage identifier
		std::size_t offset;        ///< offset in file
		std::size_t size;          ///< size in file
	public:
		Resource();
		~Resource();

		/// @name Getters
		/// @{
		std::string getCrc32() const;
		std::string getMd5() const;
		std::string getSha256() const;
		std::string getName() const;
		std::string getType() const;
		std::string getLanguage() const;
		std::string getNameIdStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getTypeIdStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getLanguageIdStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSublanguageIdStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSizeStr(std::ios_base &(* format)(std::ios_base &)) const;
		/// @}

		/// @name Setters
		/// @{
		void setCrc32(std::string rCrc32);
		void setMd5(std::string rMd5);
		void setSha256(std::string rSha256);
		void setName(std::string rName);
		void setType(std::string rType);
		void setLanguage(std::string rLan);
		void setNameId(std::size_t rId);
		void setTypeId(std::size_t rId);
		void setLanguageId(std::size_t rId);
		void setSublanguageId(std::size_t rId);
		void setOffset(std::size_t rOffset);
		void setSize(std::size_t rSize);
		/// @}
};

} // namespace fileinfo

#endif
