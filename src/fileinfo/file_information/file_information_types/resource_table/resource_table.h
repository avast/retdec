/**
 * @file src/fileinfo/file_information/file_information_types/resource_table/resource_table.h
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RESOURCE_TABLE_RESOURCE_TABLE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RESOURCE_TABLE_RESOURCE_TABLE_H

#include <vector>

#include "fileinfo/file_information/file_information_types/resource_table/resource.h"

namespace fileinfo {

/**
 * Class for resource table
 *
 * Value std::numeric_limits<std::size_t>::max() mean unspecified value or error for numeric types.
 * Methods with index parameters does not perform control of indexes.
 */
class ResourceTable
{
	private:
		std::vector<Resource> table; ///< vector of stored resources
	public:
		ResourceTable();
		~ResourceTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfResources() const;
		std::string getResourceCrc32(std::size_t index) const;
		std::string getResourceMd5(std::size_t index) const;
		std::string getResourceSha256(std::size_t index) const;
		std::string getResourceName(std::size_t index) const;
		std::string getResourceType(std::size_t index) const;
		std::string getResourceLanguage(std::size_t index) const;
		std::string getResourceNameIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceTypeIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceLanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceSublanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceOffsetStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceSizeStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		/// @}

		/// @name Other methods
		/// @{
		void addResource(Resource &resource);
		void clearResources();
		/// @}
};

} // namespace fileinfo

#endif
