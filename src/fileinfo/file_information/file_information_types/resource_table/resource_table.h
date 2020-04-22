/**
 * @file src/fileinfo/file_information/file_information_types/resource_table/resource_table.h
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RESOURCE_TABLE_RESOURCE_TABLE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RESOURCE_TABLE_RESOURCE_TABLE_H

#include <vector>

#include "retdec/fileformat/types/resource_table/resource_table.h"
#include "fileinfo/file_information/file_information_types/resource_table/resource.h"

namespace retdec {
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
		const retdec::fileformat::ResourceTable *table = nullptr;
	public:
		/// @name Getters
		/// @{
		std::size_t getNumberOfResources() const;
		std::size_t getNumberOfLanguages() const;
		std::size_t getNumberOfStrings() const;
		std::string getResourceCrc32(std::size_t index) const;
		std::string getResourceMd5(std::size_t index) const;
		std::string getResourceSha256(std::size_t index) const;
		std::string getResourceIconhashCrc32() const;
		std::string getResourceIconhashMd5() const;
		std::string getResourceIconhashSha256() const;
		std::string getResourceIconPerceptualAvgHash() const;
		std::string getResourceIconPerceptualDCTpHash() const;
		const retdec::fileformat::Resource* getResource(std::size_t position) const;
		std::string getResourceName(std::size_t index) const;
		std::string getResourceType(std::size_t index) const;
		std::string getResourceLanguage(std::size_t index) const;
		std::string getLanguageLcid(std::size_t index) const;
		std::string getLanguageCodePage(std::size_t index) const;
		std::string getStringName(std::size_t index) const;
		std::string getStringValue(std::size_t index) const;
		std::string getResourceNameIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceTypeIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceLanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceSublanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceOffsetStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getResourceSizeStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		/// @}

		/// @name Setters
		/// @{
		void setTable(const retdec::fileformat::ResourceTable *resourceTable);
		/// @}

		/// @name Other methods
		/// @{
		bool hasRecords() const;
		/// @}
};

} // namespace fileinfo
} // namespace retdec

#endif
