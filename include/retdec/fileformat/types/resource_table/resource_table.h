/**
 * @file include/retdec/fileformat/types/resource_table/resource_table.h
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_TABLE_H

#include <vector>

#include "retdec/fileformat/types/resource_table/resource.h"

namespace retdec {
namespace fileformat {

/**
 * Table of resources
 */
class ResourceTable
{
	private:
		using resourcesIterator = std::vector<Resource>::const_iterator;
		std::vector<Resource> table; ///< stored resources
	public:
		ResourceTable();
		~ResourceTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfResources() const;
		std::size_t getSizeInFile() const;
		std::size_t getLoadedSize() const;
		const Resource* getResource(std::size_t rIndex) const;
		const Resource* getResourceWithName(const std::string &rName) const;
		const Resource* getResourceWithName(std::size_t rId) const;
		const Resource* getResourceWithType(const std::string &rType) const;
		const Resource* getResourceWithType(std::size_t rId) const;
		const Resource* getResourceWithLanguage(const std::string &rLan) const;
		const Resource* getResourceWithLanguage(std::size_t rId) const;
		/// @}

		/// @name Iterators
		/// @{
		resourcesIterator begin() const;
		resourcesIterator end() const;
		/// @}

		/// @name Other methods
		/// @{
		void clear();
		void addResource(Resource &newResource);
		bool hasResources() const;
		bool hasResourceWithName(const std::string &rName) const;
		bool hasResourceWithName(std::size_t rId) const;
		bool hasResourceWithType(const std::string &rType) const;
		bool hasResourceWithType(std::size_t rId) const;
		bool hasResourceWithLanguage(const std::string &rLan) const;
		bool hasResourceWithLanguage(std::size_t rId) const;
		void dump(std::string &dumpTable) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
