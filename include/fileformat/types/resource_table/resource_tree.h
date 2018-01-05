/**
 * @file include/fileformat/types/resource_table/resource_tree.h
 * @brief Class for resource tree.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_TREE_H
#define FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_TREE_H

#include <vector>

namespace fileformat {

/**
 * Resource tree
 */
class ResourceTree
{
	private:
		std::vector<std::vector<std::size_t>> tree; ///< resource tree structure
	public:
		ResourceTree();
		~ResourceTree();

		/// @name Queries
		/// @{
		bool isValidTree() const;
		/// @}

		/// @name Getters
		/// @{
		std::size_t getNumberOfLevels() const;
		std::size_t getNumberOfLevelsWithoutRoot() const;
		std::size_t getNumberOfNodesInLevel(std::size_t level) const;
		std::size_t getNumberOfLeafs() const;
		/// @}

		/// @name Other methods
		/// @{
		void addNode(std::size_t level, std::size_t childs);
		void dump(std::string &dumpTree) const;
		/// @}
};

} // namespace fileformat

#endif
