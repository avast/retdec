/**
 * @file src/fileformat/types/resource_table/resource_tree.cpp
 * @brief Class for resource tree.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <sstream>

#include "retdec/fileformat/types/resource_table/resource_tree.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
ResourceTree::ResourceTree()
{
	tree.push_back(std::vector<std::size_t>());
	tree[0].push_back(0);
}

/**
 * Destructor
 */
ResourceTree::~ResourceTree()
{

}

/**
 * Check if stored tree structure is valid
 * @return @c true if stored tree structure is valid, @c false otherwise
 */
bool ResourceTree::isValidTree() const
{
	if(!getNumberOfLevelsWithoutRoot())
	{
		return tree.size() == 1 && tree[0].size() == 1 && tree[0][0] == 0;
	}

	for(std::size_t i = 0, e = getNumberOfLevelsWithoutRoot(); i < e; ++i)
	{
		std::size_t sumOfChildrens = 0;

		for(const auto &node : tree[i])
		{
			sumOfChildrens += node;
		}

		if(sumOfChildrens != tree[i + 1].size())
		{
			return false;
		}
	}

	return std::all_of(tree[tree.size() - 1].begin(), tree[tree.size() - 1].end(),
		[] (const auto &leaf)
		{
			return !leaf;
		}
	);
}

/**
 * Get number of stored levels
 * @return Number of stored levels
 */
std::size_t ResourceTree::getNumberOfLevels() const
{
	return tree.size();
}

/**
 * Get number of stored levels (root level is not included)
 * @return Number of stored levels without root level
 */
std::size_t ResourceTree::getNumberOfLevelsWithoutRoot() const
{
	return tree.empty() ? 0 : tree.size() - 1;
}

/**
 * Get number of nodes in selected level of tree
 * @param level Selected level (0 for root level)
 * @return Number of nodes in selected level of tree or @c 0 if selected level
 *    is invalid
 */
std::size_t ResourceTree::getNumberOfNodesInLevel(std::size_t level) const
{
	return level < tree.size() ? tree[level].size() : 0;
}

/**
 * Get number of leafs (leaf is node in last level)
 * @return Number of leafs
 */
std::size_t ResourceTree::getNumberOfLeafs() const
{
	return getNumberOfNodesInLevel(tree.size() - 1);
}

/**
 * Add node to tree
 * @param level Level in tree (0 for root node)
 * @param childs Number of childs of node
 */
void ResourceTree::addNode(std::size_t level, std::size_t childs)
{
	for(std::size_t i = tree.size(); i < level + 1; ++i)
	{
		tree.push_back(std::vector<std::size_t>());
	}

	if(!level)
	{
		tree[0][0] = childs;
	}
	else
	{
		tree[level].push_back(childs);
	}
}

/**
 * Dump information about resource tree
 * @param dumpTree Into this parameter is stored dump of tree
 */
void ResourceTree::dump(std::string &dumpTree) const
{
	std::stringstream ret;

	ret << "; ------------ Resource tree ------------\n";
	ret << "; Number of levels: " << getNumberOfLevels() << "\n";
	ret << "; Number of levels without root: " << getNumberOfLevelsWithoutRoot() << "\n";
	const auto treeIsValid = isValidTree();
	const std::string treeIsValidString = treeIsValid ? "true" : "false";
	ret << "; Tree is valid: " << treeIsValidString << "\n";

	if(!tree.empty())
	{
		ret << "\n";
	}

	for(std::size_t i = 0, e = getNumberOfLevels(); i < e; ++i)
	{
		std::size_t sumOfChildrens = 0;

		for(const auto &node : tree[i])
		{
			sumOfChildrens += node;
		}

		ret << "; " << i << " (nodes: " << getNumberOfNodesInLevel(i) << ", sumOfChildrens: " << sumOfChildrens << ")\n";
	}

	if(treeIsValid)
	{
		ret << "\n";

		for(std::size_t i = 0, e = getNumberOfLevels(); i < e; ++i)
		{
			ret << i << ": ";

			for(const auto node : tree[i])
			{
				ret << node << " ";
			}

			ret << "\n";
		}
	}

	dumpTree = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
