/**
* @file src/demangler/borland_ast/node_array.cpp
* @brief Representation of array in AST node.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/node_array.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Private constructor for NodeArray. Use create().
 */
NodeArray::NodeArray() : Node(Kind::KNodeArray), _nodes() {}

/**
 * @brief Creates shared pointer to new NodeArray object.
 * @return Pointer to empty ArrayNode.
 */
std::shared_ptr<NodeArray> NodeArray::create()
{
	return std::shared_ptr<NodeArray>(new NodeArray());
}

/**
 * @brief Appends new node to array.
 * @param node Node to be added.
 */
void NodeArray::addNode(std::shared_ptr<Node> node)
{
	_nodes.push_back(node);
}

/**
 * @return true if size of nodes is 0, false otherwise.
 */
bool NodeArray::empty() const
{
	return _nodes.empty();
}

/**
 * @return Number of nodes in array.
 */
size_t NodeArray::size()
{
	return _nodes.size();
}

/**
 * @brief Prints text representaion of array.
 * @param s Output stream.
 */
void NodeArray::printLeft(std::ostream &s) const
{
	if (!_nodes.empty()) {
		/* print first */
		auto current = _nodes.begin();
		(*current)->print(s);

		/* print others */
		while (++current != _nodes.end()) {
			s << ", ";
			(*current)->print(s);
		}
	}
}

/**
 * @param i Index to get.
 * @return Node on index i or nullptr if i is greater than size.
 */
std::shared_ptr<Node> NodeArray::get(unsigned i) const
{
	return i < _nodes.size() ? _nodes.at(i) : nullptr;
}

NodeString::NodeString() : NodeArray()
{
	_kind = Kind::KNodeString;
}

void NodeString::printLeft(std::ostream &s) const
{
	if (!_nodes.empty()) {
		auto current = _nodes.begin();
		while (current != _nodes.end()) {
			(*current)->print(s);
			++current;
		}
	}
}

std::shared_ptr<NodeString> NodeString::create() {
	return std::shared_ptr<NodeString>(new NodeString());
}

}    // borland
}    // demangler
}    // retdec
