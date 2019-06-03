/**
* @file src/demangler/borland_ast/node.cpp
* @brief Base class for all nodes in AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/node.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Abstract constructor for base node.
 * @param kind Kind of node.
 * @param has_right_side
 */
Node::Node(Kind kind, bool has_right_side) :
	_kind(kind), _has_right(has_right_side) {}

/**
 * @brief Prints left side of node.
 * @param s output stream
 */
void Node::print(std::ostream &s) const
{
	printLeft(s);
	if (_has_right) {
		printRight(s);
	}
}

/**
 * @return String representation of node.
 */
std::string Node::str() const
{
	std::stringstream ss;
	print(ss);
	return ss.str();
}

/**
 * @return Kind of node.
 */
Node::Kind Node::kind() const
{
	return _kind;
}

/**
 * @brief Some nodes need special trailing characters.
 * @param s output stream.
 */
void Node::printRight(std::ostream &s) const {}

bool Node::hasRight()
{
	return _has_right;
}

}    // borland
}    // demangler
}    // retdec
