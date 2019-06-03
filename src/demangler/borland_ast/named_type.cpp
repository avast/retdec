/**
* @file src/demangler/borland_ast/named_type.cpp
* @brief Representation of named types as classes and template class types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <iostream>

#include "retdec/demangler/borland_ast/named_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Private constructor for named types. Use create().
 */
NamedTypeNode::NamedTypeNode(std::shared_ptr<Node> typeName, const Qualifiers &quals) :
	TypeNode(quals), _typeName(typeName)
{
	_kind = Kind::KNamedType;
}

/**
 * @brief Function for creating named types.
 * If type the same type was already created, then that instance is returned.
 * @param typeName Name of integral type to create.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing named type.
 */
std::shared_ptr<NamedTypeNode> NamedTypeNode::create(
	std::shared_ptr<Node> typeName,
	const Qualifiers &quals)
{
	return std::shared_ptr<NamedTypeNode>(new NamedTypeNode(std::move(typeName), quals));
}

/**
 * @return Node representing name.
 */
std::shared_ptr<Node> NamedTypeNode::name()
{
	return _typeName;
}

/**
 * @brief Prints text representation of named type with qualifiers to output stream.
 */
void NamedTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	s << _typeName->str();
}

}    // borland
}    // demangler
}    // retdec
