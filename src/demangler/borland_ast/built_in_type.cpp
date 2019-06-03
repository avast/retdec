/**
* @file src/demangler/borland_ast/built_in_type.cpp
* @brief Representation of built-in types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <iostream>

#include "retdec/demangler/borland_ast/built_in_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Private constructor for built-in type nodes. Use create().
 * @param typeName Representation of type name.
 * @param quals
 */
BuiltInTypeNode::BuiltInTypeNode(const std::string &typeName, const Qualifiers &quals) :
	TypeNode(quals), _typeName(typeName)
{
	_kind = Kind::KBuiltInType;
}

/**
 * @brief Creates unique pointer to built-in type nodes.
 * @param context
 * @param typeName Representation of type name.
 * @param quals
 * @return Unique pointer to built-in type nodes.
 */
std::shared_ptr<BuiltInTypeNode> BuiltInTypeNode::create(
	Context &context,
	const std::string &typeName,
	const Qualifiers &quals)
{
	auto type = context.getBuiltInType(typeName, quals);
	if (type && type->kind() == Kind::KBuiltInType) {
		return type;
	}

	auto newType = std::shared_ptr<BuiltInTypeNode>(new BuiltInTypeNode(typeName, quals));
	context.addBuiltInType(newType);
	return newType;
}

/**
 * @return String representation of type name.
 */
std::string BuiltInTypeNode::typeName() const
{
	return _typeName;
}

/**
 * @brief Prints text representation of type with qualifiers to output stream.
 */
void BuiltInTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	s << _typeName;
}

}    // borland
}    // demangler
}    // retdec
