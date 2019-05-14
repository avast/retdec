/**
* @file src/demangler/borland_ast/integral_type.cpp
* @brief Representation of integral types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/integral_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Private constructor for integral types. Use create().
 */
IntegralTypeNode::IntegralTypeNode(
	const std::string &typeName, bool isUnsigned, const Qualifiers &quals) :
	BuiltInTypeNode(typeName, quals), _isUnsigned(isUnsigned)
{
	_kind = Kind::KIntegralType;
};

/**
 * @brief Function for creating integral types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param typeName Name of integral type to create.
 * @param isUnsigned Information about intgral type signedness.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing integral type.
 */
std::shared_ptr<IntegralTypeNode> IntegralTypeNode::create(
	Context &context,
	const std::string &typeName,
	bool isUnsigned,
	const Qualifiers &quals)
{
	auto type = context.getIntegralType(typeName, isUnsigned, quals);
	if (type && type->kind() == Kind::KIntegralType) {
		return type;
	}

	auto newType = std::shared_ptr<IntegralTypeNode>(new IntegralTypeNode(typeName, isUnsigned, quals));
	context.addIntegralType(newType);
	return newType;
}

/**
 * @return true if type is unsigned, else false.
 */
bool IntegralTypeNode::isUnsigned()
{
	return _isUnsigned;
}

std::string IntegralTypeNode::typeName() const
{
	return _isUnsigned ? "unsigned " + _typeName : _typeName;
}

/**
 * @brief Prints text representation of type with qualifiers to output stream.
 */
void IntegralTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	if (_isUnsigned) {
		s << "unsigned ";
	}
	s << _typeName;
}

}    // borland
}    // demangler
}    // retdec
