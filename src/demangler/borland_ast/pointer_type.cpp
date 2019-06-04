/**
* @file src/demangler/borland_ast/pointer_type.cpp
* @brief Representation of pointer types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/pointer_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Private constructor for pointers. Use create().
 */
PointerTypeNode::PointerTypeNode(const std::shared_ptr<Node> &pointee, const Qualifiers &quals) :
	TypeNode(quals), _pointee(std::move(pointee))
{
	_kind = Kind::KPointerType;
	_has_right = _pointee->hasRight();
}

/**
 * @brief Function for creating pointers.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param pointee Pointed type.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing pointer type.
 */
std::shared_ptr<PointerTypeNode> PointerTypeNode::create(
	Context &context,
	const std::shared_ptr<Node> &pointee,
	const Qualifiers &quals)
{
	auto type = context.getPointerType(pointee, quals);
	if (type && type->kind() == Kind::KPointerType) {
		return type;
	}

	auto newType = std::shared_ptr<PointerTypeNode>(new PointerTypeNode(pointee, quals));
	context.addPointerType(newType);
	return newType;
}

/**
 * @return Pointed type.
 */
std::shared_ptr<Node> PointerTypeNode::pointee()
{
	return _pointee;
}

/**
 * @brief Prints left side of pointer type or whole, depending on pointee.
 * Right side printing is used for arrays and pointers to function types.
 */
void PointerTypeNode::printLeft(std::ostream &s) const
{
	if (_pointee->hasRight()) {
		_pointee->printLeft(s);
		s << "(*";
		_quals.printSpaceL(s);
	} else {
		_pointee->print(s);
		s << " *";
		_quals.printSpaceL(s);
	}
}

/**
 * @brief Prints right side of pointer type.
 * Used for array and funtion types.
 */
void PointerTypeNode::printRight(std::ostream &s) const
{
	s << ")";
	_pointee->printRight(s);
}

}    // borland
}    // demangler
}    // retdec
