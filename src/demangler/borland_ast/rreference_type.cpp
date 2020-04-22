/**
* @file src/demangler/borland_ast/rreference_type.cpp
* @brief Representation of R-value reference types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/rreference_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Private constructor for r-value references. Use create().
 * Reference can't be const or volatile.
 */
RReferenceTypeNode::RReferenceTypeNode(std::shared_ptr<Node> pointee) :
	TypeNode({false, false}), _pointee(std::move(pointee))
{
	_kind = Kind::KRReferenceType;
	_has_right = _pointee->hasRight();
}

/**
 * @brief Function for creating r-value references.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param pointee Referenced type.
 * @return Node representing r-value reference type.
 */
std::shared_ptr<RReferenceTypeNode> RReferenceTypeNode::create(
	Context &context, std::shared_ptr<Node> pointee)
{
	auto type = context.getRReferenceType(pointee);
	if (type) {
		return type;
	}

	auto newType = std::shared_ptr<RReferenceTypeNode>(new RReferenceTypeNode(pointee));
	context.addRReferenceType(newType);
	return newType;
}

/**
 * @return Referenced type.
 */
std::shared_ptr<Node> RReferenceTypeNode::pointee()
{
	return _pointee;
}

/**
 * @brief Prints left side of reference type or whole, depending on pointee.
 * Right side printing is used for arrays and references to function types.
 */
void RReferenceTypeNode::printLeft(std::ostream &s) const
{
	if (_pointee->hasRight()) {
		_pointee->printLeft(s);
		s << "(&&";
	} else {
		_pointee->print(s);
		s << " &&";
		_quals.printSpaceL(s);
	}
}

/**
 * @brief Prints right side of reference type.
 * Used for array and funtion types.
 */
void RReferenceTypeNode::printRight(std::ostream &s) const
{
	s << ")";
	_pointee->printRight(s);
}

}    // borland
}    // demangler
}    // retdec
