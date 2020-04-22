/**
* @file src/demangler/borland_ast/array_type.cpp
* @brief Representation of array types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/array_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Private constructor for array types. Use create().
 */
ArrayNode::ArrayNode(
	std::shared_ptr<Node> pointee,
	unsigned size,
	const Qualifiers &quals) :
	TypeNode(quals), _pointee(std::move(pointee)), _size(size)
{
	_kind = Kind::KArrayNode;
	_has_right = true;
}

/**
 * @brief Function for creating array types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param pointee Type of array.
 * @param size
 * @param quals
 * @return Node representing array type.
 */
std::shared_ptr<ArrayNode> ArrayNode::create(
	Context &context,
	std::shared_ptr<Node> pointee,
	unsigned size,
	const Qualifiers &quals)
{
	auto type = context.getArray(pointee, size, quals);
	if (type) {
		return type;
	}

	auto newType = std::shared_ptr<ArrayNode>(new ArrayNode(pointee, size, quals));
	context.addArrayType(newType);
	return newType;
}

unsigned ArrayNode::size()
{
	return _size;
}

std::shared_ptr<Node> ArrayNode::pointee()
{
	return _pointee;
}

/**
 * Prints left side of array type to output stream.
 */
void ArrayNode::printLeft(std::ostream &s) const
{
	_pointee->printLeft(s);
	_quals.printSpaceL(s);
}

/**
 * Prints right side of array type to output stream.
 */
void ArrayNode::printRight(std::ostream &s) const
{
	s << "[" << _size << "]";
	_pointee->printRight(s);
}

}    // borland
}    // demangler
}    // retdec
