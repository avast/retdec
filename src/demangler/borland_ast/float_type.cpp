/**
* @file src/demangler/borland_ast/float_type.cpp
* @brief Representation of floating point number types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/demangler/borland_ast/float_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Private constructor for floating point types. Use create().
 */
FloatTypeNode::FloatTypeNode(const std::string &typeName, const Qualifiers &quals) :
	BuiltInTypeNode(typeName, quals)
{
	_kind = Kind::KFloatType;
}

/**
 * @brief Function for creating floating point types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param typeName Name of integral type to create.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing floating point type.
 */
std::shared_ptr<FloatTypeNode> FloatTypeNode::create(
	Context &context,
	const std::string &typeName,
	const Qualifiers &quals)
{
	auto type = context.getFloatType(typeName, quals);
	if (type && type->kind() == Kind::KFloatType) {
		return type;
	}

	auto newType = std::shared_ptr<FloatTypeNode>(new FloatTypeNode(typeName, quals));
	context.addFloatType(newType);
	return newType;
}

}    // borland
}    // demangler
}    // retdec
