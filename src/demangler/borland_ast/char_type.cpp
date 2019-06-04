/**
* @file src/demangler/borland_ast/char_type.cpp
* @brief Representation of char types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/char_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Private constructor for Char types. Use create().
 */
CharTypeNode::CharTypeNode(ThreeStateSignedness signedness, const Qualifiers &quals) :
	BuiltInTypeNode("char", quals), _signedness(signedness)
{
	_kind = Kind::KCharType;
}

/**
 * @brief Function for creating char types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param signedness Char signednes. Chars can be char, signed char, unsigned char. All are distinct types by standard.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing char type.
 */
std::shared_ptr<CharTypeNode> CharTypeNode::create(
	Context &context,
	ThreeStateSignedness signedness,
	const Qualifiers &quals)
{
	auto type = context.getCharType(signedness, quals);
	if (type && type->kind() == Kind::KCharType) {
		return type;
	}

	auto newType = std::shared_ptr<CharTypeNode>(new CharTypeNode(signedness, quals));
	context.addCharType(newType);
	return newType;
}

std::string CharTypeNode::typeName() const
{
	switch (_signedness) {
	case ThreeStateSignedness::signed_char:
		return "signed char";
	case ThreeStateSignedness::unsigned_char:
		return "unsigned char";
	default:
		return "char";
	}
}

/**
 * @return signedness of type.
 */
ThreeStateSignedness CharTypeNode::signedness()
{
	return _signedness;
}

/**
 * @brief Prints text representation of char type with qualifiers to output stream.
 */
void CharTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	s << typeName();
}

}    // borland
}    // demangler
}    // retdec
