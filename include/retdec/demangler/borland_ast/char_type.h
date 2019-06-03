/**
* @file include/retdec/demangler/borland_ast/char_type.h
* @brief Representation of char types in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CHAR_TYPE_H
#define RETDEC_CHAR_TYPE_H

#include "retdec/demangler/borland_ast/built_in_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Signedness used for chars.
 * Chars can be signed char, unsigned char and char, which are by standard distinct.
 * These types are all mangled differently.
 */
enum class ThreeStateSignedness
{
	signed_char,
	unsigned_char,
	no_prefix
};

/**
 * @brief Representation of char types.
 */
class CharTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<CharTypeNode> create(
		Context &context,
		ThreeStateSignedness signedness,
		const Qualifiers &quals);

	std::string typeName() const override;

	ThreeStateSignedness signedness();

	void printLeft(std::ostream &s) const override;

private:
	CharTypeNode(
		ThreeStateSignedness signedness,
		const Qualifiers &quals);

private:
	ThreeStateSignedness _signedness;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_CHAR_TYPE_H
