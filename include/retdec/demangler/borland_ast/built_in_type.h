/**
* @file include/retdec/demangler/borland_ast/built_in_type.h
* @brief Representation of built-in types in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BUILT_IN_TYPE_H
#define RETDEC_BUILT_IN_TYPE_H

#include "retdec/demangler/borland_ast/type_node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Node for representation of built-in types.
 * Used for types: void, bool, char16_t, char32_t and wchar_t
 */
class BuiltInTypeNode : public TypeNode
{
public:
	static std::shared_ptr<BuiltInTypeNode> create(
		Context &context,
		const std::string &typeName,
		const Qualifiers &quals);

	virtual std::string typeName() const;

	void printLeft(std::ostream &s) const override;

protected:
	BuiltInTypeNode(
		const std::string &typeName,
		const Qualifiers &quals);

protected:
	std::string _typeName;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_BUILT_IN_TYPE_H
