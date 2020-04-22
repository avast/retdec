/**
* @file include/retdec/demangler/borland_ast/float_type.h
* @brief Representation of floating point number types in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_FLOAT_TYPE_H
#define RETDEC_FLOAT_TYPE_H

#include "retdec/demangler/borland_ast/built_in_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Representaion of floating point number types.
 */
class FloatTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<FloatTypeNode> create(
		Context &context,
		const std::string &typeName,
		const Qualifiers &quals);

private:
	FloatTypeNode(const std::string &typeName, const Qualifiers &quals);
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_FLOAT_TYPE_H
