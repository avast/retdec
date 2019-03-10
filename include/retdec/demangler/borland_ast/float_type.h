//
// Created by adam on 10.3.19.
//

#ifndef RETDEC_FLOAT_TYPE_H
#define RETDEC_FLOAT_TYPE_H

#include "retdec/demangler/borland_ast/built_in_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Representaion of floating point types.
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
