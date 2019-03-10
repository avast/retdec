//
// Created by adam on 10.3.19.
//

#ifndef RETDEC_BUILT_IN_TYPE_H
#define RETDEC_BUILT_IN_TYPE_H

#include "retdec/demangler/borland_ast/type_node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Node for representation of built-in types.
 */
class BuiltInTypeNode : public TypeNode
{
public:
	static std::shared_ptr<BuiltInTypeNode> create(
		Context &context,
		const std::string &typeName,
		const Qualifiers &quals);

	std::string typeName() const;

	void printLeft(std::ostream &s) const override;

protected:
	BuiltInTypeNode(const std::string &typeName, const Qualifiers &quals);

protected:
	std::string _typeName;
};

}    // borland
}    // demangler
}    // retdec


#endif //RETDEC_BUILT_IN_TYPE_H
