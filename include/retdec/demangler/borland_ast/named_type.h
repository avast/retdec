//
// Created by adam on 10.3.19.
//

#ifndef RETDEC_NAMED_TYPE_H
#define RETDEC_NAMED_TYPE_H

#include "retdec/demangler/borland_ast/type_node.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Representation of named types.
 */
class NamedTypeNode : public TypeNode
{
public:
	static std::shared_ptr<NamedTypeNode> create(
		std::shared_ptr<Node> typeName,
		const Qualifiers &quals);

	std::shared_ptr<Node> name();

	void printLeft(std::ostream &s) const override;

private:
	NamedTypeNode(std::shared_ptr<Node> typeName, const Qualifiers &quals);

private:
	std::shared_ptr<Node> _typeName;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_NAMED_TYPE_H
