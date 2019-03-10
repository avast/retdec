#ifndef RETDEC_FUNCTION_NODE_H
#define RETDEC_FUNCTION_NODE_H

#include "retdec/demangler/borland_ast/node.h"
#include "retdec/demangler/borland_ast/function_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Node for representation of functions.
 */
class FunctionNode : public Node
{
public:
	static std::shared_ptr<FunctionNode> create(
		std::shared_ptr<Node> name,
		std::shared_ptr<FunctionTypeNode> funcType);

	void printLeft(std::ostream &s) const override;

private:
	FunctionNode(
		std::shared_ptr<Node> name,
		std::shared_ptr<FunctionTypeNode> funcType);

private:
	std::shared_ptr<Node> _name;
	std::shared_ptr<FunctionTypeNode> _funcNode;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_FUNCTION_NODE_H
