#ifndef RETDEC_PARENTHESES_NODE_H
#define RETDEC_PARENTHESES_NODE_H

#include "retdec/demangler/borland_ast/node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

class ParenthesesNode : public Node
{
public:
	static std::shared_ptr<ParenthesesNode> create(Context &context, std::shared_ptr<Node> type);

	void printLeft(std::ostream &s) const override;

private:
	explicit ParenthesesNode(std::shared_ptr<Node> type);

private:
	std::shared_ptr<Node> _type;
};

}	// namespace borland
}	// namespace demangler
}	// namespace retdec


#endif //RETDEC_PARENTHESES_NODE_H
