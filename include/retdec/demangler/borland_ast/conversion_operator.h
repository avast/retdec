
#ifndef RETDEC_CONVERSION_OPERATOR_H
#define RETDEC_CONVERSION_OPERATOR_H

#include "retdec/demangler/borland_ast/node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

class ConversionOperatorNode : public Node
{
public:
	static std::shared_ptr<ConversionOperatorNode> create(Context &context, std::shared_ptr<Node> type);

	void printLeft(std::ostream &s) const override;

private:
	ConversionOperatorNode(std::shared_ptr<Node> type);

private:
	std::shared_ptr<Node> _type;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_CONVERSION_OPERATOR_H
