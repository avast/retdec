/**
* @file include/retdec/demangler/borland_ast/conversion_operator.h
* @brief Representation of conversion operators in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CONVERSION_OPERATOR_H
#define RETDEC_CONVERSION_OPERATOR_H

#include "retdec/demangler/borland_ast/node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/*
 * @brief Representation of conversion operators in borland AST.
 */
class ConversionOperatorNode : public Node
{
public:
	static std::shared_ptr<ConversionOperatorNode> create(std::shared_ptr<Node> type);

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
