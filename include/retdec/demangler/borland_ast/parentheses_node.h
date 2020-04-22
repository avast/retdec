/**
* @file include/retdec/demangler/borland_ast/parentheses_node.h
* @brief Representation of node that adds parentheses around another node in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_PARENTHESES_NODE_H
#define RETDEC_PARENTHESES_NODE_H

#include "retdec/demangler/borland_ast/node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/*
 * @brief Representation of node that adds parentheses around another node in borland AST.
 */
class ParenthesesNode : public Node
{
public:
	static std::shared_ptr<ParenthesesNode> create(std::shared_ptr<Node> type);

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
