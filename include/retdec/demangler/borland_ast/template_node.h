/**
* @file include/retdec/demangler/borland_ast/template_node.h
* @brief Representation of templates in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_TEMPLATE_NODE_H
#define RETDEC_TEMPLATE_NODE_H

#include "retdec/demangler/borland_ast/node.h"

namespace retdec {
namespace demangler {
namespace borland {

/*
 * @brief Representation of templates in borland AST.
 */
class TemplateNode : public Node
{
public:
	static std::shared_ptr<TemplateNode> create(
		std::shared_ptr<Node> name,
		std::shared_ptr<Node> params);

	void printLeft(std::ostream &s) const override;

private:
	TemplateNode(
		std::shared_ptr<Node> name,
		std::shared_ptr<Node> params);

private:
	std::shared_ptr<Node> _name;
	std::shared_ptr<Node> _params;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_TEMPLATE_NODE_H
