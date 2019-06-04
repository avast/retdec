/**
* @file src/demangler/borland_ast/template_node.cpp
* @brief Representation of templates.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/template_node.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Private Template node constructor. TemplateNode::create should be used.
 * @param name Name node.
 * @param params Array node of parameters.
 */
TemplateNode::TemplateNode(
	std::shared_ptr<Node> name,
	std::shared_ptr<Node> params) :
	Node(Kind::KTemplateNode), _name(std::move(name)),
	_params(std::move(params)) {}

/**
 * @brief Creates shared pointer to template node.
 * @param name Pointer to Name or NestedName node.
 * @param params Pointer to parameters.
 * @return Unique pointer to constructed TemplateNode.
 */
std::shared_ptr<TemplateNode> TemplateNode::create(
	std::shared_ptr<Node> name,
	std::shared_ptr<Node> params)
{
	return std::shared_ptr<TemplateNode>(
		new TemplateNode(std::move(name), std::move(params)));
}

/**
 * @brief Prints text representation of template.
 * @param s Output stream.
 */
void TemplateNode::printLeft(std::ostream &s) const
{
	_name->print(s);
	s << "<";
	if (_params) {
		_params->print(s);
	}
	s << ">";
}

}    // borland
}    // demangler
}    // retdec
