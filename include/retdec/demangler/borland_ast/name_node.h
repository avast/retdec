/**
* @file include/retdec/demangler/borland_ast/name_node.h
* @brief Representation of names in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_NAME_NODE_H
#define RETDEC_NAME_NODE_H

#include "retdec/demangler/borland_ast/node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Node for representation of names.
 */
class NameNode : public Node
{
public:
	static std::shared_ptr<NameNode> create(
		Context &context,
		const std::string &name);

	void printLeft(std::ostream &s) const override;

private:
	explicit NameNode(const std::string &name);

private:
	std::string _name;
};

/**
 * @brief Node for representation of nested names.
 */
class NestedNameNode : public Node
{
public:
	static std::shared_ptr<NestedNameNode> create(
		Context &context,
		std::shared_ptr<Node> super,
		std::shared_ptr<Node> name);

	void printLeft(std::ostream &s) const override;

	std::shared_ptr<Node> super();

	std::shared_ptr<Node> name();

private:
	NestedNameNode(
		std::shared_ptr<Node> super,
		std::shared_ptr<Node> name);

private:
	std::shared_ptr<Node> _super;
	std::shared_ptr<Node> _name;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_NAME_NODE_H
