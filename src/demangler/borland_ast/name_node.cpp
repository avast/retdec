/**
* @file src/demangler/borland_ast/name_node.cpp
* @brief Representation of names.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <iostream>

#include "retdec/demangler/borland_ast/name_node.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Constructor for NameNode
 * @param name std::string representation of name.
 */
NameNode::NameNode(const std::string &name) : Node(NameNode::Kind::KName, false), _name(name) {}

/**
 * @param context
 * @param name std::string representation of name.
 * @return Unique pointer to new NameNode
 */
std::shared_ptr<NameNode> NameNode::create(Context &context, const std::string &name)
{
	auto type = context.getName(name);
	if (type) {
		return type;
	}

	auto newName = std::shared_ptr<NameNode>(new NameNode(name));
	context.addName(newName);
	return newName;
}

/**
 * @brief Prints string represention of node.
 * @param s output stream
 */
void NameNode::printLeft(std::ostream &s) const
{
	s << _name;
}

/**
 * NestedName constructor.
 * @param super Higher level node.
 * @param name Lower level node.
 */
NestedNameNode::NestedNameNode(
	std::shared_ptr<Node> super, std::shared_ptr<Node> name) :
	Node(NameNode::Kind::KNestedName, false),
	_super(std::move(super)), _name(std::move(name)) {}

/**
 * @param context
 * @param super Higher level node.
 * @param name Lower level node.
 * @return Unique pointer to new nested name node.
 */
std::shared_ptr<NestedNameNode> NestedNameNode::create(
	Context &context, std::shared_ptr<Node> super, std::shared_ptr<Node> name)
{
	auto type = context.getNestedName(super, name);
	if (type) {
		return type;
	}

	auto newName = std::shared_ptr<NestedNameNode>(new NestedNameNode(super, name));
	context.addNestedName(newName);
	return newName;
}

/**
 * @brief Prints left side of node represention.
 * @param s output stream
 */
void NestedNameNode::printLeft(std::ostream &s) const
{
	_super->print(s);
	s << std::string{"::"};
	_name->print(s);
}

/**
 * @return Higher level nodes in nested name.
 */
std::shared_ptr<Node> NestedNameNode::super()
{
	return _super;
}

/**
 * @return Lover level node in neste name.
 */
std::shared_ptr<Node> NestedNameNode::name()
{
	return _name;
}

}    // borland
}    // demangler
}    // retdec
