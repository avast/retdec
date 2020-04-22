/**
* @file src/demangler/borland_ast/function_node.cpp
* @brief Representation of functions.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/demangler/borland_ast/function_node.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Private function node constructor. Use create().
 * @param name Pointer to Name or NestedName node.
 * @param funcType
 */
FunctionNode::FunctionNode(
	std::shared_ptr<Node> name,
	std::shared_ptr<FunctionTypeNode> funcType) :
	Node(Kind::KFunction, false),
	_name(std::move(name)),
	_funcType(std::move(funcType)) {}

/**
 * @brief Creates shared pointer to function node.
 * @param name Pointer to Name or NestedName node.
 * @param funcType
 * @return Unique pointer to constructed FunctionNode.
 */
std::shared_ptr<FunctionNode> FunctionNode::create(
	std::shared_ptr<Node> name,
	std::shared_ptr<FunctionTypeNode> funcType)
{
	return std::shared_ptr<FunctionNode>(
		new FunctionNode(std::move(name), std::move(funcType)));
}

std::shared_ptr<Node> FunctionNode::name()
{
	return _name;
}

std::shared_ptr<FunctionTypeNode> FunctionNode::funcType()
{
	return _funcType;
}

/**
 * @brief Prints text representation of function.
 * @param s Output stream.
 */
void FunctionNode::printLeft(std::ostream &s) const
{
	_funcType->printLeft(s);
	_name->print(s);
	_funcType->printRight(s);
}

}    // borland
}    // demangler
}    // retdec
