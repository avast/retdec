/**
* @file include/retdec/demangler/borland_ast/pointer_type.h
* @brief Representation of pointer type in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_POINTER_TYPE_H
#define RETDEC_POINTER_TYPE_H

#include "retdec/demangler/borland_ast/type_node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Representation of pointers.
 */
class PointerTypeNode : public TypeNode
{
public:
	static std::shared_ptr<PointerTypeNode> create(
		Context &context,
		const std::shared_ptr<Node> &pointee,
		const Qualifiers &quals);

	std::shared_ptr<Node> pointee();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	PointerTypeNode(
		const std::shared_ptr<Node> &pointee,
		const Qualifiers &quals);

private:
	std::shared_ptr<Node> _pointee;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_POINTER_TYPE_H
