/**
* @file include/retdec/demangler/borland_ast/reference_type.h
* @brief Representation of L-value reference type in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_REFERENCE_TYPE_H
#define RETDEC_REFERENCE_TYPE_H

#include "retdec/demangler/borland_ast/type_node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Representation of l-value references.
 */
class ReferenceTypeNode : public TypeNode
{
public:
	static std::shared_ptr<ReferenceTypeNode> create(
		Context &context,
		std::shared_ptr<Node> pointee);

	std::shared_ptr<Node> pointee();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	explicit ReferenceTypeNode(std::shared_ptr<Node> pointee);

private:
	std::shared_ptr<Node> _pointee;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_REFERENCE_TYPE_H
