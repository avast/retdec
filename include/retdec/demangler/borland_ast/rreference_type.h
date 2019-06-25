/**
* @file include/retdec/demangler/borland_ast/rreference_type.h
* @brief Representation of R-value reference type in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_RREFERENCE_TYPE_H
#define RETDEC_RREFERENCE_TYPE_H

#include "retdec/demangler/borland_ast/type_node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Representation of R-value references.
 */
class RReferenceTypeNode : public TypeNode
{
public:
	static std::shared_ptr<RReferenceTypeNode> create(
		Context &context,
		std::shared_ptr<Node> pointee);

	std::shared_ptr<Node> pointee();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	explicit RReferenceTypeNode(std::shared_ptr<Node> pointee);

private:
	std::shared_ptr<Node> _pointee;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_RREFERENCE_TYPE_H
