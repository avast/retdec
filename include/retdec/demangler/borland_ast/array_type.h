/**
* @file include/retdec/demangler/borland_ast/array_type.h
* @brief Representation of array types in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_ARRAY_TYPE_H
#define RETDEC_ARRAY_TYPE_H

#include "retdec/demangler/borland_ast/type_node.h"
#include "retdec/demangler/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Representation of array types.
 */
class ArrayNode : public TypeNode
{
public:
	static std::shared_ptr<ArrayNode> create(
		Context &context,
		std::shared_ptr<Node> pointee,
		unsigned size,
		const Qualifiers &quals);

	std::shared_ptr<Node> pointee();

	unsigned size();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	ArrayNode(
		std::shared_ptr<Node> pointee,
		unsigned size,
		const Qualifiers &quals);

private:
	std::shared_ptr<Node> _pointee;
	unsigned _size;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_ARRAY_TYPE_H
