/**
* @file src/demangler/borland_ast/conversion_operator.cpp
* @brief Representation of conversion operators.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/conversion_operator.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Private constructor for Conversino Operator Node. Use create.
 * @param type Node representing target type.
 */
ConversionOperatorNode::ConversionOperatorNode(
	std::shared_ptr<Node> type) :
	Node(Kind::KConversionOperator), _type(std::move(type)) {}

/**
 * Creates shared pointer with Conversion operator.
 * @param type Node representing target type.
 * @return pointer to constructed operator.
 */
std::shared_ptr<ConversionOperatorNode> ConversionOperatorNode::create(std::shared_ptr<Node> type)
{
	return std::shared_ptr<ConversionOperatorNode>(new ConversionOperatorNode(std::move(type)));
}

/**
 * Prints string representation of conversion operator.
 * @param s Output stream.
 */
void ConversionOperatorNode::printLeft(std::ostream &s) const
{
	s << "operator ";
	_type->print(s);
}

}    // borland
}    // demangler
}    // retdec
