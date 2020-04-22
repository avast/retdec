/**
* @file src/demangler/borland_ast/conversion_operator.cpp
* @brief Base class for all types in AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/demangler/borland_ast/type_node.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Constructor for abstract class TypeNode.
 * @param quals Qualifiers object. Types can have const/volatile qualifiers.
 */
TypeNode::TypeNode(const Qualifiers &quals) :
	Node(Kind::KTypeNode), _quals(quals) {}

/**
 * @return Type qualifiers.
 */
Qualifiers TypeNode::quals()
{
	return _quals;
}

}    // borland
}    // demangler
}    // retdec
