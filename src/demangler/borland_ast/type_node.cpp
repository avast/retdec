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

