/**
* @file include/retdec/demangler/borland_ast/type_node.h
* @brief Base class for all types in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_TYPE_NODE_H
#define RETDEC_TYPE_NODE_H

#include "retdec/demangler/borland_ast/node.h"
#include "retdec/demangler/borland_ast/qualifiers.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Base class for all type nodes.
 */
class TypeNode : public Node
{
public:
	Qualifiers quals();

protected:
	explicit TypeNode(const Qualifiers &quals);

protected:
	Qualifiers _quals;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_TYPE_NODE_H
