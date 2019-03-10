//
// Created by adam on 10.3.19.
//

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
	explicit TypeNode(const Qualifiers &quals);	// TODO kind ako volitelny parameter

protected:
	Qualifiers _quals;
};

}    // borland
}    // demangler
}    // retdec


#endif //RETDEC_TYPE_NODE_H
