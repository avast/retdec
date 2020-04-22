/**
* @file include/retdec/demangler/borland_ast/node_array.h
* @brief Representation of arrays of nodes in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_NODE_ARRAY_H
#define RETDEC_NODE_ARRAY_H

#include "retdec/demangler/borland_ast/node.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Node for representation of arrays of nodes.
 */
class NodeArray : public Node
{
public:
	static std::shared_ptr<NodeArray> create();

	void addNode(std::shared_ptr<Node> node);

	bool empty() const;

	size_t size();

	void printLeft(std::ostream &s) const override;

	std::shared_ptr<Node> get(unsigned i) const;    // TODO operator []

protected:
	NodeArray();

protected:
	std::vector<std::shared_ptr<Node>> _nodes;
};

/**
 * @brief Node for representation of sequence of Nodes.
 */
class NodeString : public NodeArray
{
public:
	static std::shared_ptr<NodeString> create();

	void printLeft(std::ostream &s) const override;

protected:
	NodeString();
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_NODE_ARRAY_H
