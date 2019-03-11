
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

	std::shared_ptr<Node> get(unsigned i) const;	// TODO operator []

private:
	NodeArray();

private:
	std::vector<std::shared_ptr<Node>> _nodes;
};

}    // borland
}    // demangler
}    // retdec


#endif //RETDEC_NODE_ARRAY_H
