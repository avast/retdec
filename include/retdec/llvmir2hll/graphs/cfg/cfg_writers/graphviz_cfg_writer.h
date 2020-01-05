/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_writers/graphviz_cfg_writer.h
* @brief A CFG writer in the @c dot format (@c graphviz).
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_WRITERS_GRAPHVIZ_CFG_WRITER_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_WRITERS_GRAPHVIZ_CFG_WRITER_H

#include <ostream>
#include <set>
#include <string>

#include "retdec/llvmir2hll/graphs/cfg/cfg_writer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class CFG;

/**
* @brief A CFG writer in the @c dot format (@c graphviz).
*
* For more information on the @c dot format, see http://www.graphviz.org/.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class GraphvizCFGWriter: public CFGWriter {
public:
	static CFGWriter* create(CFG* cfg, std::ostream &out);

	virtual std::string getId() const override;
	virtual bool emitCFG() override;

private:
	/// Set of nodes.
	using NodeSet = std::set<CFG::Node*>;

private:
	GraphvizCFGWriter(CFG* cfg, std::ostream &out);

	void emitNodesByBreathFirstTraversal(CFG::Node* startNode,
		NodeSet &emittedNodes);
	void emitNode(CFG::Node* node);
	void emitEdge(CFG::Edge* edge);
	void emitStmt(Statement* stmt);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
