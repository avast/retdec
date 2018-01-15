/**
* @file src/llvmir2hll/graphs/cfg/cfg_writers/graphviz_cfg_writer.cpp
* @brief Implementation of GraphvizCFGWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>
#include <queue>

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_writer_factory.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_writers/graphviz_cfg_writer.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/graphviz.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

using retdec::utils::hasItem;
using retdec::utils::replaceCharsWithStrings;
using retdec::utils::toString;

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("dot", GRAPHVIZ_CFG_WRITER_ID, CFGWriterFactory,
	GraphvizCFGWriter::create);

namespace {

/// Whitespace for indentation.
const std::string INDENT = "  ";

/**
* @brief Creates a label from @a str so it can be used in labels in the @c dot
*        format.
*
* If @a str is of the form @c (x), then the surrounding brackets are removed to
* simplify the resulting label (brackets are placed around every expression).
*/
std::string createLabel(const std::string &str) {
	auto result = UtilsGraphviz::createLabel(str);

	// Replace all newlines with '\l' and appropriate indentation. This has to
	// be done after characters backslashing, which was done in
	// UtilsGraphviz::createLabel() above.
	result = replaceCharsWithStrings(result, '\n', "\\l" + INDENT);

	// Remove redundant brackets around expressions.
	if (result.front() == '(' && result.back() == ')') {
		result = result.substr(1, result.size() - 2);
	}

	return result;
}

/**
* @brief Returns a string representation of @a cfgNode to be used as a unique
*        identifier of the node.
*/
std::string cfgNodeToGraphvizNode(ShPtr<CFG::Node> cfgNode) {
	// To ensure uniqueness, we use the node's address.
	return "Node" + createLabel(toString(cfgNode.get()));
}

/**
* @brief Returns the "name" of the given function @a func, i.e. the function's
*        name followed by a list of its parameters.
*
* An example of a function's name is <tt>printf(*str, ...)</tt>.
*/
std::string createFuncName(ShPtr<Function> func) {
	auto funcName = func->getTextRepr();

	// Remove the prefix "def " (if any).
	const std::string prefix("def ");
	if (funcName.find(prefix) == 0) {
		return funcName.substr(prefix.size());
	}
	return funcName;
}

} // anonymous namespace

/**
* @brief Constructs a new graphviz CFG writer.
*
* See create() for the description of parameters.
*/
GraphvizCFGWriter::GraphvizCFGWriter(ShPtr<CFG> cfg, std::ostream &out):
	CFGWriter(cfg, out) {}

/**
* @brief Creates a new graphviz CFG writer.
*
* @param[in] cfg CFG to be emitted.
* @param[in] out Output stream into which the CFG will be emitted.
*/
ShPtr<CFGWriter> GraphvizCFGWriter::create(ShPtr<CFG> cfg, std::ostream &out) {
	return ShPtr<CFGWriter>(new GraphvizCFGWriter(cfg, out));
}

std::string GraphvizCFGWriter::getId() const {
	return GRAPHVIZ_CFG_WRITER_ID;
}

bool GraphvizCFGWriter::emitCFG() {
	auto funcName = createFuncName(cfg->getCorrespondingFunction());

	out << "digraph \"Control-flow graph for function '" << funcName << "'.\" {\n";
	out << INDENT << "label=\"Control-flow graph for function '" << funcName << "'.\";\n";
	out << INDENT << "node [shape=record];\n";
	out << "\n";

	// Perform a breath-first traversal and emit nodes and edges as they are
	// visited. In this way, we keep the desired structure of the CFG.
	NodeSet emittedNodes;
	emitNodesByBreathFirstTraversal(cfg->getEntryNode(), emittedNodes);

	// Since the CFG may be disconnected, we also have to emit all the
	// unreachable nodes.
	for (auto node : cfg->getUnreachableNodes()) {
		emitNodesByBreathFirstTraversal(node, emittedNodes);
	}

	out << "\n";
	out << "}\n";
	return true;
}

/**
* @brief Emits nodes starting from @a startNode by using a breadth-first
*        traversal.
*
* Emitted nodes are inserted into @a emittedNodes. If a node is already in @a
* emittedNodes, it is not emitted.
*/
void GraphvizCFGWriter::emitNodesByBreathFirstTraversal(
		ShPtr<CFG::Node> startNode, NodeSet &emittedNodes) {
	std::queue<ShPtr<CFG::Node>> nodesToEmit;
	nodesToEmit.push(startNode);
	while (!nodesToEmit.empty()) {
		auto node = nodesToEmit.front();
		nodesToEmit.pop();

		if (hasItem(emittedNodes, node)) {
			continue;
		}

		emitNode(node);
		emittedNodes.insert(node);

		// For each successor...
		for (auto i = node->succ_begin(), e = node->succ_end(); i != e; ++i) {
			emitEdge(*i);
			nodesToEmit.push((*i)->getDst());
		}
	}
}

/**
* @brief Emits the given node to @c out.
*/
void GraphvizCFGWriter::emitNode(ShPtr<CFG::Node> node) {
	out << INDENT << cfgNodeToGraphvizNode(node) << " [label=\"{";

	// Node label (optional).
	auto label = node->getLabel();
	if (!label.empty()) {
		out << createLabel(label) << ":\\l";
	}

	// Statements.
	for (auto i = node->stmt_begin(), e = node->stmt_end(); i != e; ++i) {
		emitStmt(*i);
	}

	out << "}\"];\n";
}

/**
* @brief Emits the given edge to @c out.
*/
void GraphvizCFGWriter::emitEdge(ShPtr<CFG::Edge> edge) {
	out << INDENT << cfgNodeToGraphvizNode(edge->getSrc()) << " -> "
		<< cfgNodeToGraphvizNode(edge->getDst());
	if (auto label = edge->getLabel()) {
		out << " [label=\"" << createLabel(label->getTextRepr()) << "\"]";
	}
	out << ";\n";
}

/**
* @brief Emits the given statement to @c out.
*/
void GraphvizCFGWriter::emitStmt(ShPtr<Statement> stmt) {
	out << INDENT << createLabel(stmt->getTextRepr()) << "\\l";
}

} // namespace llvmir2hll
} // namespace retdec
