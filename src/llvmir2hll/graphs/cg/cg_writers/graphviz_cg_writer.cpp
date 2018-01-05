/**
* @file src/llvmir2hll/graphs/cg/cg_writers/graphviz_cg_writer.cpp
* @brief Implementation of GraphvizCGWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/graphs/cg/cg_writer_factory.h"
#include "retdec/llvmir2hll/graphs/cg/cg_writers/graphviz_cg_writer.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/graphviz.h"
#include "retdec/utils/conversion.h"

using retdec::utils::toString;

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("dot", GRAPHVIZ_CG_WRITER_ID, CGWriterFactory,
	GraphvizCGWriter::create);

namespace {
/// Whitespace for indentation.
const std::string INDENT = "  ";

/// Color of nodes for declared functions (i.e. not defined).
const std::string DECL_FUNCS_NODE_COLOR = "gray50";

/// Color of nodes for functions calling some functions by a pointer.
const std::string CALLS_BY_POINTER_FUNCS_NODE_COLOR = "red";

/// Color of clusters representing modules.
const std::string MODULE_CLUSTER_COLOR = "blue3";

/// Prefix for node labels.
const std::string NODE_LABEL_PREFIX = "Node_";

/// Prefix for clusters representing modules.
// Note: To produce clusters, the name of a subgraph has to begin with
// "cluster".
const std::string MODULE_CLUSTER_LABEL_PREFIX = "cluster_";
}

/**
* @brief Constructs a new graphviz CG writer.
*
* See create() for the description of parameters.
*/
GraphvizCGWriter::GraphvizCGWriter(ShPtr<CG> cg, std::ostream &out):
	CGWriter(cg, out) {}

/**
* @brief Creates a new graphviz CG writer.
*
* @param[in] cg CG to be emitted.
* @param[in] out Output stream into which the CG will be emitted.
*/
ShPtr<CGWriter> GraphvizCGWriter::create(ShPtr<CG> cg, std::ostream &out) {
	return ShPtr<CGWriter>(new GraphvizCGWriter(cg, out));
}

std::string GraphvizCGWriter::getId() const {
	return GRAPHVIZ_CG_WRITER_ID;
}

bool GraphvizCGWriter::emitCG() {
	ShPtr<Module> module(cg->getCorrespondingModule());
	StringSet moduleNames(module->getDebugModuleNames());

	// If there is debug information available, generate module names in the
	// graph's name.
	out << "digraph \"Call graph of the module.\" {\n";
	if (!moduleNames.empty()) {
		out << INDENT << "label=\"Call graph of module" <<
			(moduleNames.size() > 1 ? "s" : "") << " ";
		bool moduleNameEmitted = false;
		for (const auto &moduleName : moduleNames) {
			if (moduleNameEmitted) {
				out << ", ";
			}
			out << UtilsGraphviz::createLabel(moduleName);
			moduleNameEmitted = true;
		}
		out << ".\";\n";
	} else {
		out << INDENT << "label=\"Call graph of the module.\";\n";
	}
	out << INDENT << "node [shape=record];\n";
	out << "\n";

	// If there is debug information available, generate each function into a
	// cluster (subgraph) that corresponds to its module.
	if (!moduleNames.empty()) {
		// For every module name...
		for (const auto &moduleName : moduleNames) {
			out << INDENT << "subgraph " << UtilsGraphviz::createNodeName(
				MODULE_CLUSTER_LABEL_PREFIX + moduleName) << " {\n";
			out << INDENT << INDENT << "label=\"" << UtilsGraphviz::createLabel(moduleName) << "\";\n";
			out << INDENT << INDENT << "color=\"" << MODULE_CLUSTER_COLOR << "\";\n";
			out << INDENT << INDENT << "fontcolor=\"" << MODULE_CLUSTER_COLOR << "\";\n";
			out << "\n";

			// Emit nodes for functions which are in this module.
			for (auto i = cg->caller_begin(), e = cg->caller_end(); i != e; ++i) {
				if (module->getDebugModuleNameForFunc(i->first) == moduleName) {
					out << INDENT;
					emitNode(i->first, i->second);
				}
			}
			out << INDENT << "}\n";
			out << "\n";
		}

		// Emit nodes for functions which do not have an assigned module.
		for (auto i = cg->caller_begin(), e = cg->caller_end(); i != e; ++i) {
			if (!module->hasAssignedDebugModuleName(i->first)) {
				emitNode(i->first, i->second);
			}
		}
		out << "\n";
	} else {
		// Emit a node for each caller in the module without any clusters...
		for (auto i = cg->caller_begin(), e = cg->caller_end(); i != e; ++i) {
			emitNode(i->first, i->second);
		}
	}

	// Emit relationships between nodes (i.e. who calls who).
	for (auto i = cg->caller_begin(), e = cg->caller_end(); i != e; ++i) {
		// For each callee of the current caller...
		for (const auto &callee : i->second->callees) {
			out << INDENT << getNodeLabelForFunc(i->first) << " -> "
				<< getNodeLabelForFunc(callee) << ";\n";
		}
	}

	out << "}\n";
	return true;
}

/**
* @brief Emits the node given by @a caller and @a callees.
*/
void GraphvizCGWriter::emitNode(ShPtr<Function> caller, ShPtr<CG::CalledFuncs> callees) {
	out << INDENT << getNodeLabelForFunc(caller) << " [";

	// Should the node be of a specific color?
	if (callees->caller->isDeclaration()) {
		out << "color=\"" << DECL_FUNCS_NODE_COLOR << "\"";
		out << ", fontcolor=\"" << DECL_FUNCS_NODE_COLOR << "\", ";
	} else if (callees->callsByPointer) {
		out << "color=\"" << CALLS_BY_POINTER_FUNCS_NODE_COLOR << "\"";
		out << ", fontcolor=\"" << CALLS_BY_POINTER_FUNCS_NODE_COLOR << "\", ";
	}
	out << "label=\"{" << UtilsGraphviz::createLabel(caller->getName()) << "}\"";
	out << "];\n";
}

/**
* @brief Returns a node label for the given function.
*/
std::string GraphvizCGWriter::getNodeLabelForFunc(ShPtr<Function> func) {
	return NODE_LABEL_PREFIX + func->getName();
}

} // namespace llvmir2hll
} // namespace retdec
