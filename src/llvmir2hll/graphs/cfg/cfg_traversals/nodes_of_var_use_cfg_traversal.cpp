/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/nodes_of_var_use_cfg_traversal.cpp
* @brief Implementation of NodesOfVarUseCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/nodes_of_var_use_cfg_traversal.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* See the description of getNodesOfUseVariable for information on the parameters.
*/
NodesOfVarUseCFGTraversal::NodesOfVarUseCFGTraversal(
	const VarDefStmtSet &setOfVarDefStmt, ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va):
		CFGTraversal(cfg, true), va(va),
		mapOfVarDefStmtNodes(new VarDefStmtNodeMap()) {
	// Initialize map where key is a variable from VarDefStmt and item is a
	// VarDefStmt.
	for (const auto &varDefStmt : setOfVarDefStmt) {
		mapOfVarVarDef[varDefStmt->getVar()] = varDefStmt;
	}
}

/**
* @brief Destructs the traverser.
*/
NodesOfVarUseCFGTraversal::~NodesOfVarUseCFGTraversal() {}

/**
* @brief Function finds all nodes where is variable from it's own definition
*        used.
*
* @param[in] setOfVarDefStmt Set with VarDefStmt statements.
* @param[in] cfg @a CFG that should be traversed.
* @param[in] va @a Analysis of values.
*
* @return map where key is a VarDefStmt and item is a set of all nodes where
*         variable from VarDefStmt is used.
*
* @par Preconditions
*  - @a cfg and @a va are non-null
*
* This function leaves @a va in a valid state.
*/
ShPtr<NodesOfVarUseCFGTraversal::VarDefStmtNodeMap> NodesOfVarUseCFGTraversal::
		getNodesOfUseVariable(const VarDefStmtSet &setOfVarDefStmt, ShPtr<CFG> cfg,
		ShPtr<ValueAnalysis> va) {
	PRECONDITION_NON_NULL(cfg);
	PRECONDITION_NON_NULL(va);

	ShPtr<NodesOfVarUseCFGTraversal> traverser(new NodesOfVarUseCFGTraversal(
		setOfVarDefStmt, cfg, va));

	// Obtain the first statement of the function. We have to skip the entry
	// node because there are just statements corresponding to the VarDefStmts
	// for function parameters.
	ShPtr<CFG::Node> funcBodyNode((*cfg->getEntryNode()->succ_begin())->getDst());
	if (!funcBodyNode->hasStmts()) {
		// There are no statements, so there is nothing to compute.
		return traverser->mapOfVarDefStmtNodes;
	}
	ShPtr<Statement> firstStmt(*funcBodyNode->stmt_begin());

	traverser->performTraversal(firstStmt);

	return traverser->mapOfVarDefStmtNodes;
}

bool NodesOfVarUseCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	ShPtr<ValueData> stmtData(va->getValueData(stmt));

	// Precompute the node for the statement so we do not have to recompute it
	// for every variable that is used in the statement.
	ShPtr<CFG::Node> nodeForStmt(cfg->getNodeForStmt(stmt).first);

	// Iterate through all variables in stmt and if a variable is in a map,
	// this means that we need save node for this VarDefStmt, because variable
	// is used.
	for (auto i = stmtData->dir_all_begin(), e = stmtData-> dir_all_end();
			i != e; ++i) {
		VarVarDefMap::iterator it = mapOfVarVarDef.find(*i);
		if (it != mapOfVarVarDef.end()) {
			(*mapOfVarDefStmtNodes)[it->second].insert(nodeForStmt);
		}
	}
	return true;
}

bool NodesOfVarUseCFGTraversal::getEndRetVal() const {
	return false;
}

bool NodesOfVarUseCFGTraversal::combineRetVals(bool origRetVal, bool newRetVal) const {
	return origRetVal ? newRetVal : false;
}

} // namespace llvmir2hll
} // namespace retdec
