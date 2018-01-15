/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/nodes_of_var_use_cfg_traversal.h
* @brief A CFG traversal that returns a map where key is a VarDefStmt statement
*        and item is the set of nodes where a variable from the VarDefStmt
*        statement is used.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_NODES_OF_VAR_USE_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_NODES_OF_VAR_USE_CFG_TRAVERSAL_H

#include <map>
#include <set>

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"

namespace retdec {
namespace llvmir2hll {

class CFG;
class ValueAnalysis;
class VarDefStmt;

/**
* @brief A CFG traversal that returns all nodes where the variables from
*        VarDefStms are used.
*
* This class is meant to be used in VarDefStmtOptimizer.
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class NodesOfVarUseCFGTraversal final: public CFGTraversal {
public:
	/// Set of cfg nodes.
	using CFGNodeSet = std::set<ShPtr<CFG::Node>>;

	/// Mapping of a VarDefStmt into a Node.
	/// Saves all nodes where variable from it's own definition is used.
	using VarDefStmtNodeMap = std::map<ShPtr<VarDefStmt>, CFGNodeSet>;

public:
	~NodesOfVarUseCFGTraversal();

	static ShPtr<VarDefStmtNodeMap> getNodesOfUseVariable(const VarDefStmtSet
		&setOfVarDefStmt, ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va);

private:
	/// Maping of a variable into a VarDefStmt.
	using VarVarDefMap = std::map<ShPtr<Variable>, ShPtr<VarDefStmt>>;

private:
	NodesOfVarUseCFGTraversal(const VarDefStmtSet &setOfVarDefStmt,
		ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va);

	virtual bool visitStmt(ShPtr<Statement> stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// A result map where key is a VarDefStmt statement and item is a set of
	/// nodes where variable from VarDefStmt statement is used.
	ShPtr<VarDefStmtNodeMap> mapOfVarDefStmtNodes;

	/// Mapping a variable from VarDefStmt to VarDefStmt.
	VarVarDefMap mapOfVarVarDef;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
