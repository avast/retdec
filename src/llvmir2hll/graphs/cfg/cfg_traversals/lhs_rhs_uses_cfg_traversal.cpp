/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/lhs_rhs_uses_cfg_traversal.cpp
* @brief Implementation of LhsRhsUsesCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/lhs_rhs_uses_cfg_traversal.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* See the description and implementation of getUses() for information on the
* parameters.
*/
LhsRhsUsesCFGTraversal::LhsRhsUsesCFGTraversal(ShPtr<Statement> stmt,
	ShPtr<Variable> origLhsVar, const VarSet &origRhsVars, ShPtr<CFG> cfg,
	ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
		CFGTraversal(cfg, true), origStmt(stmt), origLhsVar(origLhsVar),
		origRhsVars(origRhsVars), va(va), cio(cio), uses() {}

/**
* @brief Destructs the traverser.
*/
LhsRhsUsesCFGTraversal::~LhsRhsUsesCFGTraversal() {}

/**
* @brief Returns the uses of left-hand side of @a stmt such that there are no
*        modifications of variables used in @a stmt before them.
*
* @param[in] stmt Statement from which we should start the search.
* @param[in] cfg CFG that should be traversed.
* @param[in] va Analysis of values.
* @param[in] cio The used call info obtainer.
*
* @par Preconditions
*  - @a stmt, @a cfg, @a va, and @a cio are non-null
*  - @a cio has been initialized
*  - @a va is in a valid state
*
* This function returns the empty StmtSet if:
*  - @a stmt is not of the form <tt>a = x</tt> where @c a is a variable
*    and @c x is an expression containing only variables and arithmetical
*    operations
*  - @a stmt is not in @a cfg
*  - the variables used in @a stmt can be used indirectly (by a pointer)
*  - there are no suitable uses
*
* This function leaves @a va in a valid state.
*/
StmtSet LhsRhsUsesCFGTraversal::getUses(ShPtr<Statement> stmt,
	ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION_NON_NULL(cfg);
	PRECONDITION_NON_NULL(va);
	PRECONDITION(cio->isInitialized(), "it is not initialized");
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	if (!isVarDefOrAssignStmt(stmt)) {
		// It is not an assign or a variable-defining statement.
		return StmtSet();
	}

	ShPtr<Variable> lhsVar(cast<Variable>(getLhs(stmt)));
	ShPtr<Expression> rhs(getRhs(stmt));
	if (!lhsVar || !rhs) {
		// It is not of the form `a = x`, where `x` is an expression.
		return StmtSet();
	}

	CFG::StmtInNode stmtNode(cfg->getNodeForStmt(stmt));
	if (!stmtNode.first) {
		// The statement is not in the CFG.
		return StmtSet();
	}

	ShPtr<ValueData> rhsData(va->getValueData(rhs));
	if (rhsData->hasCalls() || rhsData->hasAddressOps() ||
			rhsData->hasDerefs() || rhsData->hasArrayAccesses() ||
			rhsData->hasStructAccesses()) {
		// There are non-arithmetical operations in the right-hand side.
		return StmtSet();
	}

	if (va->mayBePointed(lhsVar)) {
		// The left-hand-side variable may be used indirectly.
		return StmtSet();
	}

	// For every variable in rhs...
	for (auto i = rhsData->dir_read_begin(), e = rhsData->dir_read_end();
			i != e; ++i) {
		if (va->mayBePointed(*i)) {
			// A variable on the right-hand side may be used indirectly.
			return StmtSet();
		}
	}

	ShPtr<LhsRhsUsesCFGTraversal> traverser(new LhsRhsUsesCFGTraversal(
		stmt, lhsVar, rhsData->getDirReadVars(), cfg, va, cio));

	// The traverser returns true if and only if there are some suitable uses.
	// Dot NOT return traverser->uses without checking the return value as
	// it is not cleared when false is returned (speedup).
	traverser->checkedStmts.insert(stmt);
	if (traverser->performTraversalFromSuccessors(stmt)) {
		return traverser->uses;
	}
	return StmtSet();
}

bool LhsRhsUsesCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	ShPtr<ValueData> stmtData(va->getValueData(stmt));

	// origLhsVar <-> a

	// Write to origLhsVar.
	//
	//     a = x;
	//     ...
	//     a = 1;    <-- stmt
	//
	if (stmtData->isDirWritten(origLhsVar)) {
		currRetVal = false;
		stopTraversal = true;
		return false;
	}

	// For every variable used on the right-hand side of the original
	// statement...
	for (const auto &origRhsVar : origRhsVars) {
		// origRhsVar <-> b

		// Write to origRhsVar.
		//
		//     a = b;
		//     ...
		//     b = 1;    <-- stmt
		//     ...
		//
		if (stmtData->isDirWritten(origRhsVar)) {
			// If (1) the current node ends with a return/unreachable statement
			// and (2) there are no uses of `a` after this statement, we may
			// ignore this write.
			//
			//     a = b;
			//     b = 1;    <-- stmt
			//     ...       (no uses of `a`)
			//     return;
			//
			// Otherwise, we have to assume that `a` may be used after this
			// node, so to make this analysis safe, stop it.
			// TODO How to make this restriction less restrictive?

			// Check (1).
			CFG::StmtInNode stmtNode(cfg->getNodeForStmt(stmt));
			if (stmtNode.first->getNumberOfSuccs() != 1 ||
					cfg->getExitNode() != (*stmtNode.first->succ_begin())->getDst()) {
				// The node does not end with an exit, so stop the analysis.
				currRetVal = false;
				stopTraversal = true;
				return false;
			}

			// Check (2).
			auto i = stmtNode.second;
			auto e = stmtNode.first->stmt_end();
			while (i != e) {
				ShPtr<ValueData> currStmtData(va->getValueData(*i));
				if (currStmtData->isDirAccessed(origLhsVar)) {
					// The origLhsVar is used, so stop the analysis.
					currRetVal = false;
					stopTraversal = true;
					return false;
				}
				++i;
			}
		}

		// There cannot be a function call that modifies origRhsVar.
		//
		// int b;
		//
		// void setB() {
		//     b = 1;
		// }
		//
		// void test() {
		//     a = b;
		//     setB();      <-- stmt
		//     return a;
		// }
		const CallVector &callsInStmt(stmtData->getCalls());
		if (!callsInStmt.empty()) {
			// For each call...
			for (const auto & call : callsInStmt) {
				ShPtr<CallInfo> callInfo(cio->getCallInfo(
					call,
					cfg->getCorrespondingFunction())
				);
				if (callInfo->mayBeModified(origRhsVar)) {
					currRetVal = false;
					stopTraversal = true;
					return false;
				}
			}
		}
	}

	// Read of origLhsVar.
	//
	//     a = x;
	//     ...
	//     c = a;     <-- stmt
	//     ...
	//
	if (stmtData->isDirRead(origLhsVar)) {
		uses.insert(stmt);
		return true;
	}

	return true;
}

bool LhsRhsUsesCFGTraversal::getEndRetVal() const {
	return true;
}

bool LhsRhsUsesCFGTraversal::combineRetVals(bool origRetVal, bool newRetVal) const {
	return origRetVal ? newRetVal : false;
}

} // namespace llvmir2hll
} // namespace retdec
