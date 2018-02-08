/**
* @file src/llvmir2hll/optimizer/optimizers/copy_propagation_optimizer.cpp
* @brief Implementation of CopyPropagationOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstddef>

#include "retdec/llvmir2hll/analysis/def_use_analysis.h"
#include "retdec/llvmir2hll/analysis/use_def_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/analysis/var_uses_visitor.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/no_var_def_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/var_def_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/copy_propagation_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

namespace {

/// Maximal length of a statement that can appear after a copy propagation is
/// done. If the resulting statement is greater that this number, we won't
/// perform the propagation.
const unsigned MAX_STMT_LENGTH = 120;

/**
* @brief Returns an ordered version of the given statement set.
*/
auto ordered(const StmtSet &stmts) {
	StmtVector v(stmts.begin(), stmts.end());
	std::sort(v.begin(), v.end(), [](const auto &s1, const auto &s2) {
		// We have to use getTextRepr() because there is no other way of
		// sorting the statements.
		return s1->getTextRepr() < s2->getTextRepr();
	});
	return v;
}

/**
* @brief Returns text representations of statements in the given set.
*/
auto textReprs(const StmtSet &stmts) {
	StringSet reprs;
	for (auto &stmt : stmts) {
		reprs.insert(stmt->getTextRepr());
	}
	return reprs;
}

/**
* @brief Compares the given two statements from in DU chains.
*/
int compareStmtsInDUChains(const ShPtr<Statement> &s1, const ShPtr<Statement> &s2) {
	if (!s1 && !s2) {
		return 0;
	} else if (s1 && !s2) {
		return 1;
	} else if (!s1 && s2) {
		return -1;
	}

	const auto &s1Repr = s1->getTextRepr();
	const auto &s2Repr = s2->getTextRepr();
	return s1Repr.compare(s2Repr);
}

/**
* @brief Returns an ordered version of the given DU chain.
*/
auto ordered(const DefUseChains::DefUseChain &du) {
	std::vector<std::pair<DefUseChains::StmtVarPair, StmtSet>> v(du.begin(), du.end());
	std::sort(v.begin(), v.end(), [](const auto &p1, const auto &p2) {
		// Begin by checking the sizes of the uses because it's faster than
		// checking the statements and variables.
		auto uses1Size = p1.second.size();
		auto uses2Size = p2.second.size();
		if (uses1Size != uses2Size) {
			return uses1Size < uses2Size;
		}

		// The uses sets have the same size, so continue to variables.
		const auto &v1Name = p1.first.second->getName();
		const auto &v2Name = p2.first.second->getName();
		auto cmpResult = v1Name.compare(v2Name);
		if (cmpResult != 0) {
			return cmpResult < 0;
		}

		// Check the statements. We have to use getTextRepr() because
		// there is no other way of comparing the statements.
		auto s1 = p1.first.first;
		auto s2 = p2.first.first;
		cmpResult = compareStmtsInDUChains(s1, s2);
		if (cmpResult != 0) {
			return cmpResult < 0;
		}

		// Uses sizes, variables, and statements are equal, so we have to check
		// text representations of uses. This is time-consuming, so we do this
		// here, after previous checks were inconclusive.
		cmpResult = textReprs(p1.second) < textReprs(p2.second);
		if (cmpResult != 0) {
			return cmpResult < 0;
		}

		// Everything so far was inconclusive, so as a last resort, compare
		// parents, successors, and predecessors. This is also very time
		// consuming, so we do this as the very last check.
		//
		// Parent:
		cmpResult = compareStmtsInDUChains(s1->getParent(), s2->getParent());
		if (cmpResult != 0) {
			return cmpResult < 0;
		}
		// Successor:
		cmpResult = compareStmtsInDUChains(s1->getSuccessor(), s2->getSuccessor());
		if (cmpResult != 0) {
			return cmpResult < 0;
		}
		// Predecessors:
		while (true) {
			const auto &s1PredSize = s1->getNumberOfPredecessors();
			const auto &s2PredSize = s2->getNumberOfPredecessors();
			if (s1PredSize != s2PredSize) {
				return s1PredSize < s2PredSize;
			} else if (s1PredSize > 0 && s2PredSize > 0) {
				const auto &s1Pred = *s1->predecessor_begin();
				const auto &s2Pred = *s2->predecessor_begin();
				cmpResult = compareStmtsInDUChains(s1Pred, s2Pred);
				if (cmpResult != 0) {
					return cmpResult < 0;
				}
				s1 = s1Pred;
				s2 = s2Pred;
			} else {
				break;
			}
		}

		// The DU chains appear to be equal.
		return false;
	});
	return v;
}

} // anonymous namespace

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va Analysis of values.
* @param[in] cio Obtainer of information about function calls.
*
* @par Preconditions
*  - @a module, @a va, and @a cio are non-null
*/
CopyPropagationOptimizer::CopyPropagationOptimizer(ShPtr<Module> module,
	ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
		FuncOptimizer(module), va(va), cio(cio), vuv(), dua(), uda(),
		ducs(), udcs(), globalVars(module->getGlobalVars()),
		toEntirelyRemoveStmts(), toRemoveStmtsPreserveCalls(), modifiedStmts(),
		codeChanged(false) {
			PRECONDITION_NON_NULL(module);
			PRECONDITION_NON_NULL(va);
			PRECONDITION_NON_NULL(cio);
	}

/**
* @brief Destructs the optimizer.
*/
CopyPropagationOptimizer::~CopyPropagationOptimizer() {}

void CopyPropagationOptimizer::doOptimization() {
	// Initialization.
	// We clear the cache of va even if it is in a valid state (this
	// surprisingly speeds up the optimization).
	va->clearCache();
	va->initAliasAnalysis(module);
	cio->init(CGBuilder::getCG(module), va);
	vuv = VarUsesVisitor::create(va, true, module);
	dua = DefUseAnalysis::create(module, va, vuv);
	uda = UseDefAnalysis::create(module);

	FuncOptimizer::doOptimization();
}

void CopyPropagationOptimizer::runOnFunction(ShPtr<Function> func) {
	// Keep optimizing until there are no changes.
	do {
		ducs = dua->getDefUseChains(
			func,
			cio->getCFGForFunc(func),
			[this](auto var) {
				return this->shouldBeIncludedInDefUseChains(var);
			}
		);
		udcs = uda->getUseDefChains(func, ducs);
		codeChanged = false;
		performOptimization();
	} while (codeChanged);
}

/**
* @brief Performs the copy propagation optimization.
*
* If this function changes the code, @c codeChanged is set to @c true.
*/
void CopyPropagationOptimizer::performOptimization() {
	toRemoveStmtsPreserveCalls.clear();
	toEntirelyRemoveStmts.clear();
	modifiedStmts.clear();

	// For each def-use chain...
	// We have to iterate over an ordered DU chain to make the optimization
	// deterministic.
	for (const auto &du : ordered(ducs->du)) {
		// Currently, the optimizer is unable to optimize cases when there is
		// more than one use. If this is the case, skip the chain to make the
		// optimization faster.
		const auto &uses = du.second;
		if (uses.size() > 1) {
			continue;
		}

		const auto &stmt = du.first.first;

		// We can optimize only VarDefStmts and AssignStmts where their
		// left-hand side is a variable (i.e. not a pointer/array/structure
		// access).
		const auto &stmtLhsVar = du.first.second;
		if (!isVarDefOrAssignStmt(stmt) || getLhs(stmt) != stmtLhsVar) {
			continue;
		}

		// Do not optimize the statement if it or any of its uses have been
		// already modified.
		if (stmtOrUseHasBeenModified(stmt, uses)) {
			continue;
		}

		// Depending on the number of uses, call an appropriate handler.
		if (uses.empty()) {
			handleCaseEmptyUses(stmt, stmtLhsVar);
		} else if (uses.size() == 1) {
			handleCaseSingleUse(stmt, stmtLhsVar, *uses.begin());
		} else {
			handleCaseMoreThanOneUse(stmt, stmtLhsVar, uses);
		}
	}

	// Remove statements that are to be removed and update the CFG.
	// We have to iterate over ordered statements to make the optimization
	// deterministic.
	for (const auto &stmt : ordered(toRemoveStmtsPreserveCalls)) {
		// Since there may be function calls in the statement, we have to
		// preserve them. Therefore, we store the result of
		// removeVarDefOrAssignStatement() and use it when updating the CFG.
		const auto &newStmts = removeVarDefOrAssignStatement(stmt, ducs->func);
		ducs->cfg->replaceStmt(stmt, newStmts);
	}
	for (const auto &stmt : ordered(toEntirelyRemoveStmts)) {
		Statement::removeStatementButKeepDebugComment(stmt);
		ducs->cfg->removeStmt(stmt);
	}
}

/**
* @brief Returns @c true if @a stmt or any its uses in @a uses has been
*        modified, @c false otherwise.
*/
bool CopyPropagationOptimizer::stmtOrUseHasBeenModified(ShPtr<Statement> stmt,
		const StmtSet &uses) const {
	if (hasItem(modifiedStmts, stmt)) {
		return true;
	}

	// For each use...
	for (const auto &use : uses) {
		if (hasItem(modifiedStmts, use)) {
			return true;
		}
	}

	return false;
}

/**
* @brief Handles the situation from performOptimization() when there are no
*        uses of a variable after its definition before a subsequent
*        definition.
*
* @param[in] stmt Definition of @a stmtLhsVar.
* @param[in] stmtLhsVar Variable defined in @a stmt.
*
* If this function changes the code, @c codeChanged is set to @c true.
*
* @par Preconditions
*  - there are no uses of @a stmtLhsVar after its definition in @a stmt before a
*    subsequent definition
*/
void CopyPropagationOptimizer::handleCaseEmptyUses(ShPtr<Statement> stmt,
		ShPtr<Variable> stmtLhsVar) {
	// Do not optimize variables that may be pointed to (to preserve
	// correctness).
	if (va->mayBePointed(stmtLhsVar)) {
		return;
	}

	// Do not eliminate variable-defining statements whose variable has some
	// uses (it may be needed in some HLL writers, like CHLLWriter).
	// For example,
	//
	//     int a = 0;   // `a` here doesn't have a read use
	//     a = rand();
	//
	// cannot be optimized to
	//
	//     a = rand();
	//
	// Note that this cannot be checked by using just DU chains since their
	// next "use" may actually be a write into the variable, like in the
	// example above.
	if (isa<VarDefStmt>(stmt) && vuv->isUsed(stmtLhsVar, ducs->func, true)) {
		// What we can do is that if the variable-defining statement has a
		// non-empty, constant initializer, we may remove this initializer. For
		// example, the code above can be optimized to
		//
		//     int a;       // the initializer has been removed
		//     a = rand();
		//
		const auto &stmtData = va->getValueData(stmt);
		const auto &varDefStmt = cast<VarDefStmt>(stmt);
		if (varDefStmt->hasInitializer() && !stmtData->hasCalls()) {
			varDefStmt->removeInitializer();
			modifiedStmts.insert(stmt);
			va->removeFromCache(stmt);
			vuv->stmtHasBeenChanged(stmt, ducs->func);
			codeChanged = true;
		}
		return;
	}

	// Do not optimize variables that have assigned a name from debug
	// information (we want to keep such variables).
	if (module->hasAssignedDebugName(stmtLhsVar)) {
		return;
	}

	// Do not optimize external variables (used in a volatile load/store).
	if (stmtLhsVar->isExternal()) {
		return;
	}

	// Do not optimize global variables (we consider just local variables in
	// this optimization; global variables are too hard for it).
	if (hasItem(globalVars, stmtLhsVar)) {
		return;
	}

	// Eliminate the statement.
	toRemoveStmtsPreserveCalls.insert(stmt);
	modifiedStmts.insert(stmt);
	va->removeFromCache(stmt);
	vuv->stmtHasBeenRemoved(stmt, ducs->func);
	codeChanged = true;
}

/**
* @brief Handles the situation from performOptimization() when there is a
*        single use of a variable after its definition before a subsequent
*        definition.
*
* @param[in] stmt Definition of @a stmtLhsVar.
* @param[in] stmtLhsVar Variable defined in @a stmt.
* @param[in] use Use of @a stmtLhsVar.
*
* If this function changes the code, @c codeChanged is set to @c true.
*
* @par Preconditions
*  - there is a single use of @a stmtLhsVar after its definition in @a stmt
*    before a subsequent definition
*/
void CopyPropagationOptimizer::handleCaseSingleUse(ShPtr<Statement> stmt,
		ShPtr<Variable> stmtLhsVar, ShPtr<Statement> use) {
	// There has to be a right-hand side.
	const auto &stmtRhs = getRhs(stmt);
	if (!stmtRhs) {
		return;
	}

	// Do not include global variables (we consider just local variables in
	// this optimization; global variables are too hard for it).
	if (hasItem(globalVars, stmtLhsVar)) {
		return;
	}

	// Do not include variables that have assigned a name from debug
	// information (we want to keep such variables).
	if (module->hasAssignedDebugName(stmtLhsVar)) {
		return;
	}

	// Do not optimize external variables (used in a volatile load/store).
	if (stmtLhsVar->isExternal()) {
		return;
	}

	// Do not include variables that may be pointed to (to preserve
	// correctness).
	if (va->mayBePointed(stmtLhsVar)) {
		return;
	}

	// The right-hand side cannot be a constant string/array/structure;
	// otherwise, the following situation may occur:
	//
	//    x = {'0': 0, '1': 0, '2': {'0': 0.000000e+00}}
	//    x['0'] = 4
	//
	// is optimized to
	//
	//    {'0': 0, '1': 0, '2': {'0': 0.000000e+00}}['0'] = 4
	//
	if (isa<ConstString>(stmtRhs) || isa<ConstArray>(stmtRhs) || isa<ConstStruct>(stmtRhs)) {
		return;
	}

	// Check whether the statement contains function calls. For example, the
	// following code
	//
	//     a = func(1, 2)
	//     func(3, 4)
	//     b = a
	//
	// cannot be optimized to
	//
	//     func(3, 4)
	//     b = func(1, 2)
	//
	const auto &stmtData = va->getValueData(stmt);
	const auto &callsInStmt = stmtData->getCalls();
	if (!callsInStmt.empty()) {
		// There are some function calls.

		// For simplicity, we currently consider only the situation where the
		// use is the next statement.
		// TODO Implement support for situations where there are some
		//      statements between stmt and use.
		const auto &stmtSucc = stmt->getSuccessor();
		if (stmtSucc != use) {
			return;
		}

		// stmtLhsVar has to be used precisely once in the next statement.
		// Otherwise, by performing the copy propagation, we may end up with an
		// invalid code. For example,
		//
		//     a = func()
		//     return a + a
		//
		// cannot be safely optimized to
		//
		//    return func() + func()
		//
		const auto &stmtSuccData = va->getValueData(stmtSucc);
		if (stmtSuccData->getDirNumOfUses(stmtLhsVar) != 1) {
			return;
		}

		// There cannot be other function calls in the next statement.
		// TODO Can this restriction be relaxed a bit?
		if (stmtSuccData->hasCalls()) {
			return;
		}

		// Check that the call in stmt does not modify variables that are read
		// in the next statement.
		// Since there is only a single call in callsInStmt, it suffices to
		// use front() (we don't have to iterate over the collection).
		const auto &callInfo = cio->getCallInfo(callsInStmt.front(), ducs->func);
		for (auto i = stmtSuccData->dir_read_begin(), e = stmtSuccData->dir_read_end();
				i != e ; ++i) {
			if (callInfo->mayBeModified(*i)) {
				return;
			}
		}
	}

	// How many definitions of the use are there?
	const auto &lhsUseDefs = udcs->ud[UseDefChains::VarStmtPair(stmtLhsVar, use)];
	if (lhsUseDefs.size() == 1) {
		// There is a single definition.

		// Check that no variable on the right-hand side is modified prior the
		// use of stmtLhsVar. For example, the following code
		//
		//     a = b
		//     b = 5
		//     return a
		//
		// cannot be optimized to
		//
		//     b = 5
		//     return 5
		//
		const auto &readVarsInStmt = stmtData->getDirReadVars();
		if (VarDefCFGTraversal::isVarDefBetweenStmts(readVarsInStmt, stmt, use,
				ducs->cfg, va)) {
			return;
		}
	} else {
		// There is more than one definition of this use, so we need to check
		// several things.

		// (a) All the definitions are identical (equal).
		ShPtr<Statement> lastDef;
		for (const auto &def : lhsUseDefs) {
			if (lastDef && !lastDef->isEqualTo(def)) {
				// They're not identical.
				return;
			}
			lastDef = def;
		}

		// (b) They are both assign/variable-defining statements.
		// Note that since they are all identical by (a), we need to check just
		// lastDef.
		if (!isa<AssignStmt>(lastDef) && !isa<VarDefStmt>(lastDef)) {
			return;
		}

		// (c) They do not contain function calls.
		if (va->getValueData(lastDef)->hasCalls()) {
			return;
		}

		// (d) Variables used in their definition are not changed after these
		// definitions (except the node in which the `use` statement is). Also,
		// there are no dereferences or function calls.
		//
		// For example, consider the following piece of code:
		//
		//     result = lemon
		//     # (i)
		//     while plum < 10:
		//         # ...
		//         result = lemon
		//         # (ii)
		//     # (iii)
		//     return result
		//
		// Here, we need to make sure that `lemon` is not changed in (i) and
		// (ii), and (i) and (ii) do not contain function calls or dereferences
		// (the reason is that they may changed the value of lemon, if it is a
		// global variable). Note that (iii) can contain any statements.
		const auto &readVarsInLastDef = va->getValueData(lastDef)->getDirReadVars();
		if (!NoVarDefCFGTraversal::noVarIsDefinedBetweenStmts(use, lhsUseDefs,
				readVarsInLastDef, ducs->cfg, va)) {
			return;
		}
	}

	// Do not copy propagate NULL pointers to dereferences on the left-hand
	// sides of assign statements. That is, do not optimize
	//
	//    int *p
	//    p = NULL;
	//    *p = 1;
	//
	// to
	//
	//    *NULL = 1;
	if (isa<ConstNullPointer>(skipCasts(stmtRhs))) {
		if (const auto &useAssignStmt = cast<AssignStmt>(use)) {
			if (const auto&useLhsDeref = cast<DerefOpExpr>(
					skipCasts(useAssignStmt->getLhs()))) {
				if (skipCasts(useLhsDeref->getOperand()) == stmtLhsVar) {
					return;
				}
			}
		}
	}

	// If the variable is used more than once in the use, do not optimize it.
	// Otherwise, the resulting statement might contain stmtRhs several times,
	// which might mess up subsequent optimizations or analyses.
	// TODO To allow this, we would need to clone stmtRhs before every
	//      replacement.
	auto numOfUses = va->getValueData(use)->getDirNumOfUses(stmtLhsVar);
	if (numOfUses > 1) {
		return;
	}

	// Perform the propagation only if at least one of the following
	// readability-related conditions is satisfied:
	//
	//   (1) The right-hand side of the statement is a variable or a constant
	//       (possibly after removing casts). This is useful to allow because
	//       we will have much less copies.
	//
	//   (2) The resulting statement is no longer than MAX_STMT_LENGTH
	//       characters. This ensures that we won't introduce huge statements.
	//
	auto stmtLhsVarLen = stmtLhsVar->getTextRepr().size();
	auto stmtRhsLen = stmtRhs->getTextRepr().size();
	auto useLen = use->getTextRepr().size();
	auto resStmtLen = useLen - numOfUses*stmtLhsVarLen + numOfUses*stmtRhsLen;
	const auto &stmtRhsNoCasts = skipCasts(stmtRhs);
	if (!isa<Variable>(stmtRhsNoCasts) && !isa<Constant>(stmtRhsNoCasts) &&
			resStmtLen > MAX_STMT_LENGTH) {
		return;
	}

	// Perform the replacement.
	replaceVarWithExprInStmt(stmtLhsVar, stmtRhs, use);
	modifiedStmts.insert(stmt);
	modifiedStmts.insert(use);
	va->removeFromCache(use);
	vuv->stmtHasBeenChanged(use, ducs->func);
	if (const auto &varDefStmt = cast<VarDefStmt>(stmt)) {
		// We remove just the initializer to make sure that when there are
		// other uses of the variable, its definition remains present. If there
		// are no other uses, this definition will be removed in
		// handleCaseEmptyUses().
		varDefStmt->removeInitializer();
		va->removeFromCache(stmt);
		vuv->stmtHasBeenChanged(stmt, ducs->func);
	} else {
		toEntirelyRemoveStmts.insert(stmt);
		vuv->stmtHasBeenRemoved(stmt, ducs->func);
	}
	codeChanged = true;
}

/**
* @brief Handles the situation from performOptimization() when there is more
*        than one use of a variable after its definition before a subsequent
*        definition.
*
* @param[in] stmt Definition of @a stmtLhsVar.
* @param[in] stmtLhsVar Variable defined in @a stmt.
* @param[in] uses Uses of @a stmtLhsVar.
*
* If this function changes the code, @c codeChanged is set to @c true.
*
* @par Preconditions
*  - there is more than one use of @a stmtLhsVar after it is defined in @a stmt
*/
void CopyPropagationOptimizer::handleCaseMoreThanOneUse(ShPtr<Statement> stmt,
		ShPtr<Variable> stmtLhsVar, const StmtSet &uses) {
	// TODO How to handle this situation?
}

/**
* @brief Should the given variable be included in def-use chains?
*/
bool CopyPropagationOptimizer::shouldBeIncludedInDefUseChains(
		ShPtr<Variable> var) {
	// Do not include variables that may be pointed to (to preserve
	// correctness).
	if (va->mayBePointed(var)) {
		return false;
	}

	// Do not include global variables (we consider just local variables in
	// this optimization; global variables are too hard for it).
	if (hasItem(globalVars, var)) {
		return false;
	}

	// Do not include variables that have assigned a name from debug
	// information (we want to keep such variables).
	if (module->hasAssignedDebugName(var)) {
		return false;
	}

	// Do not optimize external variables (used in a volatile load/store).
	if (var->isExternal()) {
		return false;
	}

	return true;
}

} // namespace llvmir2hll
} // namespace retdec
