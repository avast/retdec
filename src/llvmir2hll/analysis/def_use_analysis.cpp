/**
* @file src/llvmir2hll/analysis/def_use_analysis.cpp
* @brief Implementation of DefUseAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/def_use_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/analysis/var_uses_visitor.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/recursive_cfg_builder.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;
using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

namespace {

/// Set of nodes in a CFG.
using NodeSet = std::set<ShPtr<CFG::Node>>;

/// Order of nodes in a CFG.
using NodeOrder = std::vector<ShPtr<CFG::Node>>;

} // anonymous namespace

/**
* @brief Emits all the live variables info to standard error.
*
* Only for debugging purposes.
*/
void DefUseChains::debugPrint() {
	llvm::errs() << "[DefUseChains] Debug info for function '" << func->getName() << "':\n";
	llvm::errs() << "\n";
	llvm::errs() << "Out, in, gen, and kill sets:\n";
	llvm::errs() << "----------------------------\n";
	for (auto i = cfg->node_begin(), e = cfg->node_end(); i != e; ++i) {
		llvm::errs() << "  " << (*i)->getLabel() << ":\n";
		llvm::errs() << "    kill: \n";
		for (auto j = kill[*i].begin(), f = kill[*i].end(); j != f; ++j) {
			llvm::errs() << "      (" << j->first << ", "
				<< j->second->getName() << ")\n";
		}
		llvm::errs() << "\n    gen: \n";
		for (auto j = gen[*i].begin(), f = gen[*i].end(); j != f; ++j) {
			llvm::errs() << "      (" << j->first << ", "
				<< j->second->getName() << ")\n";
		}
		llvm::errs() << "\n    in: \n";
		for (auto j = in[*i].begin(), f = in[*i].end(); j != f; ++j) {
			llvm::errs() << "      (" << j->first << ", "
				<< j->second->getName() << ")\n";
		}
		llvm::errs() << "\n    out: \n";
		for (auto j = out[*i].begin(), f = out[*i].end(); j != f; ++j) {
			llvm::errs() << "      (" << j->first << ", "
				<< j->second->getName() << ")\n";
		}
		llvm::errs() << "\n\n";
	}
	llvm::errs() << "Def-use chains:\n";
	llvm::errs() << "---------------\n";
	for (auto i = du.begin(), e = du.end(); i != e; ++i) {
		llvm::errs() << "  du[" << i->first.first << ", "
			<< i->first.second->getName() << "] (in "
			<< cfg->getNodeForStmt(i->first.first).first->getLabel() << "):\n";
		for (auto j = i->second.begin(), f = i->second.end(); j != f; ++j) {
			llvm::errs() << "    " << (*j) << " (in "
				<< cfg->getNodeForStmt(*j).first->getLabel() << ")\n";
		}
		llvm::errs() << "\n";
	}
}

/**
* @brief Constructs a new analysis.
*
* See create() for the description of the parameters.
*/
DefUseAnalysis::DefUseAnalysis(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<VarUsesVisitor> vuv):
		module(module), va(va), vuv(vuv),
		cfgBuilder(RecursiveCFGBuilder::create()) {
	// If we don't have a visitor for obtaining uses of variables, create one.
	if (!this->vuv) {
		this->vuv = VarUsesVisitor::create(this->va);
	}
}

/**
* @brief Destructs the analysis.
*/
DefUseAnalysis::~DefUseAnalysis() {}

/**
* @brief Returns def-use chains for the given function.
*
* @param[in] func Function for which the analysis is computed.
* @param[in] cfg Optional CFG for @a func.
* @param[in] shouldBeIncluded A function that returns whether the given
*                             variable should be included in def-use chains.
*
* @par Preconditions
*  - if @a cfg is non-null, it has to be a CFG corresponding to @a func
*/
ShPtr<DefUseChains> DefUseAnalysis::getDefUseChains(
		ShPtr<Function> func, ShPtr<CFG> cfg,
		std::function<bool (ShPtr<Variable>)> shouldBeIncluded) {
	auto ducs = std::make_shared<DefUseChains>();
	ducs->func = func;
	ducs->shouldBeIncluded = shouldBeIncluded;

	// If we don't have a CFG, generate it.
	ducs->cfg = cfg;
	if (!ducs->cfg) {
		ducs->cfg = cfgBuilder->getCFG(func);
	}

	computeGenAndKill(ducs);
	computeInAndOut(ducs);
	computeDefUseChains(ducs);

	return ducs;
}

/**
* @brief Creates a new analysis.
*
* @param[in] module Module for which the analysis is created.
* @param[in] va The used analysis of values.
* @param[in] vuv The used visitor for obtaining uses of variables.
*
* If @a vuv is not provided, a new visitor is created.
*
* @par Preconditions
*  - @a va is in a valid state
*
* All methods of this class leave @a va in a valid state.
*/
ShPtr<DefUseAnalysis> DefUseAnalysis::create(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<VarUsesVisitor> vuv) {
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	return ShPtr<DefUseAnalysis>(new DefUseAnalysis(module, va, vuv));
}

/**
* @brief Computes the @c GEN[B] and @c KILL[B] sets for each CFG node @c B.
*
* This function modifies @a ducs.
*/
void DefUseAnalysis::computeGenAndKill(ShPtr<DefUseChains> ducs) {
	// For each node B...
	for (auto i = ducs->cfg->node_begin(), e = ducs->cfg->node_end();
			i != e; ++i) {
		computeGenAndKillForNode(ducs, *i);
	}
}

/**
* @brief Computes the @c GEN[B] and @c KILL[B] sets for the given CFG node @a
*        node @c B.
*
* This function modifies @a ducs.
*/
void DefUseAnalysis::computeGenAndKillForNode(ShPtr<DefUseChains> ducs,
	ShPtr<CFG::Node> node) {

	// Aliases to speed up the computation.
	auto &gen = ducs->gen[node];
	auto &kill = ducs->kill[node];

	// Initialization.
	gen.clear();
	kill.clear();

	// Defined variables in the node (regularly updated).
	VarSet defVars;

	//
	// Compute GEN[node].
	//

	// For each statement in the node...
	for (auto i = node->stmt_begin(), e = node->stmt_end(); i != e; ++i) {
		// Compute read/written variables in the current statement.
		const auto &stmtData = va->getValueData(*i);

		// Compute GEN[node] for the current statement.
		for (auto j = stmtData->dir_read_begin(), f = stmtData->dir_read_end();
				j != f; ++j) {
			if (!hasItem(defVars, *j) && ducs->shouldBeIncluded(*j)) {
				gen.emplace(*i, *j);
			}
		}

		// Update the set of defined variables that the present statement
		// defines.
		for (auto j = stmtData->dir_written_begin(), f = stmtData->dir_written_end();
				j != f; ++j) {
			if (ducs->shouldBeIncluded(*j)) {
				defVars.insert(*j);
			}
		}
	}

	//
	// Compute KILL[node].
	//

	// For each defined variable in the node...
	for (const auto &defVar : defVars) {
		// Get all statements where the current variable is used.
		const auto &varUses = vuv->getUses(defVar, ducs->func)->dirUses;

		// Insert to KILL[node] such statements from varUses that are not in
		// the node.
		for (const auto &varUse : varUses) {
			// Consider only uses which are "read" uses, not "write" uses.
			const auto &readVarsInVarUse = va->getValueData(varUse)->getDirReadVars();
			if (!hasItem(readVarsInVarUse, defVar)) {
				continue;
			}

			kill.emplace(varUse, defVar);
		}
	}
}

/**
* @brief Computes the @c IN[B] and @c OUT[B] sets for each CFG node @c B.
*
* computeGenAndKill() has to be run before this function. This function modifies
* @a ducs.
*/
void DefUseAnalysis::computeInAndOut(ShPtr<DefUseChains> ducs) {
	// The subsequent implementation is based on Section 6.3.6 in [ItC] (see
	// the class description). The algorithm is the same as in the analysis of
	// live variables (see page 112 in [ItC]).

	// To speedup the execution, we first order the nodes so that when we
	// compute IN and OUT in this order, it will require less iterations than
	// computing these sets in a "random" order. At first, we add just the entry
	// node to the order. Then, we add all its successors to the order. We
	// keep traversing the CFG until we add all of its non-exit nodes. Notice
	// that we have to add the nodes to the front of the order, not to the
	// back (this would greatly lengthen the computation of IN and OUT).
	NodeOrder order;
	order.reserve(ducs->cfg->getNumberOfNodes());
	order.push_back(ducs->cfg->getEntryNode());
	// To check whether a node has already been added to the order, we use a
	// set. The reason is that a vector searches in O(n) while a set searches
	// in O(log(n)).
	// Note: Using unordered_set instead of a set doesn't speed up the
	//       computation, so we use just set.
	NodeSet orderSet(order.begin(), order.end());
	// We will keep iterating until we add all non-exit nodes to the order.
	do {
		// For every node in the order...
		// Note: We have to iterate using indices because in the nested loop,
		//       we modify order. If we used a range-based for loop, we may
		//       ended up with invalid iterators. Another solution may be to
		//       iterate over a copy of order, but this would be needlessly
		//       inefficient (the computation of IN and OUT has to be as fast
		//       as possible).
		for (std::size_t i = 0, e = order.size(); i < e; ++i) {
			const auto &node = order[i];
			// For every predecessor of this node...
			for (auto j = node->succ_begin(), f = node->succ_end(); j != f; ++j) {
				const auto &pred = (*j)->getDst();
				// Do not include the node if it is either already present in
				// the order or it is the exit node.
				if (!hasItem(orderSet, pred) && pred != ducs->cfg->getExitNode()) {
					order.push_back(pred);
					orderSet.insert(pred);
				}
			}
		}
	// The -1 below is for the exit node, which we do not add into the order.
	} while (order.size() < ducs->cfg->getNumberOfNodes() - 1);

	//
	// Initialize the analysis.
	//
	ducs->in.clear();
	ducs->out.clear();
	// Normally, we would have to set IN[B] = \emptyset for each node B.
	// However, since ducs->in[B] gets initialized to an empty set
	// automatically upon first access, we don't have to do it.

	//
	// Perform the iterative algorithm to obtain IN and OUT for each node.
	//
	bool setChanged;
	do {
		setChanged = false;
		// For each node in the computer order...
		// Note: To use the order computed above, we have to traverse the
		// vector in reverse, i.e. from its end towards its beginning.
		for (auto i = order.rbegin(), e = order.rend(); i != e; ++i) {
			setChanged |= computeInAndOutForNode(ducs, *i);
		}
	} while (setChanged);
}

/**
* @brief Computes the @c IN[node] and @c OUT[node] set for the given node @a node.
*
* @return @c true if either of these two sets has been changed, @c false
*         otherwise.
*
* This function modifies @a ducs.
*
* @par Preconditions
*  - @a node is not the exit node of a CFG
*/
bool DefUseAnalysis::computeInAndOutForNode(ShPtr<DefUseChains> ducs,
		ShPtr<CFG::Node> node) {
	// See the implementation of computeInAndOut() for the description of the
	// following algorithm.

	// OUT[B] = \bigcup_{S \in succ(B)} IN[S]
	DefUseChains::StmtVarPairSet newOut;
	for (auto i = node->succ_begin(), e = node->succ_end(); i != e; ++i) {
		addToSet(ducs->in[(*i)->getDst()], newOut);
	}

	// Check whether OUT[B] has been changed.
	auto &out = ducs->out[node];
	auto &in = ducs->in[node];
	if (out.size() != newOut.size()) {
		// We no longer need newOut, so we can make a move instead of a copy.
		out = std::move(newOut);
	} else if (!in.empty()) {
		// OUT[B] hasn't been changed and IN[B] has already been
		// computed, so we don't have to recompute IN[B] because it
		// would remain unchanged.
		return false;
	}

	// IN[B] = GEN[B] \cup (OUT[B] - KILL[B])
	// The following code is faster than
	// in = setUnion(ducs->gen[node], setDifference(out, ducs->kill[node]));
	in = ducs->gen[node];
	auto &kill = ducs->kill[node];
	for (auto &item : out) {
		if (!hasItem(kill, item)) {
			in.insert(item);
		}
	}

	// At this moment, OUT may be unchanged, but IN has been computed for the
	// first time. Therefore, we have to check that at least one item has been
	// added to IN.
	return !in.empty();
}

/**
* @brief Computes the <tt>DU[s, x]</tt> set for each statement @c s that
*        defines a variable @c x.
*
* computeGenAndKill() and computeInAndOut() have to be run before this
* function. This function modifies @a ducs.
*/
void DefUseAnalysis::computeDefUseChains(ShPtr<DefUseChains> ducs) {
	ducs->du.clear();

	// For each node...
	for (auto i = ducs->cfg->node_begin(), e = ducs->cfg->node_end();
			i != e; ++i) {
		computeDefUseChainForNode(ducs, *i);
	}
}

/**
* @brief Computes the <tt>DU[s, x]</tt> set for each statement @c s in @a
*        node that defines a variable @c x.
*
* This function should be run only from computeDefUseChains(), and it modifies
* @a ducs.
*/
void DefUseAnalysis::computeDefUseChainForNode(ShPtr<DefUseChains> ducs,
		ShPtr<CFG::Node> node) {
	// For each statement in the node...
	for (auto i = node->stmt_begin(), e = node->stmt_end(); i != e; ++i) {
		if (const auto &defVar = getDefVarInStmt(*i)) {
			computeDefUseChainForStmt(ducs, node, i, defVar);
		}
	}
}

/**
* @brief Computes the <tt>DU[*varDefStmtIter, defVar]</tt> set.
*
* @param[in] ducs Information about def-use chains.
* @param[in] node Currently processed basic block.
* @param[in] varDefStmtIter Iterator to the current statement in @a node.
* @param[in] defVar Variable that is defined in @c *varDefStmtIter.
*
* This function should be run only from computeDefUseChainForNode(), and it
* modifies @a ducs.
*/
void DefUseAnalysis::computeDefUseChainForStmt(ShPtr<DefUseChains> ducs,
		ShPtr<CFG::Node> node, CFG::stmt_iterator varDefStmtIter,
		ShPtr<Variable> defVar) {
	// For brevity, create an alias for the def-use chain that is being computed.
	ducs->du.emplace_back(std::make_pair(*varDefStmtIter, defVar), StmtSet());
	auto &du = ducs->du.back().second;

	// The following implementation is based on the computation of DU(d, x) on
	// page 112 in [ItC].
	for (auto i = ++varDefStmtIter, e = node->stmt_end(); i != e; ++i) {
		// If the current statement is a definition of defVar, we have to stop
		// the computation.
		if (getDefVarInStmt(*i) == defVar) {
			// Check whether defVar is used in the right-hand side of the
			// current statement. If so, then we have to include the statement
			// to the def-use chain because defVar is used there.
			// Note: In [ItC], this is not done. However, the algorithm doesn't
			//       work correctly if we don't add the current statement into
			//       the def-use chain in such a case.
			const auto &readVars = va->getValueData(*i)->getDirReadVars();
			if (hasItem(readVars, defVar)) {
				du.insert(*i);
			}
			return;
		}

		// Check whether the statement uses defVar (if not, then skip it).
		const auto &readVars = va->getValueData(*i)->getDirReadVars();
		if (!hasItem(readVars, defVar)) {
			continue;
		}

		du.insert(*i);
	}

	// We have traversed all statements in the node without stopping the
	// computation, so add also the relevant contents of OUT[node] to the
	// def-use chain.
	for (auto &item : ducs->out[node]) {
		if (item.second == defVar) {
			du.insert(item.first);
		}
	}
}

/**
* @brief Returns the variable that is defined in @a stmt (if any).
*
* "Defined" means that it is assigned a value (it doesn't necessary mean that
* @a stmt is a VarDefStmt).
*
* If @a stmt doesn't define any variable, this function returns the null
* pointer.
*/
ShPtr<Variable> DefUseAnalysis::getDefVarInStmt(ShPtr<Statement> stmt) {
	const auto &writtenVars = va->getValueData(stmt)->getDirWrittenVars();
	return writtenVars.empty() ? ShPtr<Variable>() : *writtenVars.begin();
}

} // namespace llvmir2hll
} // namespace retdec
