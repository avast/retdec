/**
* @file include/retdec/llvmir2hll/analysis/def_use_analysis.h
* @brief An analysis providing def-use chains.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_DEF_USE_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_DEF_USE_ANALYSIS_H

#include <functional>
#include <map>
#include <set>
#include <vector>

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class CFGBuilder;
class Function;
class Module;
class ValueAnalysis;
class VarUsesVisitor;
class Variable;

/**
* @brief Def-use chains.
*
* See the description of DefUseAnalysis for more info (mainly concerning the
* book that this implementation is based on: [ItC]).
*/
class DefUseChains {
public:
	/// (statement, variable) pair
	using StmtVarPair = std::pair<ShPtr<Statement>, ShPtr<Variable>>;

	/// Set of (statement, variable) pairs.
	using StmtVarPairSet = std::set<StmtVarPair>;

	/// Mapping of a CFG node into a set of (statement, variable) pairs.
	using NodePairMap = std::map<ShPtr<CFG::Node>, StmtVarPairSet>;

	/// A def-use chain (see [ItC]).
	// Implementation note: we have to use std::vector instead of std::map to
	// make the chain deterministic.
	using DefUseChain = std::vector<std::pair<StmtVarPair, StmtSet>>;

public:
	void debugPrint();

public:
	/// Function for which the chains have been computed.
	ShPtr<Function> func;

	/// CFG of @c func.
	ShPtr<CFG> cfg;

	/// A function that returns whether the given variable should be included
	/// in def-use chains.
	std::function<bool (ShPtr<Variable>)> shouldBeIncluded;

	/// Def-use chain for each statement @c s that defines a variable @c x (the
	/// <tt>DU(s, x)</tt> set in [ItC]).
	DefUseChain du;

	/// Mapping of a CFG node @c B into the following set:
	/// @code
	/// {(s, x) | s \notin B uses x and B defines x}
	/// @endcode
	/// (The @c KILL[B] set from Definition 27 in [ItC].)
	NodePairMap kill;

	/// Mapping of a CFG node @c B into the following set:
	/// @code
	/// {(s, x) | s \in B uses x and x is not defined prior to s in B}
	/// @endcode
	/// (The @c GEN[B] set from Definition 27 in [ItC].)
	NodePairMap gen;

	/// Mapping of a CFG node @c B into the following set:
	/// @code
	/// {(s, x) | s uses x and s is reachable from the beginning of B}
	/// @endcode
	/// (The @c IN[B] set from Definition 27 in [ItC].)
	NodePairMap in;

	/// Mapping of a CFG node @c B into the following set:
	/// @code
	/// {(s, x) | s \notin B uses x and s is reachable from the end of B}
	/// @endcode
	/// (The @c OUT[B] set from Definition 27 in [ItC].)
	NodePairMap out;
};

/**
* @brief An analysis providing def-use chains.
*
* The analysis and its implementation is based on the following book:
*
* - [ItC] D. Vermeir: An Introduction to Compilers, 2009
*         (http://tinf2.vub.ac.be/~dvermeir/courses/compilers/compilers.pdf)
*
* For some basic information about def-use chains, see
* http://en.wikipedia.org/wiki/Use-define_chain.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class DefUseAnalysis: private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	~DefUseAnalysis();

	ShPtr<DefUseChains> getDefUseChains(
		ShPtr<Function> func,
		ShPtr<CFG> cfg = nullptr,
		std::function<bool (ShPtr<Variable>)> shouldBeIncluded =
			[](auto) { return true; }
	);

	static ShPtr<DefUseAnalysis> create(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<VarUsesVisitor> vuv = nullptr);

private:
	DefUseAnalysis(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<VarUsesVisitor> vuv = nullptr);

	void computeGenAndKill(ShPtr<DefUseChains> ducs);
	void computeGenAndKillForNode(ShPtr<DefUseChains> ducs,
		ShPtr<CFG::Node> node);
	void computeInAndOut(ShPtr<DefUseChains> ducs);
	bool computeInAndOutForNode(ShPtr<DefUseChains> ducs,
		ShPtr<CFG::Node> node);
	void computeDefUseChains(ShPtr<DefUseChains> ducs);
	void computeDefUseChainForNode(ShPtr<DefUseChains> ducs,
		ShPtr<CFG::Node> node);
	void computeDefUseChainForStmt(ShPtr<DefUseChains> ducs,
		ShPtr<CFG::Node> node, CFG::stmt_iterator varDefStmtIter,
		ShPtr<Variable> defVar);
	ShPtr<Variable> getDefVarInStmt(ShPtr<Statement> stmt);

private:
	/// Module that is being analyzed.
	ShPtr<Module> module;

	/// Analysis of used values.
	ShPtr<ValueAnalysis> va;

	/// Visitor for obtaining uses of variables.
	ShPtr<VarUsesVisitor> vuv;

	/// The used builder of CFGs.
	ShPtr<CFGBuilder> cfgBuilder;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
