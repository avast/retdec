/**
* @file include/retdec/llvmir2hll/analysis/use_def_analysis.h
* @brief An analysis providing use-def chains.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_USE_DEF_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_USE_DEF_ANALYSIS_H

#include <map>
#include <set>

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Function;
class Module;
class Variable;
class DefUseChains;

/**
* @brief Use-def chains.
*
* See the description of UseDefAnalysis for more info.
*/
class UseDefChains {
public:
	/// (variable, statement) pair
	using VarStmtPair = std::pair<ShPtr<Variable>, ShPtr<Statement>>;

	/// Set of (variable, statement) pairs.
	using StmtVarPairSet = std::set<VarStmtPair>;

	/// Mapping of a pair (variable, statement) to a set of statements (a
	/// use-def chain).
	using UseDefChain = std::map<VarStmtPair, StmtSet>;

public:
	void debugPrint();

public:
	/// Function for which the chains have been computed.
	ShPtr<Function> func;

	/// CFG of @c func.
	ShPtr<CFG> cfg;

	/// Use-def chain for each variable @c x that is used in a statement @c s:
	/// @code
	/// UD[x, s] = {d | d is a reachable definition of x in s}.
	/// @endcode
	UseDefChain ud;
};

/**
* @brief An analysis providing use-def chains.
*
* For some basic information about use-def chains, see
* http://en.wikipedia.org/wiki/Use-define_chain.
*
* Use-def chains are computed from def-use chains.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class UseDefAnalysis: private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	~UseDefAnalysis();

	ShPtr<UseDefChains> getUseDefChains(ShPtr<Function> func,
		ShPtr<DefUseChains> ducs);

	static ShPtr<UseDefAnalysis> create(ShPtr<Module> module);

private:
	explicit UseDefAnalysis(ShPtr<Module> module);

	static void computeUseDefChains(ShPtr<UseDefChains> udcs,
		ShPtr<DefUseChains> ducs);

private:
	/// Module that is being analyzed.
	ShPtr<Module> module;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
