/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/var_def_stmt_optimizer.h
* @brief Optimizes VarDefStmt to the closest place of it's variable use.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_VAR_DEF_STMT_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_VAR_DEF_STMT_OPTIMIZER_H

#include <cstddef>
#include <map>
#include <set>
#include <vector>

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class Statement;
class UForLoopStmt;
class ValueAnalysis;

/**
* @brief Optimizes VarDefStmt to closest place of it's variable use.
*
* For example, the following code
* @code
* int a;
* a = b + c;
* @endcode
* can be optimized into
* @code
* int a = b + c;
* @endcode
* and
* @code
* int a;
* int b;
* int c;
* if (b > 5) {
*     printf("...");
* }
* while (true) {
*     a = b + c;
* }
* @endcode
* can be optimized into
* @code
* int b;
* if (b > 5) {
*     printf("...");
* }
* while (true) {
*     int c;
*     int a = b + c;
* }
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class VarDefStmtOptimizer final: public FuncOptimizer {
public:
	VarDefStmtOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va);

	virtual ~VarDefStmtOptimizer() override;

	virtual std::string getId() const override { return "VarDefStmt"; }

private:
	/// Enumeration for type of optimizations.
	enum class OptType {
		A, ///< assign optimize
		P  ///< prepend optimize
	};

	/// Structure that saves statement to optimize and type of optimization.
	struct StmtToOptimize {
		ShPtr<Statement> stmt;
		OptType optType;
	};

	/// Structure that saves basic information about next nesting level block.
	struct NextLvlStmts {
		ShPtr<Statement> stmt; ///< parent statement of block
		std::size_t order; ///< order of parent statement in it's block
		VarSet vars; ///< variables that are visible from this block
	};

	/// Structure that saves statement of first use of some variable. Also saves
	/// level of nesting.
	struct FirstUse {
		ShPtr<Statement> stmt;
		std::size_t level;
	};

	/// Vector of VarDefStmt.
	using VarDefStmtVec = std::vector<ShPtr<VarDefStmt>>;

	/// Mapping of a Variable into a VarDefStmt.
	using VarVarDefMap = std::map<ShPtr<Variable>, ShPtr<VarDefStmt>>;

	/// Mapping of a Variable into a StmtToOptimize.
	using VarStmtToOptimizeMap = std::map<ShPtr<Variable>, StmtToOptimize>;

	/// Mapping of a Variable into a FirstUse.
	using VarFirstUseMap = std::map<ShPtr<Variable>, FirstUse >;

	/// Mapping of a level of nesting into a count of usage variable.
	using LevelCountMap = std::map<std::size_t, std::size_t>;

	/// Mapping of a Variable into a LevelCountMap.
	using VarLevelCountMap = std::map<ShPtr<Variable>, LevelCountMap>;

	/// Vector of NextLvlStmts.
	using VecNextLvlStmts = std::vector<NextLvlStmts>;

	/// Mapping of a level of nesting into a vector of NextLvlStmts.
	using IntNextLvlStmtsMap = std::map<std::size_t, VecNextLvlStmts>;

private:
	virtual void doOptimization() override;

	void analyseVariablesInStmt(ShPtr<Statement> stmt, VarSet &thisLvlVars);
	void clearAllRecords();
	ShPtr<Statement> findCorrectStatement(ShPtr<Variable> var, std::size_t level);
	void findStmtsToOptimize();
	ShPtr<Statement> findStmtToPrepend(ShPtr<Variable> var, std::size_t level) const;
	void getVarsFromVarDefStmts(const VarDefStmtSet &noInitVarDefStmts);
	void goToNextBlockAndAppendVisibleVars(ShPtr<Statement> stmt,
		ShPtr<Statement> parent, std::size_t order, VarSet &vars);
	bool isAssignStmtWithVarOnLhs(ShPtr<Statement> stmt,
		ShPtr<Variable> var) const;
	VarSet oneBlockTraversal(ShPtr<Statement> stmt, ShPtr<Statement> parent,
		std::size_t order);
	void optimizeAssignStmts(StmtSet &toRemoveStmts) const;
	void optimizeVarDefStmts() const;
	void optimizeWithPrepend(StmtSet &toRemoveStmts) const;
	OptType prependOrAssign(ShPtr<Statement> stmt, ShPtr<Variable> var) const;
	void removeStructAndArrayVarDefStmts(VarDefStmtSet &noInitVarDefStmts) const;
	void removeToBeRemovedStmts(StmtSet toRemoveStmts) const;
	virtual void runOnFunction(ShPtr<Function> func) override;
	void saveCountOfUsageVars(const VarSet &vars);
	void saveVars(ShPtr<Statement> parent, std::size_t order, VarSet vars);
	void setStmtToOptimize(ShPtr<Variable> var, ShPtr<Statement> stmt);
	void sortVarDefStmts(const VarDefStmtSet &noInitVarDefStmts);
	void tryToFindAndEnterToNextNestingLevel(ShPtr<Statement> stmt,
		VarSet &thisLvlVars, std::size_t order);
	bool tryOptimizeUForLoop(ShPtr<UForLoopStmt> loop,
		ShPtr<Variable> optimizedVar) const;

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// Saves level of current nesting.
	std::size_t level;

	/// Mapping a Variable into a statements where was this Variable used. Also
	/// level of nesting for this statement.
	VarFirstUseMap firstUseMap;

	/// Map of all next level statements like if, else if, while, switch, for
	/// etc. Access to this map is by nesting level. Items are all next level
	/// statements in this mapped nesting level. With next level statements are
	/// also saved parents of next level statements(one level upper block
	/// entry) and order in current block of these next level statements.
	IntNextLvlStmtsMap mapOfNextLvlStmts;

	/// Set of all variables from VarDefStmt to optimize.
	VarSet varsFromVarDefStmt;

	/// Map of all statements to optimize. Access to map is by variable from
	/// VarDefStmt to optimize.
	VarStmtToOptimizeMap optimizeStmts;

	/// Mapping variable into it's number of use in separate blocks of same
	/// nesting level.
	VarLevelCountMap varLevelCountMap;

	/// Vector of sorted VarDefStmt by name of variable.
	VarDefStmtVec sortedNoInitVarDefStmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
