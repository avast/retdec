/**
* @file src/llvmir2hll/optimizer/optimizers/var_def_stmt_optimizer.cpp
* @brief Implementation of VarDefStmtOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <limits>

#include "retdec/llvmir2hll/analysis/no_init_var_def_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/var_def_stmt_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/container.h"
#include "retdec/utils/string.h"

using retdec::utils::addToSet;
using retdec::utils::isLowerThanCaseInsensitive;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va Analysis of values.
*
* @par Preconditions
*  - @a module and @a va are non-null
*/
VarDefStmtOptimizer::VarDefStmtOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va): FuncOptimizer(module), va(va), level(0) {
	PRECONDITION_NON_NULL(module);
	PRECONDITION_NON_NULL(va);
}

/**
* @brief Destructs the optimizer.
*/
VarDefStmtOptimizer::~VarDefStmtOptimizer() {}

void VarDefStmtOptimizer::doOptimization() {
	// Clear the cache of va because other optimizations may have left it in an
	// invalid state.
	va->clearCache();

	FuncOptimizer::doOptimization();
}

void VarDefStmtOptimizer::runOnFunction(ShPtr<Function> func) {
	ShPtr<NoInitVarDefAnalysis> varDefStmtAnalysis(new NoInitVarDefAnalysis());

	// Get all VarDefStmt statements without an initializer.
	VarDefStmtSet noInitVarDefStmts = varDefStmtAnalysis->getNoInitVarDefStmts(func);

	// We don't want to optimize structures and array VarDefStmts.
	removeStructAndArrayVarDefStmts(noInitVarDefStmts);

	// Get all vars from noInitVarDefStmts and save them into varsFromVarDefStmt.
	getVarsFromVarDefStmts(noInitVarDefStmts);

	// Sort a VarDefStmt from setOfVarDefStmt into sortedNoInitVarDefStmts.
	sortVarDefStmts(noInitVarDefStmts);

	// Get the first statement in the function.
	ShPtr<Statement> stmt = func->getBody();

	// Start analysing of all nesting levels. Parent in this case can be
	// anything. The first level is number 0.
	oneBlockTraversal(stmt, stmt, 0);

	// After analyse we can find the statements to optimize.
	findStmtsToOptimize();

	// After finding the statements to optimize we can optimize.
	optimizeVarDefStmts();

	// Function clear all records about variables in function.
	clearAllRecords();
}

/**
* @brief This function is recursive. One recursion visits all statements in
*        block and calls a new recursion for the next nesting level blocks.
*
* This function also analyses variables usage in blocks.
*
* @param[in] stmt The first statement in block.
* @param[in] parent A parent of block.
* @param[in] parOrder An order of parent in his block.
*
* @return A @c VarSet of vars that are visible from this block.
*/
VarSet VarDefStmtOptimizer::oneBlockTraversal(ShPtr<Statement> stmt,
		ShPtr<Statement> parent, std::size_t parOrder) {
	// Simple counter for order of statements.
	std::size_t order = 0;
	// Set of vars that are visible from this block.
	VarSet thisLvlVars;

	// Iterate through all statements and analyse them.
	for (; stmt; stmt = stmt->getSuccessor()) {

		// Skip VarDefStmts. We don't need to analyse them.
		ShPtr<VarDefStmt> varDefStmt(cast<VarDefStmt>(stmt));
		if (varDefStmt){
			order++;
			continue;
		}

		// Analysing of all variables in statement.
		analyseVariablesInStmt(stmt, thisLvlVars);

		// Try to find enter of next nesting level block. If find, than enter to
		// this block. After out from entered block append visible variables to
		// current block.
		tryToFindAndEnterToNextNestingLevel(stmt, thisLvlVars, order);

		// Going to next statement, so increment order of statements.
		order++;
	}

	// Save vars that used in this level for parent statement.
	//    if (1) {
	//        a = 2;
	//        b = 4;
	//    }
	// Need to save that variables "a" and "b" are used in if(1). Also is saved
	// the order of if(1). With this we got all blocks with variables that are
	// used in same level.
	saveVars(parent, parOrder, thisLvlVars);

	//
	//    if (1) {
	//        a = 2;
	//    }
	//    if (2) {
	//        a = 5;
	//    }
	// Need to save that variable "a" is used in two blocks in same level.
	saveCountOfUsageVars(thisLvlVars);

	// return the visible variables from this block.
	return thisLvlVars;
}

/**
* @brief Tries to find the enter of the next nesting level block and enters it
*        if it is found.
*
* Tries to find the enter of the next nesting level block. If it is found, this
* function enters this block. After out from the entered block, it appends
* visible variables to the current block.
*
* @param[in] stmt The current statement.
* @param[in,out] thisLvlVars Set of vars that are visible from this block.
* @param[in] order Order of the current statement.
*/
void VarDefStmtOptimizer::tryToFindAndEnterToNextNestingLevel(
		ShPtr<Statement> stmt, VarSet &thisLvlVars, std::size_t order) {
	if (ShPtr<IfStmt> ifStmt = cast<IfStmt>(stmt)) {
		for (auto i = ifStmt->clause_begin(), e = ifStmt->clause_end();
				i != e; ++i) {
			goToNextBlockAndAppendVisibleVars(i->second, stmt, order,
				thisLvlVars);
		}
		if (ifStmt->hasElseClause()) {
			goToNextBlockAndAppendVisibleVars(ifStmt->getElseClause(), stmt,
				order, thisLvlVars);
		}
		return;
	}

	if (ShPtr<WhileLoopStmt> whileLoopStmt = cast<WhileLoopStmt>(stmt)) {
		goToNextBlockAndAppendVisibleVars(whileLoopStmt->getBody(), stmt,
			order, thisLvlVars);
		return;
	}

	if (ShPtr<ForLoopStmt> forLoopStmt = cast<ForLoopStmt>(stmt)) {
		goToNextBlockAndAppendVisibleVars(forLoopStmt->getBody(), stmt,
			order, thisLvlVars);
		return;
	}

	if (ShPtr<UForLoopStmt> uforLoopStmt = cast<UForLoopStmt>(stmt)) {
		goToNextBlockAndAppendVisibleVars(uforLoopStmt->getBody(), stmt,
			order, thisLvlVars);
		return;
	}

	if (ShPtr<SwitchStmt> switchStmt = cast<SwitchStmt>(stmt)) {
		for (auto i = switchStmt->clause_begin(), e = switchStmt->clause_end();
				i != e; ++i) {
			goToNextBlockAndAppendVisibleVars(i->second, stmt, order,
				thisLvlVars);
		}
		return;
	}
}

/**
* @brief Tries to optimize the given variable for the given universal for loop.
*
* @return @c true when the optimization was performed, @c false otherwise.
*/
bool VarDefStmtOptimizer::tryOptimizeUForLoop(ShPtr<UForLoopStmt> loop,
		ShPtr<Variable> optimizedVar) const {
	// When the variable is used in the initialization part of a
	// universal for loop, we can mark its initialization part as a definition.
	// This enables us to emit
	//
	//     for (int i = 1; i < 10; ++i) /* ... */
	//
	// instead of
	//
	//     int i;
	//     for (i = 1; i < 10; ++i) /* ... */
	//
	auto assignExpr = cast<AssignOpExpr>(loop->getInit());
	if (!assignExpr || assignExpr->getFirstOperand() != optimizedVar) {
		return false;
	}

	loop->markInitAsDefinition();
	loop->redirectGotosTo(loop);
	return true;
}

/**
* @brief Analyses statement @a stmt.
*
* This function appends all variables that are used in @a stmt into @a
* thisLvlVars because these variables are visible from this block. It also
* saves the first usage of every variable.
*
* @param[in] stmt The statement to analyse.
* @param[in,out] thisLvlVars Set of variables that are visible from this block.
*/
void VarDefStmtOptimizer::analyseVariablesInStmt(ShPtr<Statement> stmt,
		VarSet &thisLvlVars) {
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	for (auto i = stmtData->dir_all_begin(), e = stmtData-> dir_all_end();
			i != e; ++i) {
		// Find if this variable was in some VarDefStmt.
		auto itVars = varsFromVarDefStmt.find(*i);
		// Find if this variable has already been saved as visible from this
		// block.
		auto itSetLvlVars = thisLvlVars.find(*i);
		// Save visibility of this variable.
		if (itVars != varsFromVarDefStmt.end() &&
				itSetLvlVars == thisLvlVars.end()) {
			thisLvlVars.insert(*i);
		}

		// Is this first use of variable from VarDefStmt except VarDefStmt?
		auto itFirst = firstUseMap.find(*i);
		// Analyzing of first use of variable.
		if (itVars != varsFromVarDefStmt.end() && itFirst == firstUseMap.end()) {
			// This is first use of variable, just save it.
			FirstUse firstUse = {stmt, level};
			firstUseMap[*i] = firstUse;
		} else if (itVars != varsFromVarDefStmt.end() &&
				itFirst != firstUseMap.end()) {
			// In some cases we need to change first use of variable because
			// we go to next nesting level immediately when we find enter.
			// Example:
			//    if (1) {
			//        if (2) {
			//            a;
			//        }
			//        a;
			//    }
			// Need to change first use to if(2).
			if (itFirst->second.level > level) {
				// Need to find where we can place first use.
				FirstUse firstUse = {findStmtToPrepend(*i, level + 1), level};
				firstUseMap[*i] = firstUse;
			}
		}
	}
}

/**
* @brief Calls recursion to next block and append visible variables
*        from the next block to the currenct block.
*
* @param[in] stmt The first statement in block.
* @param[in] parent A parent of next nested level block.
* @param[in] order An order of parent in his block.
* @param[in,out] vars A @c VarSet of variables that are visible from the current
*                 block.
*/
void VarDefStmtOptimizer::goToNextBlockAndAppendVisibleVars(ShPtr<Statement> stmt,
		ShPtr<Statement> parent, std::size_t order, VarSet &vars) {
	// Need to increment level because we go to next nesting level.
	level++;
	VarSet appendVarsSet = oneBlockTraversal(stmt, parent, order);
	level--;
	// If we are not in 0 level append visibility of variables.
	// The 0 level are basic level. We don't want to merge variables from all
	// block to one in basic level.
	if (level) {
		addToSet(appendVarsSet, vars);
	}
}

/**
* @brief Saves all variables that are used in block to parent of this block.
*
* @param[in] parent A parent of block.
* @param[in] order An order of parent in his block.
* @param[in] vars A @c VarSet of variables that are visible from current block.
*/
void VarDefStmtOptimizer::saveVars(ShPtr<Statement> parent, std::size_t order,
		VarSet vars) {
	// Create structure to save of all need informations.
	NextLvlStmts nextLvlStmts = {parent, order, vars};

	// Find if exists this nesting level.
	auto it = mapOfNextLvlStmts.find(level);
	if (it != mapOfNextLvlStmts.end()) {
		// It exists, so append a new block.
		it->second.push_back(nextLvlStmts);
	} else {
		// If it does not exist, create it.
		VecNextLvlStmts nextVec;
		nextVec.push_back(nextLvlStmts);
		mapOfNextLvlStmts[level] = nextVec;
	}
}

/**
* @brief This function is responsible for counting of blocks where a variable
*        is used in the same level.
*
* @param[in] vars A @c VarSet of vars that need to add to counting.
*/
void VarDefStmtOptimizer::saveCountOfUsageVars(const VarSet &vars) {
	for (const auto &var : vars) {
		// Is some count record of iterated variable?
		auto itVarLvlCnt = varLevelCountMap.find(var);
		if (itVarLvlCnt != varLevelCountMap.end()) {
			// Is some count record of iterated variable in current level?
			auto lvlCnt = itVarLvlCnt->second.find(level);
			if (lvlCnt != itVarLvlCnt->second.end()) {
				// Variable record and level record exists, just add usage.
				lvlCnt->second++;
			} else {
				// Variable record exists bud level not. Set to first usage.
				itVarLvlCnt->second[level] = 1;
			}
		} else {
			// Not exists record for iterated variable. Need to create it.
			LevelCountMap levelCounts;
			levelCounts[level] = 1;
			varLevelCountMap[var] = levelCounts;
		}
	}
}

/**
* @brief Finds a statement in @a level to prepend.
*
* @param[in] var A variable for which is finding statement.
* @param[in] level A nested level where is finding statement.
*
* @return A statement to prepend.
*/
ShPtr<Statement> VarDefStmtOptimizer::findStmtToPrepend(ShPtr<Variable> var,
		std::size_t level) const {
	std::size_t order = std::numeric_limits<std::size_t>::max();
	ShPtr<Statement> stmt;

	// Find level.
	auto it = mapOfNextLvlStmts.find(level);

	// Iterate through all blocks in this level and find the first one.
	for (const auto &block : it->second) {
		// Is variable used in this block?
		if (block.vars.find(var) != block.vars.end()) {
			if (block.order < order) {
				// Find the first one
				order = block.order;
				stmt = block.stmt;
			}
		}
	}
	return stmt;
}

/**
* @brief Finds the final statement to optimize.
*/
void VarDefStmtOptimizer::findStmtsToOptimize() {
	VarLevelCountMap::const_iterator i, e;
	LevelCountMap::const_iterator j, k;

	for (i = varLevelCountMap.begin(), e = varLevelCountMap.end(); i != e; ++i) {
		// Iterate with variable through all level and find if variable is used
		// in two blocks.
		for (j = i->second.begin(), k = i->second.end(); j!=k; ++j) {
			if (j->second > 1) {
				break;
			}
		}

		if (j != i->second.end()) {
			// Variable is used in two blocks.
			// Need to find final statement to optimize.
			ShPtr<Statement> stmt = findStmtToPrepend((*i).first, (*j).first);

			// Need to check if variable was not used before two or more blocks.
			//    a = 5;
			//    if () {
			//        a = 2;
			//    }
			//    if () {
			//        a = 4;
			//    }
			//
			auto itFirstUse = firstUseMap.find((*i).first);
			if (itFirstUse != firstUseMap.end() &&
					itFirstUse->second.level < (*j).first) {
				stmt = itFirstUse->second.stmt;
			}

			setStmtToOptimize((*i).first, stmt);
		} else {
			// Find only one block where is variable used. We can optimize in
			// this statement.
			auto it = firstUseMap.find((*i).first);
			setStmtToOptimize(it->first, it->second.stmt);
		}
	}
}

/**
* @brief Removes structures VarDefStmt and array VarDefStmt from @a
*        noInitVarDefStmts.
*
* @param[in,out] noInitVarDefStmts A set of @c VarDefStmt.
*/
void VarDefStmtOptimizer::removeStructAndArrayVarDefStmts(
		VarDefStmtSet &noInitVarDefStmts) const {
	// We don't want to optimize structures VarDefStmt and array VarDefStmt.
	// Only VarDefStmt like int a. So, remove these VarDefStmts from the set.
	// For example, we don't want to optimize
	//
	//    struct struct4 banana;
	//    banana.e0 = 0;
	//
	// to
	//
	//    struct struct4 banana.e0 = 0;
	//
	// because the result is not correct C.
	for (auto it = noInitVarDefStmts.begin(); it != noInitVarDefStmts.end(); ) {
		ShPtr<Type> varType = (*it)->getVar()->getType();
		if (!isa<IntType>(varType) && !isa<FloatType>(varType) &&
				!isa<PointerType>(varType)) {
			noInitVarDefStmts.erase(it++);
		} else {
			++it;
		}
	}
}

/**
* @brief Gets all variables from @a noInitVarDefStmts and saves them into @c
*        varsFromVarDefStmt.
*
* @param[in] noInitVarDefStmts A set of @c VarDefStmt.
*/
void VarDefStmtOptimizer::getVarsFromVarDefStmts(
		const VarDefStmtSet &noInitVarDefStmts) {
	for (const auto &stmt : noInitVarDefStmts) {
		varsFromVarDefStmt.insert(stmt->getVar());
	}
}

/**
* @brief Compares the two given VarDefStms by their name.
*
* @return @c true if the name of @a v1 comes before the name of @a v2
*         (case-insensitively), @c false otherwise.
*/
bool compareVarDefStms(const ShPtr<VarDefStmt> &v1,
		const ShPtr<VarDefStmt> &v2) {
	return isLowerThanCaseInsensitive(v1->getVar()->getName(),
		v2->getVar()->getName());
}

/**
* @brief Sorts VarDefStmts by name from set into @c sortedNoInitVarDefStmts.
*
* @param[in] noInitVarDefStmts A set to sort into vector @c
*                              sortedNoInitVarDefStmts.
*/
void VarDefStmtOptimizer::sortVarDefStmts(const VarDefStmtSet &noInitVarDefStmts) {
	sortedNoInitVarDefStmts.clear();
	sortedNoInitVarDefStmts.assign(noInitVarDefStmts.begin(),
		noInitVarDefStmts.end());
	std::sort(sortedNoInitVarDefStmts.begin(), sortedNoInitVarDefStmts.end(),
		compareVarDefStms);
}

/**
* @brief Analyses the given statement and makes a decision if the optimization
*        will be with prepend the statement or change the assign statement.
*
* @param[in] stmt A statement to check.
* @param[in] var A variable that will be optimized.
*
* @return Type of optimization.
*/
VarDefStmtOptimizer::OptType VarDefStmtOptimizer::prependOrAssign(
		ShPtr<Statement> stmt, ShPtr<Variable> var) const {
	// Statement is not an assign statement or var is not in left side of
	// AssignStmt, need to prepend.
	if (!isAssignStmtWithVarOnLhs(stmt, var)) {
		return OptType::P;
	}

	// We can't optimize something like that:
	// int a = a + 2;
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	return stmtData->getDirNumOfUses(var) > 1 ? OptType::P : OptType::A;
}

/**
* @brief Checks if @a stmt is an @c AssignStmt and assigned variable is a @a
*        var.
*
* @param[in] stmt A statement to check if is it an @c AssignStmt.
* @param[in] var A variable to check if is on left side of @c AssignStmt.
*
* @return @c true if the @a stmt is an @c AssignStmt and @a var is on left side
*         of @c AssignStmt, otherwise @c false.
*/
bool VarDefStmtOptimizer::isAssignStmtWithVarOnLhs(ShPtr<Statement> stmt,
		ShPtr<Variable> var) const {
	ShPtr<AssignStmt> assignStmt = cast<AssignStmt>(stmt);
	if (!assignStmt) {
		// Statement is not an assign statement, return false.
		return false;
	}

	ShPtr<Variable> lhsVar(cast<Variable>(assignStmt->getLhs()));
	if (!lhsVar) {
		// If variable is not found on left side of assignStmt, return false.
		return false;
	}

	if (lhsVar != var) {
		// Variable on left side is not same as variable that we want to
		// optimize.
		return false;
	}

	// Is an AssignStmt and var is on left side of AssignStmt.
	return true;
}

/**
* @brief Assigns to a variable statement to optimize.
*
* @param[in] var A variable for VarDefStmt.
* @param[in] stmt A statement to optimize.
*/
void VarDefStmtOptimizer::setStmtToOptimize(ShPtr<Variable> var,
		ShPtr<Statement> stmt) {
	// Save statement to optimize and type of optimization.
	StmtToOptimize stmtToOptimize = {stmt, prependOrAssign(stmt, var)};
	optimizeStmts[var] = stmtToOptimize;
}

/**
* @brief Optimizes all VarDefStmt after analyses in VarDefStmtOptimizer.
*/
void VarDefStmtOptimizer::optimizeVarDefStmts() const {
	// During the optimization, instead of removing the statements directly, we
	// add them in the following set and remove them at the end, i.e. after the
	// optimization is done. This has to be done in order to prevent prepending
	// something to a statement which has already been removed.
	StmtSet toRemoveStmts;

	// First, perform optimizations of the form
	//
	//    int a;
	//    ...
	//    stmt;    <-- use of a
	//
	// i.e. the definition cannot be moved directly into a statement that uses
	// the variable.
	//
	// This optimization has to be run before the second one because it
	// prepends statements. If the second one was run instead, the proper
	// statement before which we should prepend might not exist.
	optimizeWithPrepend(toRemoveStmts);

	// Second, perform optimizations of the form
	//
	//    int a = xxx;
	//
	// i.e. the definition is moved directly into a statement that uses the
	// variable.
	optimizeAssignStmts(toRemoveStmts);

	// Remove all the statements that we have marked as "to be removed".
	removeToBeRemovedStmts(toRemoveStmts);
}

/**
* @brief Optimizes statements that have to be optimized with prepend statement.
*
* @param[in,out] toRemoveStmts Set for optimized @c VarDefStmt that can be removed.
*/
void VarDefStmtOptimizer::optimizeWithPrepend(StmtSet &toRemoveStmts) const {
	for (const auto &stmt : sortedNoInitVarDefStmts) {
		auto it = optimizeStmts.find(stmt->getVar());
		if (it != optimizeStmts.end() && it->second.optType == OptType::P) {
			// Perform the optimization.
			ShPtr<Statement> stmtClone(ucast<Statement>(stmt->clone()));

			// Move metadata from the statement to the prepended statement (if
			// any). This way, instead of
			//
			//    // branch -> 0x401ebc
			//    uint32_t var;
			//    // 0x401ebc
			//    // some statement
			//
			// we get
			//
			//    // branch -> 0x401ebc
			//    // 0x401ebc
			//    uint32_t var;
			//    // some statement
			//
			const std::string &metadata(it->second.stmt->getMetadata());
			if (!metadata.empty()) {
				stmtClone->setMetadata(metadata);
				it->second.stmt->setMetadata("");
			}

			// Universal for loops have to be treated specifically.
			if (auto uforLoop = cast<UForLoopStmt>(it->second.stmt)) {
				bool optimized = tryOptimizeUForLoop(uforLoop, stmt->getVar());
				if (optimized) {
					toRemoveStmts.insert(stmt);
					continue;
				}
			}

			it->second.stmt->prependStatement(stmtClone);
			it->second.stmt->redirectGotosTo(stmtClone);
			toRemoveStmts.insert(stmt);
		}
	}
}

/**
* @brief Optimizes assign statements.
*
* @param[in,out] toRemoveStmts Set for optimized @c VarDefStmt that can be removed.
*/
void VarDefStmtOptimizer::optimizeAssignStmts(StmtSet &toRemoveStmts) const {
	for (const auto &varDefStmt : sortedNoInitVarDefStmts) {
		auto it = optimizeStmts.find(varDefStmt->getVar());
		if (it != optimizeStmts.end() && it->second.optType == OptType::A) {
			// Perform the optimization.
			ShPtr<AssignStmt> assignStmt(cast<AssignStmt>(it->second.stmt));
			assert(assignStmt);
			ShPtr<VarDefStmt> optimizedVarDefStmt(VarDefStmt::create(
				varDefStmt->getVar(), assignStmt->getRhs()));
			Statement::replaceStatement(assignStmt, optimizedVarDefStmt);
			toRemoveStmts.insert(varDefStmt);
		}
	}
}

/**
* @brief Remove all statements that are in @a toRemoveStmts from abstract syntax
*        tree
*
* @param[in] toRemoveStmts Set of all statements to remove.
*/
void VarDefStmtOptimizer::removeToBeRemovedStmts(const StmtSet toRemoveStmts) const {
	for (const auto &stmt : toRemoveStmts) {
		Statement::removeStatement(stmt);
	}
}

/**
* @brief Clear all records about variables that are collected in function
*        analyses.
*/
void VarDefStmtOptimizer::clearAllRecords() {
	firstUseMap.clear();
	mapOfNextLvlStmts.clear();
	varsFromVarDefStmt.clear();
	optimizeStmts.clear();
	varLevelCountMap.clear();
	sortedNoInitVarDefStmts.clear();
}

} // namespace llvmir2hll
} // namespace retdec
