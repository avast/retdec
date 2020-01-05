/**
* @file include/retdec/llvmir2hll/utils/loop_optimizer.h
* @brief Utilities for optimizers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_UTILS_LOOP_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_UTILS_LOOP_OPTIMIZER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A representation of a "while true" loop.
*
* Consider a general "while true" loop:
* @code
* while True:
*     // Statements (1)
*     if cond: // Loop end (2)
*         either nothing or a variable assignment
*         break or return
*     // Statements (3)
* @endcode
*
* This class represents a loop splitted into the parts (1) through (3).
*/
struct SplittedWhileTrueLoop {
	/// Statements before the loop's end -- corresponds to (1) in the class
	/// description.
	Statement* beforeLoopEndStmts = nullptr;

	/// The loop's end -- corresponds to (2) in the class description.
	IfStmt* loopEnd = nullptr;

	/// Statements after the loop's end -- corresponds to (3) in the class
	/// description.
	Statement* afterLoopEndStmts = nullptr;
};

/**
* @brief Information about the induction variable of a "while true" loop.
*
* Consider a "while true" loop that can be optimized into a for loop:
* @code
* ...
* i = 0 // (1)
* ...
* while True:
*     ...
*     if cond: // (2)
*         break or return
*     i = i + 1 // (3)
* @endcode
*/
struct IndVarInfo {
	IndVarInfo(
			Statement* initStmt,
			Variable* indVar,
			Expression* exitCond,
			Statement* updateStmt,
			bool updateBeforeExit)
			: initStmt(initStmt)
			, indVar(indVar)
			, exitCond(exitCond)
			, updateStmt(updateStmt)
			, updateBeforeExit(updateBeforeExit)
	{}

	/// Initialization of the induction variable (either a definition or an
	/// assignment) -- corresponds to (1) in the class description.
	Statement* initStmt = nullptr;

	/// Induction variable -- corresponds to (1) in the class description.
	Variable* indVar = nullptr;

	/// Exit condition -- corresponds to (2) in the class description.
	Expression* exitCond = nullptr;

	/// Update of the induction variable -- corresponds to (3) in the class
	/// description.
	Statement* updateStmt = nullptr;

	/// Is an update statement before exit condition?
	bool updateBeforeExit;
};

bool isLoopEnd(Statement* stmt);
Expression* getExitCondition(Statement* loopEnd);
SplittedWhileTrueLoop* splitWhileTrueLoop(
		WhileLoopStmt* stmt,
		IndVarInfo* indVarInfo = nullptr);
IndVarInfo* getIndVarInfo(WhileLoopStmt* stmt);

} // namespace llvmir2hll
} // namespace retdec

#endif
