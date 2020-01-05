/**
* @file include/retdec/llvmir2hll/utils/ir.h
* @brief IR utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_UTILS_IR_H
#define RETDEC_LLVMIR2HLL_UTILS_IR_H

#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CastExpr;
class Expression;
class Function;
class Module;
class Statement;
class Variable;
class WhileLoopStmt;

/// @name Operations Over Backend IR
/// @{

void sortByName(FuncVector &vec);
void sortByName(VarVector &vec);
void sortByName(VarInitPairVector &vec);

Statement* skipEmptyStmts(Statement* stmts);
Expression* skipCasts(Expression* expr);
Expression* skipDerefs(Expression* expr);
Expression* skipAddresses(Expression* expr);
bool endsWithRetOrUnreach(Statement* stmts);
Expression* getLhs(Statement* stmt);
Expression* getRhs(Statement* stmt);
StmtVector removeVarDefOrAssignStatement(Statement* stmt,
	Function* func = nullptr);
void replaceVarWithExprInStmt(Variable* var,
	Expression* expr, Statement* stmt);
bool isVarDefOrAssignStmt(Statement* stmt);
bool isLoop(Statement* stmt);
bool isInfiniteEmptyLoop(WhileLoopStmt* stmt);
bool isWhileTrueLoop(WhileLoopStmt* stmt);
Function* getCalledFunc(CallExpr* callExpr, Module* module);
std::string getNameOfCalledFunc(CallExpr* callExpr, Module* module);
bool isCallByPointer(Expression* callExpr, Module* module);
Statement* getInnermostLoop(Statement* stmt);
Statement* getInnermostLoopOrSwitch(Statement* stmt);
bool isDefOfVar(Statement* stmt, Variable* var);
void addLocalVarToFunc(Variable* var, Function* func,
	Expression* init = nullptr);
void convertGlobalVarToLocalVarInFunc(Variable* var,
	Function* func, Expression* init = nullptr);

/// @}

} // namespace llvmir2hll
} // namespace retdec

#endif
