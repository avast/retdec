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

ShPtr<Statement> skipEmptyStmts(ShPtr<Statement> stmts);
ShPtr<Expression> skipCasts(ShPtr<Expression> expr);
ShPtr<Expression> skipDerefs(ShPtr<Expression> expr);
ShPtr<Expression> skipAddresses(ShPtr<Expression> expr);
bool endsWithRetOrUnreach(ShPtr<Statement> stmts);
ShPtr<Expression> getLhs(ShPtr<Statement> stmt);
ShPtr<Expression> getRhs(ShPtr<Statement> stmt);
StmtVector removeVarDefOrAssignStatement(ShPtr<Statement> stmt,
	ShPtr<Function> func = nullptr);
void replaceVarWithExprInStmt(ShPtr<Variable> var,
	ShPtr<Expression> expr, ShPtr<Statement> stmt);
bool isVarDefOrAssignStmt(ShPtr<Statement> stmt);
bool isLoop(ShPtr<Statement> stmt);
bool isInfiniteEmptyLoop(ShPtr<WhileLoopStmt> stmt);
bool isWhileTrueLoop(ShPtr<WhileLoopStmt> stmt);
ShPtr<Function> getCalledFunc(ShPtr<CallExpr> callExpr, ShPtr<Module> module);
std::string getNameOfCalledFunc(ShPtr<CallExpr> callExpr, ShPtr<Module> module);
bool isCallByPointer(ShPtr<Expression> callExpr, ShPtr<Module> module);
ShPtr<Statement> getInnermostLoop(ShPtr<Statement> stmt);
ShPtr<Statement> getInnermostLoopOrSwitch(ShPtr<Statement> stmt);
bool isDefOfVar(ShPtr<Statement> stmt, ShPtr<Variable> var);
void addLocalVarToFunc(ShPtr<Variable> var, ShPtr<Function> func,
	ShPtr<Expression> init = nullptr);
void convertGlobalVarToLocalVarInFunc(ShPtr<Variable> var,
	ShPtr<Function> func, ShPtr<Expression> init = nullptr);

/// @}

} // namespace llvmir2hll
} // namespace retdec

#endif
