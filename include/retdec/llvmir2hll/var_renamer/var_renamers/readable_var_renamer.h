/**
* @file include/retdec/llvmir2hll/var_renamer/var_renamers/readable_var_renamer.h
* @brief A renamer of variable names which names them to make the code as
*        readable as possible.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_READABLE_VAR_RENAMER_H
#define RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_READABLE_VAR_RENAMER_H

#include <cstddef>
#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"

namespace retdec {
namespace llvmir2hll {

class VarNameGen;

/**
* @brief A renamer of variable names which names them to make the code as
*        readable as possible.
*
* The following renames are done:
*   (1) If a variable has assigned a name from debug information, it is used.
*
*   (2) Induction variables of loops are named "i", "j", "k", ... (if possible).
*
*   (3) If only a single variable is returned from a function, this variable is
*       named "result" (if possible).
*
*   (4) The parameters of the main() function are named "argc" and "argv" (if
*       possible).
*
*   (5) Variables storing the return values of some well-known functions, which
*       are named uniformly by programmers, are assigned such names. For
*       example, depending on the used semantics, the variable storing the
*       result of @c getchar() may be named @c c.
*
*   (6) Variables passed as arguments to some well-known functions are given
*       more meaningful names (whenever possible). For example, depending on
*       the used semantics, the variable passed as the first argument of @c
*       fopen() may be named @c file_path.
*
*   (7) The remaining variables are named @c gX (global variables), @c aX
*       (parameters), and @c vX (local variables), where @c Xs are consecutive
*       numbers, starting from 1.
*
* Use create() to create instances.
*/
class ReadableVarRenamer: public VarRenamer {
public:
	static ShPtr<VarRenamer> create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames = true);

	virtual std::string getId() const override;

private:
	virtual void renameGlobalVar(ShPtr<Variable> var) override;
	virtual void renameVarsInFunc(ShPtr<Function> func) override;
	virtual void renameFuncParam(ShPtr<Variable> var,
		ShPtr<Function> func) override;
	virtual void renameFuncLocalVar(ShPtr<Variable> var,
		ShPtr<Function> func) override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	virtual void visit(ShPtr<ReturnStmt> stmt) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<CallExpr> expr) override;
	virtual void visit(ShPtr<Variable> var) override;
	/// @}

	void visitSubsequentStmts(ShPtr<Statement> stmt);
	void visitFuncBody(ShPtr<Function> func);
	void renameMainParams(ShPtr<Function> func);
	void renameInductionVars(ShPtr<Function> func);
	void renameInductionVar(ShPtr<Variable> var, ShPtr<Function> func);
	void renameReturnedVars(ShPtr<Function> func);
	void renameResultsOfWellKnownFuncs(ShPtr<Function> func);
	void renameArgsOfWellKnownFuncs(ShPtr<Function> func);
	void renameOtherLocalVars(ShPtr<Function> func);
	void renameVarByChoosingNameFromList(ShPtr<Variable> var,
		ShPtr<Function> func, const char **names, std::size_t numOfAvailNames);
	void tryRenameVarStoringCallResult(ShPtr<Statement> stmt);
	void tryRenameVarsPassedAsArgsToFuncCall(ShPtr<CallExpr> expr);
	void tryRenameVarPassedAsArgToFuncCall(ShPtr<Function> calledFunc,
		ShPtr<Variable> var, unsigned argPos);
	ShPtr<Function> getDeclaredFunc(ShPtr<CallExpr> expr) const;
	ShPtr<Variable> getVarFromCallArg(ShPtr<Expression> arg) const;
	std::string genNameForFuncParam(ShPtr<Variable> var,
		ShPtr<Function> func) const;

	ReadableVarRenamer(ShPtr<VarNameGen> varNameGen, bool useDebugNames);

private:
	/// Generator of names for global variables.
	UPtr<VarNameGen> globalVarNameGen;

	/// Generator of names for local variables.
	UPtr<VarNameGen> localVarNameGen;

	/// Names of induction variables in the current function.
	/// Available only after renameInductionVars() is run.
	StringSet indVarsNamesInCurrFunc;

	/// Are we renaming induction variables?
	bool renamingInductionVars;

	/// Are we renaming return variables?
	bool renamingReturnVars;

	/// Are we renaming variables storing the results of calls to well-known
	/// functions?
	bool renamingResultsOfWellKnownFuncs;

	/// Are we renaming variables passed as arguments of calls to well-known
	/// functions?
	bool renamingArgsOfWellKnownFuncs;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
