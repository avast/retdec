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
	static VarRenamer* create(VarNameGen* varNameGen,
		bool useDebugNames = true);

	virtual std::string getId() const override;

private:
	virtual void renameGlobalVar(Variable* var) override;
	virtual void renameVarsInFunc(Function* func) override;
	virtual void renameFuncParam(Variable* var,
		Function* func) override;
	virtual void renameFuncLocalVar(Variable* var,
		Function* func) override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ForLoopStmt* stmt) override;
	virtual void visit(ReturnStmt* stmt) override;
	virtual void visit(AssignStmt* stmt) override;
	virtual void visit(VarDefStmt* stmt) override;
	virtual void visit(CallExpr* expr) override;
	virtual void visit(Variable* var) override;
	/// @}

	void visitSubsequentStmts(Statement* stmt);
	void visitFuncBody(Function* func);
	void renameMainParams(Function* func);
	void renameInductionVars(Function* func);
	void renameInductionVar(Variable* var, Function* func);
	void renameReturnedVars(Function* func);
	void renameResultsOfWellKnownFuncs(Function* func);
	void renameArgsOfWellKnownFuncs(Function* func);
	void renameOtherLocalVars(Function* func);
	void renameVarByChoosingNameFromList(Variable* var,
		Function* func, const char **names, std::size_t numOfAvailNames);
	void tryRenameVarStoringCallResult(Statement* stmt);
	void tryRenameVarsPassedAsArgsToFuncCall(CallExpr* expr);
	void tryRenameVarPassedAsArgToFuncCall(Function* calledFunc,
		Variable* var, unsigned argPos);
	Function* getDeclaredFunc(CallExpr* expr) const;
	Variable* getVarFromCallArg(Expression* arg) const;
	std::string genNameForFuncParam(Variable* var,
		Function* func) const;

	ReadableVarRenamer(VarNameGen* varNameGen, bool useDebugNames);

private:
	/// Generator of names for global variables.
	VarNameGen* globalVarNameGen = nullptr;

	/// Generator of names for local variables.
	VarNameGen* localVarNameGen = nullptr;

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
