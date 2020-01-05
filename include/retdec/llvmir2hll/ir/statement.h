/**
* @file include/retdec/llvmir2hll/ir/statement.h
* @brief A representation of a program statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_STATEMENT_H
#define RETDEC_LLVMIR2HLL_IR_STATEMENT_H

#include <cstddef>
#include <set>
#include <string>

#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class GotoStmt;

/**
* @brief A representation of a program statement.
*
* Each statement can have at most one parent, i.e. it has to be used at most
* once in the whole program. If you want to have the same statement on multiple
* places, clone it by calling clone().
*
* Instances of this class have reference object semantics.
*
* Statement successors have to be set in subclasses by calling setSuccessor()
* (the reason is that @c shared_from_this() cannot be called from a
* constructor).
*
* Other functions for manipulating statements can be found in @c
* Utils/IR.h.
*/
class Statement: public Value {
public:
	/// Predecessor iterator.
	using predecessor_iterator = StmtSet::const_iterator;

public:
	/**
	* @brief Replaces all occurrences of @a oldExpr with @a newExpr in the
	*        current statement.
	*
	* @param[in] oldExpr Old expression to be replaced.
	* @param[in] newExpr Replacement.
	*
	* In compound statements, their body is left untouched, i.e. this function
	* doesn't replace expressions in the bodies of statements.
	*
	* @par Preconditions
	*  - @a oldExpr is non-null
	*/
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) = 0;

	/**
	* @brief Returns @c true if the statement is a compound statement, @c false
	*        otherwise.
	*
	* A compound statement is a statement with nested statements, e.g. an if
	* statement, a switch statement, a while loop, and a for loop.
	*/
	virtual bool isCompound() = 0;

	/**
	* @brief Returns the statement as an expression.
	*
	* If the statement cannot be converted into an expression, the null pointer
	* is returned.
	*
	* Parts of the statement are not cloned (if you want a clone, call @c
	* clone() on the returned expression).
	*/
	virtual Expression* asExpression() const = 0;

	/// @name Successor Management
	/// @{
	bool hasSuccessor() const;
	Statement* getSuccessor() const;
	void setSuccessor(Statement* newSucc);
	void removeSuccessor();
	void appendStatement(Statement* stmt);
	/// @}

	/// @name Predecessor Management
	/// @{
	bool hasPredecessors() const;
	std::size_t getNumberOfPredecessors() const;
	void addPredecessor(Statement* stmt);
	Statement* getUniquePredecessor() const;
	void removePredecessor(Statement* stmt);
	void removePredecessors(bool onlyNonGoto = false);
	void prependStatement(Statement* stmt);

	predecessor_iterator predecessor_begin() const;
	predecessor_iterator predecessor_end() const;
	/// @}

	/// @name Label
	/// @{
	bool hasLabel() const;
	std::string getLabel() const;
	void setLabel(const std::string &newLabel);
	void removeLabel();
	void transferLabelFrom(Statement* stmt);
	void transferLabelTo(Statement* stmt);
	/// @}

	Statement* getParent() const;
	Address getAddress() const;

	/// @name Goto Targets
	/// @{
	bool isGotoTarget() const;
	void redirectGotosTo(Statement* stmt);
	/// @}

	static void removeStatement(Statement* stmt);
	static void removeStatementButKeepDebugComment(Statement* stmt);
	static bool areEqualStatements(Statement* stmts1, Statement* stmts2);
	static bool isStatementInStatements(Statement* stmt,
		Statement* stmts);
	static void replaceStatement(Statement* oldStmt,
		Statement* newStmt);
	static void removeLastStatement(Statement* stmts);
	static Statement* mergeStatements(
		Statement* stmt1, Statement* stmt2);
	static Statement* cloneStatements(Statement* stmts);
	static Statement* getLastStatement(Statement* stmts);

protected:
	Statement(Address a = Address::Undefined);

protected:
	/// Successor statement.
	Statement* succ = nullptr;

	/// Predecessor statements.
	StmtSet preds;

	/// Label.
	std::string label;

	/// Address of ASM instruction from which this statement was created from.
	Address address;

private:
	bool targetIsCurrentStatement(GotoStmt* gotoStmt) const;
	bool containsJustGotosToCurrentStatement(const StmtSet &stmts) const;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
