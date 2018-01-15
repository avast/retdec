/**
* @file include/retdec/llvmir2hll/ir/if_stmt.h
* @brief An if/else-if/else statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_IF_STMT_H
#define RETDEC_LLVMIR2HLL_IR_IF_STMT_H

#include <list>
#include <utility>

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief An if/else-if/else statement.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class IfStmt final: public Statement {
public:
	/// `If` clause (condition and body).
	using IfClause = std::pair<ShPtr<Expression>, ShPtr<Statement>>;

	/// A list of `if` clauses.
	// Note to developers: We have to use std::list as the underlying container
	//                     due to the requirements of several member functions.
	using IfClauseList = std::list<IfClause>;

	/// `If/else-if` clause iterator.
	/// Attributes (@c i is an iterator):
	///   - @c i->first is the clause's condition,
	///   - @c i->second is the clause's body.
	using clause_iterator = IfClauseList::const_iterator;

public:
	static ShPtr<IfStmt> create(ShPtr<Expression> cond, ShPtr<Statement> body,
		ShPtr<Statement> succ = nullptr);

	virtual ~IfStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return true; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject, ShPtr<Value> arg = nullptr) override;
	/// @}

	/// @name Clause Accessors
	/// @{
	clause_iterator clause_begin() const;
	clause_iterator clause_end() const;

	void addClause(ShPtr<Expression> cond, ShPtr<Statement> body);
	clause_iterator removeClause(clause_iterator clauseIterator);
	bool hasClauses() const;
	bool hasIfClause() const;
	ShPtr<Expression> getFirstIfCond() const;
	ShPtr<Statement> getFirstIfBody() const;
	void setFirstIfCond(ShPtr<Expression> newCond);
	void setFirstIfBody(ShPtr<Statement> newBody);
	bool hasElseIfClauses() const;
	ShPtr<Statement> getElseClause() const;
	bool hasElseClause() const;
	void setElseClause(ShPtr<Statement> body);
	void removeElseClause();
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	IfStmt(ShPtr<Expression> cond, ShPtr<Statement> body);

private:
	/// A list of `if` clauses.
	IfClauseList ifClauseList;

	/// The else clause (if any).
	ShPtr<Statement> elseClause;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
