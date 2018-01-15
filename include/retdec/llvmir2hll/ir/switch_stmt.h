/**
* @file include/retdec/llvmir2hll/ir/switch_stmt.h
* @brief A switch statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_SWITCH_STMT_H
#define RETDEC_LLVMIR2HLL_IR_SWITCH_STMT_H

#include <list>
#include <utility>

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A switch statement.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class SwitchStmt final: public Statement {
public:
	/// `case` clause (condition and body).
	using SwitchClause = std::pair<ShPtr<Expression>, ShPtr<Statement>>;

	/// A list of `case` clauses.
	// Note to developers: We have to use std::list as the underlying container
	//                     due to the requirements of several member functions.
	using SwitchClauseList = std::list<SwitchClause>;

	/// `case` clause iterator.
	/// Attributes (@c i is an iterator):
	///   - @c i->first is the clause's condition,
	///   - @c i->second is the clause's body.
	/// The default clause (if any) has null @c i->first, i.e. there is no
	/// condition, only a body.
	using clause_iterator = SwitchClauseList::const_iterator;

public:
	static ShPtr<SwitchStmt> create(ShPtr<Expression> controlExpr,
		ShPtr<Statement> succ = nullptr);

	virtual ~SwitchStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return true; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	/// @name Control Expression Accessors
	/// @{
	ShPtr<Expression> getControlExpr() const;
	void setControlExpr(ShPtr<Expression> newExpr);
	/// @}

	/// @name Clause Accessors
	/// @{
	void addClause(ShPtr<Expression> expr, ShPtr<Statement> body);
	clause_iterator removeClause(clause_iterator clauseIterator);
	bool hasDefaultClause() const;
	ShPtr<Statement> getDefaultClauseBody() const;
	void addDefaultClause(ShPtr<Statement> body);
	void setDefaultClauseBody(ShPtr<Statement> body);
	void removeDefaultClause();

	clause_iterator clause_begin() const;
	clause_iterator clause_end() const;
	/// @}

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject, ShPtr<Value> arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit SwitchStmt(ShPtr<Expression> controlExpr);

private:
	/// List of `case` clauses.
	SwitchClauseList switchClauseList;

	/// Control expression.
	ShPtr<Expression> controlExpr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
