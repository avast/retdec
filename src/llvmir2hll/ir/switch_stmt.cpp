/**
* @file src/llvmir2hll/ir/switch_stmt.cpp
* @brief Implementation of SwitchStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new switch statement.
*
* See create() for more information.
*/
SwitchStmt::SwitchStmt(ShPtr<Expression> controlExpr):
	switchClauseList(), controlExpr(controlExpr) {}

/**
* @brief Destructs the statement.
*/
SwitchStmt::~SwitchStmt() {}

ShPtr<Value> SwitchStmt::clone() {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(
		ucast<Expression>(controlExpr->clone())));

	// Clone all clauses.
	for (auto i = clause_begin(), e = clause_end(); i != e; ++i) {
		if (i->first) {
			switchStmt->addClause(ucast<Expression>(i->first->clone()),
				ucast<Statement>(i->second->clone()));
		} else {
			// The default clause.
			switchStmt->addDefaultClause(ucast<Statement>(i->second->clone()));
		}
	}

	switchStmt->setMetadata(getMetadata());
	return switchStmt;
}

bool SwitchStmt::isEqualTo(ShPtr<Value> otherValue) const {
	// The types of compared instances have to match.
	ShPtr<SwitchStmt> otherSwitchStmt = cast<SwitchStmt>(otherValue);
	if (!otherSwitchStmt) {
		return false;
	}

	// The number of switch clauses have to match.
	if (switchClauseList.size() != otherSwitchStmt->switchClauseList.size()) {
		return false;
	}

	// All switch clauses have to match.
	for (auto i = clause_begin(), j = otherSwitchStmt->clause_begin(),
			e = clause_end(); i != e; ++i, ++j) {
		// Default clauses do not have any condition, so we have to treat them
		// specially.
		if (!i->first || !j->first) {
			// At least one of the current clauses is the default clause.
			if (!i->first && j->first) {
				// The clause in the first switch statement is the default
				// clause, but this is not true for the clause in the second
				// statment.
				return false;
			} else if (i->first && !j->first) {
				// The clause in the second switch statement is the default
				// clause, but this is not true for the clause in the first
				// statment.
				return false;
			} else if (!i->second->isEqualTo(j->second)) {
				// The default clauses have different bodies.
				return false;
			}

			// The currently compared clauses match, so move to the next
			// clauses.
			continue;
		}

		if (!i->first->isEqualTo(j->first) ||
				!i->second->isEqualTo(j->second)) {
			return false;
		}
	}

	// The control expressions have to match.
	return controlExpr->isEqualTo(otherSwitchStmt->controlExpr);
}

void SwitchStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	if (oldExpr == controlExpr) {
		setControlExpr(newExpr);
	}

	// For each clause...
	for (auto i = switchClauseList.begin(), e = switchClauseList.end();
			i != e; ++i) {
		if (i->first == oldExpr) {
			i->first->removeObserver(shared_from_this());
			newExpr->addObserver(shared_from_this());
			i->first = newExpr;
		}
	}
}

ShPtr<Expression> SwitchStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Adds a new case clause.
*
* @param[in] expr Clause condition.
* @param[in] body Clause body.
*
* If @a expr is the null pointer, this clause is the default clause; otherwise,
* it is a regular clause.
*
* Does not invalidate any existing iterators to this switch statement.
*
* @par Preconditions
*  - if @a expr is the null pointer, there cannot be a default clause
*  - @a body is non-null
*/
void SwitchStmt::addClause(ShPtr<Expression> expr, ShPtr<Statement> body) {
	PRECONDITION_NON_NULL(body);
	PRECONDITION(expr || !hasDefaultClause(),
		"adding a default clause when there already is one");

	if (expr) {
		expr->addObserver(shared_from_this());
	}
	body->addObserver(shared_from_this());
	switchClauseList.push_back(SwitchClause(expr, body));
}

/**
* @brief Removes the given clause, specified by an iterator.
*
* @return Iterator to the next clause (or clause_end() if there are no
* subsequent clauses).
*
* After this function is called, existing iterators to the removed clause are
* invalidated. To provide an easy way of removing clauses while iterating over
* them, the iterator returned from this function can be used. Example:
* @code
* clause_iterator i(switchStmt->clause_begin());
* while (i != switchStmt->clause_end()) {
*     if (condition) {
*         i = switchStmt->removeClause(i);
*     } else {
*         ++i;
*     }
* }
* @endcode
*
* @par Preconditions
*  - the passed iterator is valid
*/
SwitchStmt::clause_iterator SwitchStmt::removeClause(
		clause_iterator clauseIterator) {
	// We assume that the used container is std::list.
	if (clauseIterator->first) {
		clauseIterator->first->removeObserver(shared_from_this());
	}
	clauseIterator->second->removeObserver(shared_from_this());
	return switchClauseList.erase(clauseIterator);
}

/**
* @brief Returns the control expression.
*/
ShPtr<Expression> SwitchStmt::getControlExpr() const {
	return controlExpr;
}

/**
* @brief Sets a new control expression.
*/
void SwitchStmt::setControlExpr(ShPtr<Expression> newExpr) {
	controlExpr->removeObserver(shared_from_this());
	newExpr->addObserver(shared_from_this());
	controlExpr = newExpr;
}

/**
* @brief Returns @c true if there is a default clause, @c false otherwise.
*/
bool SwitchStmt::hasDefaultClause() const {
	for (auto i = clause_begin(), e = clause_end(); i != e; ++i) {
		if (!i->first) {
			return true;
		}
	}
	return false;
}

/**
* @brief Returns the body of the default clause.
*
* If there is no default clause, the null pointer is returned.
*/
ShPtr<Statement> SwitchStmt::getDefaultClauseBody() const {
	for (auto i = clause_begin(), e = clause_end(); i != e; ++i) {
		if (!i->first) {
			return i->second;
		}
	}
	return ShPtr<Statement>();
}

/**
* @brief Adds a default clause.
*
* This function is equivalent to calling
* @code
* addClause(ShPtr<Expression>(), body)
* @endcode
*
* Does not invalidate any existing iterators to this switch statement.
*
* @par Preconditions
*  - there is no default clause
*  - @a body is non-null
*/
void SwitchStmt::addDefaultClause(ShPtr<Statement> body) {
	PRECONDITION_NON_NULL(body);
	PRECONDITION(!hasDefaultClause(),
		"adding a default clause when there already is one");

	addClause(ShPtr<Expression>(), body);
}

/**
* @brief Sets a new body of the default clause.
*
* @par Preconditions
*  - there is a default clause
*  - @a body is non-null
*/
void SwitchStmt::setDefaultClauseBody(ShPtr<Statement> body) {
	PRECONDITION_NON_NULL(body);

	// If there is already a default clause, just change its body.
	for (auto i = switchClauseList.begin(), e = switchClauseList.end();
			i != e; ++i) {
		if (!i->first) {
			i->second = body;
			return;
		}
	}

	PRECONDITION_FAILED("there is no default clause");
}

/**
* @brief Removes the default clause (if any).
*
* After this function is called, existing iterators to the removed clause are
* invalidated.
*/
void SwitchStmt::removeDefaultClause() {
	for (auto i = switchClauseList.begin(), e = switchClauseList.end();
			i != e; ++i) {
		if (!i->first) {
			i->first->removeObserver(shared_from_this());
			switchClauseList.erase(i);
			return;
		}
	}
}

/**
* @brief Returns an iterator to the first case clause.
*
*/
SwitchStmt::clause_iterator SwitchStmt::clause_begin() const {
	return switchClauseList.begin();
}

/**
* @brief Returns an iterator past the last case clause.
*
*/
SwitchStmt::clause_iterator SwitchStmt::clause_end() const {
	return switchClauseList.end();
}

/**
* @brief Creates a new switch statement.
*
* @param[in] controlExpr Control expression.
* @param[in] succ Follower of the statement in the program flow.
*
* @par Preconditions
*  - @a controlExpr is non-null
*/
ShPtr<SwitchStmt> SwitchStmt::create(ShPtr<Expression> controlExpr,
		ShPtr<Statement> succ) {
	PRECONDITION_NON_NULL(controlExpr);

	ShPtr<SwitchStmt> stmt(new SwitchStmt(controlExpr));
	stmt->setSuccessor(succ);

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	controlExpr->addObserver(stmt);

	return stmt;
}

/**
* @brief Updates the operator according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @arg. For example, if @a subject is the body of
* some clause, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any part of this statement
*  - @a arg is not an expression/statement
*
* If @a subject is the null pointer, the expression of the default clause is
* updated.
*
* @par Preconditions
*  - if @a subject is the control expression or the body of some clause, @a arg
*    has to be non-null
*
* @see Subject::update()
*/
void SwitchStmt::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	// TODO Refactor the handling of observers into a separate function?

	ShPtr<Expression> newExpr = cast<Expression>(arg);
	ShPtr<Statement> newBody = cast<Statement>(arg);

	// Check the control expression.
	if (subject == controlExpr && newExpr) {
		controlExpr->removeObserver(shared_from_this());
		newExpr->addObserver(shared_from_this());
		controlExpr = newExpr;
	}

	// Check all clauses.
	for (auto i = switchClauseList.begin(), e = switchClauseList.end();
			i != e; ++i) {
		if (subject == i->first) {
			i->first->removeObserver(shared_from_this());
			if (newExpr) {
				newExpr->addObserver(shared_from_this());
			}
			i->first = newExpr;
		} else if (subject == i->second && newBody) {
			i->second->removeObserver(shared_from_this());
			newBody->addObserver(shared_from_this());
			i->second = newBody;
		}
	}
}

void SwitchStmt::accept(Visitor *v) {
	v->visit(ucast<SwitchStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
