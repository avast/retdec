/**
* @file src/llvmir2hll/ir/if_stmt.cpp
* @brief Implementation of IfStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new if/else-if/else statement.
*
* See create() for more information.
*/
IfStmt::IfStmt(ShPtr<Expression> cond, ShPtr<Statement> body):
		ifClauseList{IfClause(cond, body)}, elseClause() {}

/**
* @brief Destructs the statement.
*/
IfStmt::~IfStmt() {}

ShPtr<Value> IfStmt::clone() {
	ShPtr<IfStmt> ifStmt(IfStmt::create(
		ucast<Expression>(ifClauseList.front().first->clone()),
		ucast<Statement>(ifClauseList.front().second->clone())));
	if (elseClause) {
		ifStmt->setElseClause(
			ucast<Statement>(elseClause->clone()));
	}

	// Clone all other clauses.
	for (const auto &clause : ifClauseList) {
		// The first clause has already been cloned, so skip it.
		if (clause == ifClauseList.front()) {
			continue;
		}
		ifStmt->addClause(
			ucast<Expression>(clause.first->clone()),
			ucast<Statement>(clause.second->clone()));
	}

	ifStmt->setMetadata(getMetadata());
	return ifStmt;
}

bool IfStmt::isEqualTo(ShPtr<Value> otherValue) const {
	// The types of compared instances have to match.
	ShPtr<IfStmt> otherIfStmt = cast<IfStmt>(otherValue);
	if (!otherIfStmt) {
		return false;
	}

	// The number of 'if' clauses have to match.
	if (ifClauseList.size() != otherIfStmt->ifClauseList.size()) {
		return false;
	}

	// All 'if' clauses have to match.
	for (auto i = clause_begin(), j = otherIfStmt->clause_begin(),
			e = clause_end(); i != e; ++i, ++j) {
		if (!(i->first->isEqualTo(j->first) &&
				i->second->isEqualTo(j->second))) {
			return false;
		}
	}

	// The else clauses have to match.
	if (hasElseClause()) {
		return otherIfStmt->hasElseClause() &&
			elseClause->isEqualTo(otherIfStmt->elseClause);
	}
	// The first if statement doesn't have an else clause, so the other if
	// statement should also not have one.
	return !otherIfStmt->hasElseClause();
}

void IfStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	// For each clause...
	for (auto &clause : ifClauseList) {
		if (clause.first == oldExpr) {
			clause.first->removeObserver(shared_from_this());
			newExpr->addObserver(shared_from_this());
			clause.first = newExpr;
		} else {
			clause.first->replace(oldExpr, newExpr);
		}
	}
}

ShPtr<Expression> IfStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Adds a new clause (`[else] if cond then body`).
*
* @param[in] cond Clause condition.
* @param[in] body Clause body.
*
* If there are no clauses, the added clause is the if clause; otherwise, it is
* an else-if clause.
*
* Does not invalidate any existing iterators to this if statement.
*
* @par Preconditions
*  - both arguments are non-null
*/
void IfStmt::addClause(ShPtr<Expression> cond, ShPtr<Statement> body) {
	PRECONDITION_NON_NULL(cond);
	PRECONDITION_NON_NULL(body);

	body->removePredecessors(true);
	cond->addObserver(shared_from_this());
	body->addObserver(shared_from_this());
	ifClauseList.push_back(IfClause(cond, body));
}

/**
* @brief Returns @c true if there is at least one else-if clause, @c false
*        otherwise.
*
* An else-if clause is a clause which is not the main if's clause or the else
* clause.
*/
bool IfStmt::hasElseIfClauses() const {
	return ifClauseList.size() > 1;
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
* clause_iterator i(ifStmt->clause_begin());
* while (i != ifStmt->clause_end()) {
*     if (condition) {
*         i = ifStmt->removeClause(i);
*     } else {
*         ++i;
*     }
* }
* @endcode
*
* You cannot remove the else clause by this function; use removeElseClause()
* instead.
*
* If you remove the only clause of the statement, then the statement becomes a
* statement without any clauses. Such a statement is useless.
*
* @par Preconditions
*  - the passed iterator is valid
*/
IfStmt::clause_iterator IfStmt::removeClause(clause_iterator clauseIterator) {
	// We assume that the used container is std::list.
	clauseIterator->first->removeObserver(shared_from_this());
	clauseIterator->second->removeObserver(shared_from_this());
	return ifClauseList.erase(clauseIterator);
}

/**
* @brief Returns @c true if there is at least one clause, @c false otherwise.
*
* This function takes into account all the types of clauses: the if clause,
* else-if clauses, and the else clause (if any).
*/
bool IfStmt::hasClauses() const {
	return !ifClauseList.empty() || elseClause;
}

/**
* @brief Returns @c true if the statement has the if clause, @c false otherwise.
*
* Note that if this function returns @c false, then the statement is most
* probably not valid (every if statement should have an if clause).
*/
bool IfStmt::hasIfClause() const {
	return !ifClauseList.empty();
}

/**
* @brief Sets the else clause (`else body`).
*
* @param[in] body Clause body.
*
* If @a body is the null pointer, then there is no else clause.
*/
void IfStmt::setElseClause(ShPtr<Statement> body) {
	if (hasElseClause()) {
		elseClause->removeObserver(shared_from_this());
	}
	if (body) {
		body->removePredecessors(true);
		body->addObserver(shared_from_this());
	}
	elseClause = body;
}

/**
* @brief Removes the else clause (if any).
*
* Calling this function is the same as calling @c
* setElseClause(ShPtr<Statement>()).
*/
void IfStmt::removeElseClause() {
	setElseClause(ShPtr<Statement>());
}

/**
* @brief Returns @c true if this if statement has an else clause, @c false
* otherwise.
*/
bool IfStmt::hasElseClause() const {
	return elseClause != nullptr;
}

/**
* @brief Returns an iterator to the first if clause (`if cond then body`).
*
* Use getElseClause() to obtain the else clause (it cannot be accessed by
* iterators).
*/
IfStmt::clause_iterator IfStmt::clause_begin() const {
	return ifClauseList.begin();
}

/**
* @brief Returns an iterator past the last else-if clause.
*
* Use getElseClause() to obtain the else clause (it cannot be accessed by
* iterators).
*/
IfStmt::clause_iterator IfStmt::clause_end() const {
	return ifClauseList.end();
}

/**
* @brief Returns the else clause (if any), the null pointer otherwise.
*/
ShPtr<Statement> IfStmt::getElseClause() const {
	return elseClause;
}

/**
* @brief Constructs a new if statement.
*
* @param[in] cond Statement condition.
* @param[in] body Statement body.
* @param[in] succ Follower of the statement in the program flow.
*
* @par Preconditions
*  - @a cond and @a body are non-null
*/
ShPtr<IfStmt> IfStmt::create(ShPtr<Expression> cond, ShPtr<Statement> body,
			ShPtr<Statement> succ) {
	PRECONDITION_NON_NULL(cond);
	PRECONDITION_NON_NULL(body);

	ShPtr<IfStmt> stmt(new IfStmt(cond, body));
	stmt->setSuccessor(succ);

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	cond->addObserver(stmt);
	body->addObserver(stmt);
	body->removePredecessors(true);

	return stmt;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @a arg. For example, if @a subject is the conditions
* of some if-clause, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any part of the statement
*  - @a arg is not a statement/expression
*
* @par Preconditions
*  - @a subject is non-null
*  - when @a subject is a condition or a body of an if-clause, @a arg has to be
*    non-null
*
* @see Subject::update()
*/
void IfStmt::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);

	// Check all if/else-if clauses.
	ShPtr<Expression> newCond = cast<Expression>(arg);
	ShPtr<Statement> newBody = cast<Statement>(arg);
	for (auto &clause : ifClauseList) {
		// TODO Refactor the handling of observers into a separate function
		// after methods for updating if-else clauses are implemented.
		if (subject == clause.first && newCond) {
			clause.first->removeObserver(shared_from_this());
			newCond->addObserver(shared_from_this());
			clause.first = newCond;
		} else if (subject == clause.second && newBody) {
			clause.second->removeObserver(shared_from_this());
			newBody->addObserver(shared_from_this());
			clause.second = newBody;
		}
	}

	// Check the else clause.
	if (hasElseClause() && subject == elseClause && (!arg || newBody)) {
		setElseClause(newBody);
		return;
	}
}

void IfStmt::accept(Visitor *v) {
	v->visit(ucast<IfStmt>(shared_from_this()));
}

/**
* @brief Returns the condition of the first if clause in the statement.
*
* If there are no if clauses, the null pointer is returned.
*/
ShPtr<Expression> IfStmt::getFirstIfCond() const {
	if (ifClauseList.empty()) {
		return ShPtr<Expression>();
	}
	return clause_begin()->first;
}

/**
* @brief Returns the body of the first if clause in the statement.
*
* If there are no if clauses, the null pointer is returned.
*/
ShPtr<Statement> IfStmt::getFirstIfBody() const {
	if (ifClauseList.empty()) {
		return ShPtr<Statement>();
	}
	return clause_begin()->second;
}

/**
* @brief Sets a new condition of the first if clause.
*
* @par Preconditions
*  - @a newCond is non-null
*/
void IfStmt::setFirstIfCond(ShPtr<Expression> newCond) {
	PRECONDITION_NON_NULL(newCond);

	ifClauseList.begin()->first->removeObserver(shared_from_this());
	newCond->addObserver(shared_from_this());
	*ifClauseList.begin() = IfClause(newCond, ifClauseList.begin()->second);
}

/**
* @brief Sets a new body of the first if clause.
*
* @par Preconditions
*  - @a newBody is non-null
*/
void IfStmt::setFirstIfBody(ShPtr<Statement> newBody) {
	PRECONDITION_NON_NULL(newBody);

	ifClauseList.begin()->second->removeObserver(shared_from_this());
	newBody->addObserver(shared_from_this());
	newBody->removePredecessors(true);
	*ifClauseList.begin() = IfClause(ifClauseList.begin()->first, newBody);
}

} // namespace llvmir2hll
} // namespace retdec
