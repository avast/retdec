/**
* @file src/llvmir2hll/ir/empty_stmt.cpp
* @brief Implementation of EmptyStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new empty statement.
*
* See create() for more information.
*/
EmptyStmt::EmptyStmt() {}

/**
* @brief Destructs the statement.
*/
EmptyStmt::~EmptyStmt() {}

ShPtr<Value> EmptyStmt::clone() {
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
	emptyStmt->setMetadata(getMetadata());
	return emptyStmt;
}

bool EmptyStmt::isEqualTo(ShPtr<Value> otherValue) const {
	return isa<EmptyStmt>(otherValue);
}

void EmptyStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	// There is nothing to do.
}

ShPtr<Expression> EmptyStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Creates a new empty statement.
*
* @param[in] succ Follower of the statement in the program flow.
*/
ShPtr<EmptyStmt> EmptyStmt::create(ShPtr<Statement> succ) {
	ShPtr<EmptyStmt> stmt(new EmptyStmt());
	stmt->setSuccessor(succ);
	return stmt;
}

void EmptyStmt::accept(Visitor *v) {
	v->visit(ucast<EmptyStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
