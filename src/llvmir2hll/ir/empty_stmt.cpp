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

EmptyStmt::EmptyStmt(Address a) : Statement(a) {}

ShPtr<Value> EmptyStmt::clone() {
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create(nullptr, getAddress()));
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
* @param[in] a Address.
*/
ShPtr<EmptyStmt> EmptyStmt::create(ShPtr<Statement> succ, Address a) {
	ShPtr<EmptyStmt> stmt(new EmptyStmt(a));
	stmt->setSuccessor(succ);
	return stmt;
}

void EmptyStmt::accept(Visitor *v) {
	v->visit(ucast<EmptyStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
