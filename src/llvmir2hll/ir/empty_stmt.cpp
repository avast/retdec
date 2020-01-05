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

Value* EmptyStmt::clone() {
	EmptyStmt* emptyStmt(EmptyStmt::create(nullptr, getAddress()));
	emptyStmt->setMetadata(getMetadata());
	return emptyStmt;
}

bool EmptyStmt::isEqualTo(Value* otherValue) const {
	return isa<EmptyStmt>(otherValue);
}

void EmptyStmt::replace(Expression* oldExpr, Expression* newExpr) {
	// There is nothing to do.
}

Expression* EmptyStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Creates a new empty statement.
*
* @param[in] succ Follower of the statement in the program flow.
* @param[in] a Address.
*/
EmptyStmt* EmptyStmt::create(Statement* succ, Address a) {
	EmptyStmt* stmt(new EmptyStmt(a));
	stmt->setSuccessor(succ);
	return stmt;
}

void EmptyStmt::accept(Visitor *v) {
	v->visit(ucast<EmptyStmt>(this));
}

} // namespace llvmir2hll
} // namespace retdec
