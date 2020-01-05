/**
* @file src/llvmir2hll/ir/unreachable_stmt.cpp
* @brief Implementation of UnreachableStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new unreachable statement.
*/
UnreachableStmt::UnreachableStmt(Address a): Statement(a) {}

Value* UnreachableStmt::clone() {
	UnreachableStmt* unreachableStmt(UnreachableStmt::create(getAddress()));
	unreachableStmt->setMetadata(getMetadata());
	return unreachableStmt;
}

bool UnreachableStmt::isEqualTo(Value* otherValue) const {
	return isa<UnreachableStmt>(otherValue);
}

void UnreachableStmt::replace(Expression* oldExpr, Expression* newExpr) {
	// There is nothing to do.
}

Expression* UnreachableStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

void UnreachableStmt::accept(Visitor *v) {
	v->visit(ucast<UnreachableStmt>(this));
}

UnreachableStmt* UnreachableStmt::create(Address a) {
	return new UnreachableStmt(a);
}

} // namespace llvmir2hll
} // namespace retdec
