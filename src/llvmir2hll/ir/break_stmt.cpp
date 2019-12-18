/**
* @file src/llvmir2hll/ir/break_stmt.cpp
* @brief Implementation of BreakStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

BreakStmt::BreakStmt(Address a) : Statement(a) {}

bool BreakStmt::isEqualTo(ShPtr<Value> otherValue) const {
	return isa<BreakStmt>(otherValue);
}

void BreakStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	// There is nothing to do.
}

ShPtr<Expression> BreakStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

ShPtr<Value> BreakStmt::clone() {
	ShPtr<BreakStmt> breakStmt(BreakStmt::create(getAddress()));
	breakStmt->setMetadata(getMetadata());
	return breakStmt;
}

/**
* @brief Creates a new break statement.
* @param[in] a Address.
*/
ShPtr<BreakStmt> BreakStmt::create(Address a) {
	return ShPtr<BreakStmt>(new BreakStmt(a));
}

void BreakStmt::accept(Visitor *v) {
	v->visit(ucast<BreakStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
