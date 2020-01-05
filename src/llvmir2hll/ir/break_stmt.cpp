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

bool BreakStmt::isEqualTo(Value* otherValue) const {
	return isa<BreakStmt>(otherValue);
}

void BreakStmt::replace(Expression* oldExpr, Expression* newExpr) {
	// There is nothing to do.
}

Expression* BreakStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

Value* BreakStmt::clone() {
	BreakStmt* breakStmt(BreakStmt::create(getAddress()));
	breakStmt->setMetadata(getMetadata());
	return breakStmt;
}

/**
* @brief Creates a new break statement.
* @param[in] a Address.
*/
BreakStmt* BreakStmt::create(Address a) {
	return new BreakStmt(a);
}

void BreakStmt::accept(Visitor *v) {
	v->visit(ucast<BreakStmt>(this));
}

} // namespace llvmir2hll
} // namespace retdec
