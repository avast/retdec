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

/**
* @brief Constructs a new break statement.
*/
BreakStmt::BreakStmt() {}

/**
* @brief Destructs the statement.
*/
BreakStmt::~BreakStmt() {}

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
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	breakStmt->setMetadata(getMetadata());
	return breakStmt;
}

/**
* @brief Creates a new break statement.
*/
ShPtr<BreakStmt> BreakStmt::create() {
	return ShPtr<BreakStmt>(new BreakStmt());
}

void BreakStmt::accept(Visitor *v) {
	v->visit(ucast<BreakStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
