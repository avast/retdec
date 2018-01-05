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
UnreachableStmt::UnreachableStmt() {}

/**
* @brief Destructs the statement.
*/
UnreachableStmt::~UnreachableStmt() {}

ShPtr<Value> UnreachableStmt::clone() {
	ShPtr<UnreachableStmt> unreachableStmt(UnreachableStmt::create());
	unreachableStmt->setMetadata(getMetadata());
	return unreachableStmt;
}

bool UnreachableStmt::isEqualTo(ShPtr<Value> otherValue) const {
	return isa<UnreachableStmt>(otherValue);
}

void UnreachableStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	// There is nothing to do.
}

ShPtr<Expression> UnreachableStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

void UnreachableStmt::accept(Visitor *v) {
	v->visit(ucast<UnreachableStmt>(shared_from_this()));
}

ShPtr<UnreachableStmt> UnreachableStmt::create() {
	return ShPtr<UnreachableStmt>(new UnreachableStmt());
}

} // namespace llvmir2hll
} // namespace retdec
