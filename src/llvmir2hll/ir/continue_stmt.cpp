/**
* @file src/llvmir2hll/ir/continue_stmt.cpp
* @brief Implementation of ContinueStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new continue statement.
*/
ContinueStmt::ContinueStmt(Address a)
	: Statement(Value::ValueKind::ContinueStmt, a) {}

Value* ContinueStmt::clone() {
	ContinueStmt* continueStmt(ContinueStmt::create(getAddress()));
	continueStmt->setMetadata(getMetadata());
	return continueStmt;
}

bool ContinueStmt::isEqualTo(Value* otherValue) const {
	return isa<ContinueStmt>(otherValue);
}

void ContinueStmt::replace(Expression* oldExpr, Expression* newExpr) {
	// There is nothing to do.
}

Expression* ContinueStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Creates a new continue statement.
* @param[in] a Address.
*/
ContinueStmt* ContinueStmt::create(Address a) {
	return new ContinueStmt(a);
}

void ContinueStmt::accept(Visitor *v) {
	v->visit(ucast<ContinueStmt>(this));
}

} // namespace llvmir2hll
} // namespace retdec
