/**
* @file src/llvmir2hll/analysis/written_into_globals_visitor.cpp
* @brief Implementation of WrittenIntoGlobalsVisitor.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/written_into_globals_visitor.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new visitor.
*
* @param[in] module The current module.
*
* @par Preconditions
*  - @a module is non-null
*/
WrittenIntoGlobalsVisitor::WrittenIntoGlobalsVisitor(Module* module):
	OrderedAllVisitor(), module(module), globalVars(module->getGlobalVars()),
			writtenIntoGlobals(), writing(false) {}

/*
* @brief Returns the set of all written-into variables in the given function.
*
* @param[in] func The given function.
* @param[in] module Module in which @a func is.
*
* @par Preconditions
*  - both @a func and @a module are non-null
*/
VarSet WrittenIntoGlobalsVisitor::getWrittenIntoGlobals(Function* func,
		Module* module) {
	PRECONDITION_NON_NULL(func);
	PRECONDITION_NON_NULL(module);

	WrittenIntoGlobalsVisitor* visitor(new WrittenIntoGlobalsVisitor(
		module));
	func->accept(visitor);
	return visitor->writtenIntoGlobals;
}

void WrittenIntoGlobalsVisitor::visit(Variable* var) {
	if (writing && hasItem(globalVars, var)) {
		writtenIntoGlobals.insert(var);
	}
}

void WrittenIntoGlobalsVisitor::visit(ArrayIndexOpExpr* expr) {
	// We consider a in a[1] = 5 to be just read (not written). To this end, we
	// now can stop the computation since inside the indexed expression, there
	// can be only read variables.
}

void WrittenIntoGlobalsVisitor::visit(StructIndexOpExpr* expr) {
	// We consider a in a['1'] = 5 to be just read (not written). To this end,
	// we now can stop the computation since inside the indexed expression,
	// there can be only read variables.
}

void WrittenIntoGlobalsVisitor::visit(DerefOpExpr* expr) {
	// We consider a in *a = 5 to be just read (not written). To this end, we
	// now can stop the computation since inside the dereferenced expression,
	// there can be only read variables.
}

void WrittenIntoGlobalsVisitor::visit(AssignStmt* stmt) {
	writing = true;
	stmt->getLhs()->accept(this);
	writing = false;
	// We do not have to traverse the right-hand side since there may be only
	// read variables.
	visitStmt(stmt->getSuccessor());
}

void WrittenIntoGlobalsVisitor::visit(VarDefStmt* stmt) {
	writing = true;
	stmt->getVar()->accept(this);
	writing = false;
	// We do not have to traverse the right-hand side since there may be only
	// read variables.
	visitStmt(stmt->getSuccessor());
}

void WrittenIntoGlobalsVisitor::visit(ForLoopStmt* stmt) {
	writing = true;
	stmt->getIndVar()->accept(this);
	writing = false;
	// We do not have to traverse the other operands, like the start value and
	// the end value, because there may be only read variables.
	visitStmt(stmt->getBody());
	visitStmt(stmt->getSuccessor());
}

} // namespace llvmir2hll
} // namespace retdec
