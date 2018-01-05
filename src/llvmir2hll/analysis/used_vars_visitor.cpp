/**
* @file src/llvmir2hll/analysis/used_vars_visitor.cpp
* @brief Implementation of UsedVarsVisitor.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/used_vars_visitor.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new UsedVars object.
*/
UsedVars::UsedVars(): readVars(), writtenVars(), allVars(), numOfVarUses() {}

/**
* @brief Constructs a new UsedVars object from @a other.
*/
UsedVars::UsedVars(const UsedVars &other) = default;

/**
* @brief Destructs the object.
*/
UsedVars::~UsedVars() {}

/**
* @brief Assigns @a other to the current object.
*/
UsedVars &UsedVars::operator=(const UsedVars &other) = default;

/**
* @brief Returns @c true if the current object is equal to @a other, @c false
*        otherwise.
*/
bool UsedVars::operator==(const UsedVars &other) const {
	return (readVars == other.readVars &&
		writtenVars == other.writtenVars &&
		allVars == other.allVars &&
		numOfVarUses == other.numOfVarUses);
}

/**
* @brief Returns @c true if the current object is not equal to @a other, @c
*        false otherwise.
*/
bool UsedVars::operator!=(const UsedVars &other) const {
	return !(*this == other);
}

/**
* @brief Returns the variables that are read.
*/
VarSet UsedVars::getReadVars() const {
	return readVars;
}

/**
* @brief Returns the variables that are written into.
*/
VarSet UsedVars::getWrittenVars() const {
	return writtenVars;
}

/**
* @brief Returns read variables merged with written-into variables.
*/
VarSet UsedVars::getAllVars() const {
	return allVars;
}

/**
* @brief Returns the number of used variables.
*
* @param[in] read Include the number of variables that are read.
* @param[in] written Include the number of written-into variables.
*
* If a variable is both read and written, it is counted only once.
*/
std::size_t UsedVars::getCount(bool read, bool written) const {
	if (read && !written) {
		return readVars.size();
	}
	if (written && !read) {
		return writtenVars.size();
	}
	return allVars.size();
}

/**
* @brief Returns the number of uses of @a var.
*
* @par Preconditions
*  - @a var is non-null
*/
std::size_t UsedVars::getNumOfUses(ShPtr<Variable> var) const {
	PRECONDITION_NON_NULL(var);

	auto i = numOfVarUses.find(var);
	if (i != numOfVarUses.end()) {
		return i->second;
	}
	// The given variable doesn't exist, so it doesn't have any use.
	return 0;
}

/**
* @brief Returns an iterator to the first read variable.
*/
UsedVars::var_iterator UsedVars::read_begin() const {
	return readVars.begin();
}

/**
* @brief Returns an iterator past the last read variable.
*/
UsedVars::var_iterator UsedVars::read_end() const {
	return readVars.end();
}

/**
* @brief Returns an iterator to the first written variable.
*/
UsedVars::var_iterator UsedVars::written_begin() const {
	return writtenVars.begin();
}

/**
* @brief Returns an iterator past the last written variable.
*/
UsedVars::var_iterator UsedVars::written_end() const {
	return writtenVars.end();
}

/**
* @brief Returns an iterator to the first variable.
*/
UsedVars::var_iterator UsedVars::all_begin() const {
	return allVars.begin();
}

/**
* @brief Returns an iterator past the last variable.
*/
UsedVars::var_iterator UsedVars::all_end() const {
	return allVars.end();
}

/**
* @brief Returns @c true if @a var is used, @c false otherwise.
*
* @param[in] var Variable that is looked up.
* @param[in] read Consider variables that are read.
* @param[in] written Consider written-into variables.
*/
bool UsedVars::isUsed(ShPtr<Variable> var, bool read,
		bool written) const {
	if (read && readVars.find(var) != readVars.end()) {
		return true;
	}
	if (written && writtenVars.find(var) != writtenVars.end()) {
		return true;
	}
	return false;
}

/**
* @brief Clears all private containers.
*/
void UsedVars::clear() {
	readVars.clear();
	writtenVars.clear();
	allVars.clear();
	numOfVarUses.clear();
}

/**
* @brief Constructs a new visitor.
*
* See the description of create() for more information.
*/
UsedVarsVisitor::UsedVarsVisitor(bool visitSuccessors, bool visitNestedStmts,
		bool enableCaching):
	OrderedAllVisitor(), Caching(enableCaching), usedVars(),
	writing(false), visitSuccessors(visitSuccessors), visitNestedStmts(visitNestedStmts)
	{}

/**
* @brief Destructs the visitor.
*/
UsedVarsVisitor::~UsedVarsVisitor() {}

/*
* @brief Returns the set of used variables in the given value.
*
* @param[in] value Searched value.
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<UsedVars> UsedVarsVisitor::getUsedVars_(ShPtr<Value> value) {
	PRECONDITION_NON_NULL(value);

	// Caching.
	if (getCachedResult(value, usedVars)) {
		return usedVars;
	}

	// Initialization.
	accessedStmts.clear();
	usedVars = ShPtr<UsedVars>(new UsedVars());
	writing = false;

	// Obtain read and written-into variables.
	if (ShPtr<Statement> block = cast<Statement>(value)) {
		visitStmt(block, visitSuccessors, visitNestedStmts);
	} else {
		value->accept(this);
	}

	// Merge them into the set of all variables.
	addToSet(usedVars->readVars, usedVars->allVars);
	addToSet(usedVars->writtenVars, usedVars->allVars);

	// Caching.
	addToCache(value, usedVars);

	return usedVars;
}

/*
* @brief Creates a new visitor.
*
* @param[in] visitSuccessors If @c true, used variables are obtained
*                            also from successors of statements.
* @param[in] visitNestedStmts If @c true, used variables are obtained also
*                             from nested statements, e.g. from loop, if, and
*                             switch statement's bodies.
* @param[in] enableCaching If @c true, it caches the results returned by getUsedVars_()
*                          until restartCache() or disableCaching() is called.
*                          This may speed up subsequent calls to getUsedVars_()
*                          if the same values are passed to getUsedVars_().
*/
ShPtr<UsedVarsVisitor> UsedVarsVisitor::create(bool visitSuccessors,
		bool visitNestedStmts, bool enableCaching) {
	return ShPtr<UsedVarsVisitor>(new UsedVarsVisitor(visitSuccessors,
		visitNestedStmts, enableCaching));
}

/**
* @brief Returns the set of used variables in the given value.
*
* @param[in] value Searched value.
* @param[in] visitSuccessors If @c true and @a value is a statement,
*                            it obtains used variables also from successive
*                            statements, i.e. it searches through the whole
*                            block (@a value is then the first statement in the
*                            block).
* @param[in] visitNestedStmts If @c true, used variables are obtained also
*                             from nested statements, e.g. from loop, if, and
*                             switch statement's bodies.
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<UsedVars> UsedVarsVisitor::getUsedVars(ShPtr<Value> value,
		bool visitSuccessors, bool visitNestedStmts) {
	PRECONDITION_NON_NULL(value);

	ShPtr<UsedVarsVisitor> visitor(new UsedVarsVisitor(visitSuccessors,
		visitNestedStmts));
	return visitor->getUsedVars_(value);
}

void UsedVarsVisitor::visit(ShPtr<Function> func) {
	if (func->isDefinition()) {
		visitStmt(func->getBody());
	}
}

void UsedVarsVisitor::visit(ShPtr<Variable> var) {
	if (writing) {
		usedVars->writtenVars.insert(var);
	} else {
		usedVars->readVars.insert(var);
	}

	usedVars->numOfVarUses[var]++;
}

void UsedVarsVisitor::visit(ShPtr<ArrayIndexOpExpr> expr) {
	// We consider a in a[1] = 5 to be just read (not written). This allows a
	// much simpler implementation of various optimizations.
	bool oldWriting = writing;
	writing = false;
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
	writing = oldWriting;
}

void UsedVarsVisitor::visit(ShPtr<StructIndexOpExpr> expr) {
	// We consider a in a['1'] = 5 to be just read (not written). This allows a
	// much simpler implementation of various optimizations.
	bool oldWriting = writing;
	writing = false;
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
	writing = oldWriting;
}

void UsedVarsVisitor::visit(ShPtr<DerefOpExpr> expr) {
	// We consider a in *a = 5 to be just read (not written). This allows a
	// much simpler implementation of various optimizations.
	bool oldWriting = writing;
	writing = false;
	expr->getOperand()->accept(this);
	writing = oldWriting;
}

void UsedVarsVisitor::visit(ShPtr<AssignStmt> stmt) {
	writing = true;
	stmt->getLhs()->accept(this);
	writing = false;
	stmt->getRhs()->accept(this);

	if (visitSuccessors) {
		visitStmt(stmt->getSuccessor());
	}
}

void UsedVarsVisitor::visit(ShPtr<VarDefStmt> stmt) {
	writing = true;
	stmt->getVar()->accept(this);
	writing = false;
	if (ShPtr<Expression> init = stmt->getInitializer()) {
		init->accept(this);
	}

	if (visitSuccessors) {
		visitStmt(stmt->getSuccessor());
	}
}

void UsedVarsVisitor::visit(ShPtr<ForLoopStmt> stmt) {
	writing = true;
	stmt->getIndVar()->accept(this);
	writing = false;
	stmt->getStartValue()->accept(this);
	stmt->getEndCond()->accept(this);
	stmt->getStep()->accept(this);
	if (visitNestedStmts) {
		visitStmt(stmt->getBody());
	}
	if (visitSuccessors) {
		visitStmt(stmt->getSuccessor());
	}
}

} // namespace llvmir2hll
} // namespace retdec
