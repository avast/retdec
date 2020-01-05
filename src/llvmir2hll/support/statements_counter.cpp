/**
* @file src/llvmir2hll/support/statements_counter.cpp
* @brief Implementation of StatementsCounter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/statements_counter.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new statements counter.
*/
StatementsCounter::StatementsCounter(): OrderedAllVisitor(),
	numOfStmts(0), recursive(true), includeEmptyStmts(false) {}

/**
* @brief Returns the number of statements in @a block.
*
* @param[in] block Sequence of statements (possibly empty).
* @param[in] recursive Visit also nested statements (in compound statements)?
* @param[in] includeEmptyStmts Count also empty statements?
*/
unsigned StatementsCounter::count(Statement* block, bool recursive,
		bool includeEmptyStmts) {
	StatementsCounter* counter(new StatementsCounter());
	return counter->countInternal(block, recursive, includeEmptyStmts);
}

/**
* @brief Internal implementation of count().
*
* See the description of count() for more info.
*/
unsigned StatementsCounter::countInternal(Statement* block, bool recursive_,
		bool includeEmptyStmts_) {
	if (!block) {
		return 0;
	}

	numOfStmts = 0;
	recursive = recursive_;
	includeEmptyStmts = includeEmptyStmts_;
	OrderedAllVisitor::visitStmt(block);
	return numOfStmts;
}

void StatementsCounter::visit(GlobalVarDef* varDef) {
	FAIL("this function should never be called");
}

void StatementsCounter::visit(Function* func) {
	FAIL("this function should never be called");
}

void StatementsCounter::visit(Variable* var) {}

void StatementsCounter::visit(AddressOpExpr* expr) {}

void StatementsCounter::visit(AssignOpExpr* expr) {}

void StatementsCounter::visit(ArrayIndexOpExpr* expr) {}

void StatementsCounter::visit(StructIndexOpExpr* expr) {}

void StatementsCounter::visit(DerefOpExpr* expr) {}

void StatementsCounter::visit(NotOpExpr* expr) {}

void StatementsCounter::visit(NegOpExpr* expr) {}

void StatementsCounter::visit(EqOpExpr* expr) {}

void StatementsCounter::visit(NeqOpExpr* expr) {}

void StatementsCounter::visit(LtEqOpExpr* expr) {}

void StatementsCounter::visit(GtEqOpExpr* expr) {}

void StatementsCounter::visit(LtOpExpr* expr) {}

void StatementsCounter::visit(GtOpExpr* expr) {}

void StatementsCounter::visit(AddOpExpr* expr) {}

void StatementsCounter::visit(SubOpExpr* expr) {}

void StatementsCounter::visit(MulOpExpr* expr) {}

void StatementsCounter::visit(ModOpExpr* expr) {}

void StatementsCounter::visit(DivOpExpr* expr) {}

void StatementsCounter::visit(AndOpExpr* expr) {}

void StatementsCounter::visit(OrOpExpr* expr) {}

void StatementsCounter::visit(BitAndOpExpr* expr) {}

void StatementsCounter::visit(BitOrOpExpr* expr) {}

void StatementsCounter::visit(BitXorOpExpr* expr) {}

void StatementsCounter::visit(BitShlOpExpr* expr) {}

void StatementsCounter::visit(BitShrOpExpr* expr) {}

void StatementsCounter::visit(TernaryOpExpr* expr) {}

void StatementsCounter::visit(CallExpr* expr) {}

void StatementsCounter::visit(CommaOpExpr* expr) {}

// Casts.
void StatementsCounter::visit(BitCastExpr* expr) { }

void StatementsCounter::visit(ExtCastExpr* expr) { }

void StatementsCounter::visit(TruncCastExpr* expr) { }

void StatementsCounter::visit(FPToIntCastExpr* expr) { }

void StatementsCounter::visit(IntToFPCastExpr* expr) { }

void StatementsCounter::visit(IntToPtrCastExpr* expr) { }

void StatementsCounter::visit(PtrToIntCastExpr* expr) { }
// End of casts

void StatementsCounter::visit(ConstBool* constant) {}

void StatementsCounter::visit(ConstFloat* constant) {}

void StatementsCounter::visit(ConstInt* constant) {}

void StatementsCounter::visit(ConstNullPointer* constant) {}

void StatementsCounter::visit(ConstString* constant) {}

void StatementsCounter::visit(ConstArray* constant) {}

void StatementsCounter::visit(ConstStruct* constant) {}

void StatementsCounter::visit(ConstSymbol* constant) {}

void StatementsCounter::visit(AssignStmt* stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(VarDefStmt* stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(CallStmt* stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ReturnStmt* stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(EmptyStmt* stmt) {
	if (includeEmptyStmts) {
		numOfStmts++;
	}
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(IfStmt* stmt) {
	numOfStmts++;

	if (recursive) {
		// For each clause...
		for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
			visitStmt(i->second);
		}
		visitStmt(stmt->getElseClause());
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(SwitchStmt* stmt) {
	numOfStmts++;

	if (recursive) {
		// For each clause...
		for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
			visitStmt(i->second);
		}
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(WhileLoopStmt* stmt) {
	numOfStmts++;

	if (recursive) {
		visitStmt(stmt->getBody());
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ForLoopStmt* stmt) {
	numOfStmts++;

	if (recursive) {
		visitStmt(stmt->getBody());
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(UForLoopStmt* stmt) {
	numOfStmts++;

	if (recursive) {
		visitStmt(stmt->getBody());
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(BreakStmt* stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ContinueStmt* stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(GotoStmt* stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(UnreachableStmt* stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(FloatType* type) {}

void StatementsCounter::visit(IntType* type) {}

void StatementsCounter::visit(PointerType* type) {}

void StatementsCounter::visit(StringType* type) {}

void StatementsCounter::visit(ArrayType* type) {}

void StatementsCounter::visit(StructType* type) {}

void StatementsCounter::visit(VoidType* type) {}

void StatementsCounter::visit(UnknownType* type) {}

} // namespace llvmir2hll
} // namespace retdec
