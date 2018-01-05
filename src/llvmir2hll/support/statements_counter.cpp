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
* @brief Destructs the counter.
*/
StatementsCounter::~StatementsCounter() {}

/**
* @brief Returns the number of statements in @a block.
*
* @param[in] block Sequence of statements (possibly empty).
* @param[in] recursive Visit also nested statements (in compound statements)?
* @param[in] includeEmptyStmts Count also empty statements?
*/
unsigned StatementsCounter::count(ShPtr<Statement> block, bool recursive,
		bool includeEmptyStmts) {
	ShPtr<StatementsCounter> counter(new StatementsCounter());
	return counter->countInternal(block, recursive, includeEmptyStmts);
}

/**
* @brief Internal implementation of count().
*
* See the description of count() for more info.
*/
unsigned StatementsCounter::countInternal(ShPtr<Statement> block, bool recursive_,
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

void StatementsCounter::visit(ShPtr<GlobalVarDef> varDef) {
	FAIL("this function should never be called");
}

void StatementsCounter::visit(ShPtr<Function> func) {
	FAIL("this function should never be called");
}

void StatementsCounter::visit(ShPtr<Variable> var) {}

void StatementsCounter::visit(ShPtr<AddressOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<AssignOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<ArrayIndexOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<StructIndexOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<DerefOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<NotOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<NegOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<EqOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<NeqOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<LtEqOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<GtEqOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<LtOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<GtOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<AddOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<SubOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<MulOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<ModOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<DivOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<AndOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<OrOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<BitAndOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<BitOrOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<BitXorOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<BitShlOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<BitShrOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<TernaryOpExpr> expr) {}

void StatementsCounter::visit(ShPtr<CallExpr> expr) {}

void StatementsCounter::visit(ShPtr<CommaOpExpr> expr) {}

// Casts.
void StatementsCounter::visit(ShPtr<BitCastExpr> expr) { }

void StatementsCounter::visit(ShPtr<ExtCastExpr> expr) { }

void StatementsCounter::visit(ShPtr<TruncCastExpr> expr) { }

void StatementsCounter::visit(ShPtr<FPToIntCastExpr> expr) { }

void StatementsCounter::visit(ShPtr<IntToFPCastExpr> expr) { }

void StatementsCounter::visit(ShPtr<IntToPtrCastExpr> expr) { }

void StatementsCounter::visit(ShPtr<PtrToIntCastExpr> expr) { }
// End of casts

void StatementsCounter::visit(ShPtr<ConstBool> constant) {}

void StatementsCounter::visit(ShPtr<ConstFloat> constant) {}

void StatementsCounter::visit(ShPtr<ConstInt> constant) {}

void StatementsCounter::visit(ShPtr<ConstNullPointer> constant) {}

void StatementsCounter::visit(ShPtr<ConstString> constant) {}

void StatementsCounter::visit(ShPtr<ConstArray> constant) {}

void StatementsCounter::visit(ShPtr<ConstStruct> constant) {}

void StatementsCounter::visit(ShPtr<ConstSymbol> constant) {}

void StatementsCounter::visit(ShPtr<AssignStmt> stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<VarDefStmt> stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<CallStmt> stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<ReturnStmt> stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<EmptyStmt> stmt) {
	if (includeEmptyStmts) {
		numOfStmts++;
	}
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<IfStmt> stmt) {
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

void StatementsCounter::visit(ShPtr<SwitchStmt> stmt) {
	numOfStmts++;

	if (recursive) {
		// For each clause...
		for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
			visitStmt(i->second);
		}
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<WhileLoopStmt> stmt) {
	numOfStmts++;

	if (recursive) {
		visitStmt(stmt->getBody());
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<ForLoopStmt> stmt) {
	numOfStmts++;

	if (recursive) {
		visitStmt(stmt->getBody());
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<UForLoopStmt> stmt) {
	numOfStmts++;

	if (recursive) {
		visitStmt(stmt->getBody());
	}

	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<BreakStmt> stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<ContinueStmt> stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<GotoStmt> stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<UnreachableStmt> stmt) {
	numOfStmts++;
	visitStmt(stmt->getSuccessor());
}

void StatementsCounter::visit(ShPtr<FloatType> type) {}

void StatementsCounter::visit(ShPtr<IntType> type) {}

void StatementsCounter::visit(ShPtr<PointerType> type) {}

void StatementsCounter::visit(ShPtr<StringType> type) {}

void StatementsCounter::visit(ShPtr<ArrayType> type) {}

void StatementsCounter::visit(ShPtr<StructType> type) {}

void StatementsCounter::visit(ShPtr<VoidType> type) {}

void StatementsCounter::visit(ShPtr<UnknownType> type) {}

} // namespace llvmir2hll
} // namespace retdec
