/**
* @file include/retdec/llvmir2hll/support/statements_counter.h
* @brief Counter of the number of statements in a block.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_STATEMENTS_COUNTER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_STATEMENTS_COUNTER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Counter of the number of statements in a block.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class StatementsCounter: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	static unsigned count(Statement* block, bool recursive = true,
		bool includeEmptyStmts = false);

private:
	StatementsCounter();

	unsigned countInternal(Statement* block, bool recursive,
		bool includeEmptyStmts);

	/// @name Visitor Interface
	/// @{
	virtual void visit(GlobalVarDef* varDef) override;
	virtual void visit(Function* func) override;
	virtual void visit(Variable* var) override;
	virtual void visit(AddressOpExpr* expr) override;
	virtual void visit(AssignOpExpr* expr) override;
	virtual void visit(ArrayIndexOpExpr* expr) override;
	virtual void visit(StructIndexOpExpr* expr) override;
	virtual void visit(DerefOpExpr* expr) override;
	virtual void visit(NotOpExpr* expr) override;
	virtual void visit(NegOpExpr* expr) override;
	virtual void visit(EqOpExpr* expr) override;
	virtual void visit(NeqOpExpr* expr) override;
	virtual void visit(LtEqOpExpr* expr) override;
	virtual void visit(GtEqOpExpr* expr) override;
	virtual void visit(LtOpExpr* expr) override;
	virtual void visit(GtOpExpr* expr) override;
	virtual void visit(AddOpExpr* expr) override;
	virtual void visit(SubOpExpr* expr) override;
	virtual void visit(MulOpExpr* expr) override;
	virtual void visit(ModOpExpr* expr) override;
	virtual void visit(DivOpExpr* expr) override;
	virtual void visit(AndOpExpr* expr) override;
	virtual void visit(OrOpExpr* expr) override;
	virtual void visit(BitAndOpExpr* expr) override;
	virtual void visit(BitOrOpExpr* expr) override;
	virtual void visit(BitXorOpExpr* expr) override;
	virtual void visit(BitShlOpExpr* expr) override;
	virtual void visit(BitShrOpExpr* expr) override;
	virtual void visit(TernaryOpExpr* expr) override;
	virtual void visit(CallExpr* expr) override;
	virtual void visit(CommaOpExpr* expr) override;
	virtual void visit(ConstBool* constant) override;
	virtual void visit(ConstFloat* constant) override;
	virtual void visit(ConstInt* constant) override;
	virtual void visit(ConstNullPointer* constant) override;
	virtual void visit(ConstString* constant) override;
	virtual void visit(ConstArray* constant) override;
	virtual void visit(ConstStruct* constant) override;
	virtual void visit(ConstSymbol* constant) override;
	virtual void visit(AssignStmt* stmt) override;
	virtual void visit(VarDefStmt* stmt) override;
	virtual void visit(CallStmt* stmt) override;
	virtual void visit(ReturnStmt* stmt) override;
	virtual void visit(EmptyStmt* stmt) override;
	virtual void visit(IfStmt* stmt) override;
	virtual void visit(SwitchStmt* stmt) override;
	virtual void visit(WhileLoopStmt* stmt) override;
	virtual void visit(ForLoopStmt* stmt) override;
	virtual void visit(UForLoopStmt* stmt) override;
	virtual void visit(BreakStmt* stmt) override;
	virtual void visit(ContinueStmt* stmt) override;
	virtual void visit(GotoStmt* stmt) override;
	virtual void visit(UnreachableStmt* stmt) override;
	// Types
	virtual void visit(FloatType* type) override;
	virtual void visit(IntType* type) override;
	virtual void visit(PointerType* type) override;
	virtual void visit(StringType* type) override;
	virtual void visit(ArrayType* type) override;
	virtual void visit(StructType* type) override;
	virtual void visit(VoidType* type) override;
	virtual void visit(UnknownType* type) override;
	// Casts
	virtual void visit(BitCastExpr* expr) override;
	virtual void visit(ExtCastExpr* expr) override;
	virtual void visit(TruncCastExpr* expr) override;
	virtual void visit(FPToIntCastExpr* expr) override;
	virtual void visit(IntToFPCastExpr* expr) override;
	virtual void visit(IntToPtrCastExpr* expr) override;
	virtual void visit(PtrToIntCastExpr* expr) override;
	/// @}

private:
	/// Counter of the number of statements.
	unsigned numOfStmts;

	/// Should we also visit nested statements (in compound statements)?
	bool recursive;

	/// Should we also count empty statements?
	bool includeEmptyStmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
