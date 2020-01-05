/**
* @file include/retdec/llvmir2hll/support/visitor_adapter.h
* @brief A visitor whose visit methods do nothing.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_VISITOR_ADAPTER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_VISITOR_ADAPTER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A visitor whose visit methods do nothing by default.
*
* Concrete visitors should:
*  - subclass this class
*  - override the needed functions from the Visitor base class (remember that
*    non-overridden functions have to brought to scope using the <tt>using
*    VisitorAdapter::visit;</tt> declaration; otherwise, they'll be hidden by
*    the overridden ones)
*
* Use this class as a base class when you want the Visitor functionality, but
* you don't want to provide the default implementation for visit functions that
* you don't use.
*/
class VisitorAdapter: public Visitor {
public:
	/// @name Visitor Interface
	/// @{
	virtual void visit(GlobalVarDef* varDef) override {}
	virtual void visit(Function* func) override {}
	// Statements
	virtual void visit(AssignStmt* stmt) override {}
	virtual void visit(BreakStmt* stmt) override {}
	virtual void visit(CallStmt* stmt) override {}
	virtual void visit(ContinueStmt* stmt) override {}
	virtual void visit(EmptyStmt* stmt) override {}
	virtual void visit(ForLoopStmt* stmt) override {}
	virtual void visit(UForLoopStmt* stmt) override {}
	virtual void visit(GotoStmt* stmt) override {}
	virtual void visit(IfStmt* stmt) override {}
	virtual void visit(ReturnStmt* stmt) override {}
	virtual void visit(SwitchStmt* stmt) override {}
	virtual void visit(UnreachableStmt* stmt) override {}
	virtual void visit(VarDefStmt* stmt) override {}
	virtual void visit(WhileLoopStmt* stmt) override {}
	// Expressions
	virtual void visit(AddOpExpr* expr) override {}
	virtual void visit(AddressOpExpr* expr) override {}
	virtual void visit(AssignOpExpr* expr) override {}
	virtual void visit(AndOpExpr* expr) override {}
	virtual void visit(ArrayIndexOpExpr* expr) override {}
	virtual void visit(BitAndOpExpr* expr) override {}
	virtual void visit(BitOrOpExpr* expr) override {}
	virtual void visit(BitShlOpExpr* expr) override {}
	virtual void visit(BitShrOpExpr* expr) override {}
	virtual void visit(BitXorOpExpr* expr) override {}
	virtual void visit(CallExpr* expr) override {}
	virtual void visit(CommaOpExpr* expr) override {}
	virtual void visit(DerefOpExpr* expr) override {}
	virtual void visit(DivOpExpr* expr) override {}
	virtual void visit(EqOpExpr* expr) override {}
	virtual void visit(GtEqOpExpr* expr) override {}
	virtual void visit(GtOpExpr* expr) override {}
	virtual void visit(LtEqOpExpr* expr) override {}
	virtual void visit(LtOpExpr* expr) override {}
	virtual void visit(ModOpExpr* expr) override {}
	virtual void visit(MulOpExpr* expr) override {}
	virtual void visit(NegOpExpr* expr) override {}
	virtual void visit(NeqOpExpr* expr) override {}
	virtual void visit(NotOpExpr* expr) override {}
	virtual void visit(OrOpExpr* expr) override {}
	virtual void visit(StructIndexOpExpr* expr) override {}
	virtual void visit(SubOpExpr* expr) override {}
	virtual void visit(TernaryOpExpr* expr) override {}
	virtual void visit(Variable* var) override {}
	// Casts
	virtual void visit(BitCastExpr* expr) override {}
	virtual void visit(ExtCastExpr* expr) override {}
	virtual void visit(FPToIntCastExpr* expr) override {}
	virtual void visit(IntToFPCastExpr* expr) override {}
	virtual void visit(IntToPtrCastExpr* expr) override {}
	virtual void visit(PtrToIntCastExpr* expr) override {}
	virtual void visit(TruncCastExpr* expr) override {}
	// Constants
	virtual void visit(ConstArray* constant) override {}
	virtual void visit(ConstBool* constant) override {}
	virtual void visit(ConstFloat* constant) override {}
	virtual void visit(ConstInt* constant) override {}
	virtual void visit(ConstNullPointer* constant) override {}
	virtual void visit(ConstString* constant) override {}
	virtual void visit(ConstStruct* constant) override {}
	virtual void visit(ConstSymbol* constant) override {}
	// Types
	virtual void visit(ArrayType* type) override {}
	virtual void visit(FloatType* type) override {}
	virtual void visit(IntType* type) override {}
	virtual void visit(PointerType* type) override {}
	virtual void visit(StringType* type) override {}
	virtual void visit(StructType* type) override {}
	virtual void visit(FunctionType* type) override {}
	virtual void visit(VoidType* type) override {}
	virtual void visit(UnknownType* type) override {}
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
