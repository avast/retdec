/**
* @file include/retdec/llvmir2hll/support/visitors/ordered_all_visitor.h
* @brief A visitor that visits everything in an ordered way.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_VISITORS_ORDERED_ALL_VISITOR_H
#define RETDEC_LLVMIR2HLL_SUPPORT_VISITORS_ORDERED_ALL_VISITOR_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A visitor that visits everything in an ordered way.
*
* Concrete visitors should:
*  - subclass this class
*  - override the needed functions from the Visitor base class (remember that
*    non-overridden functions have to brought to scope using the <tt>using
*    OrderedAllVisitor::visit;</tt> declaration; otherwise, they'll be hidden by
*    the overridden ones)
*  - add every accessed statement to the @c accessedStmts set to avoid looping
*    over the same statements. Also, when a statement is accessed, it should
*    check this set before accessing any of its "nested statements". For example,
*    an if statement should check whether its body has already been accessed or
*    not. visitStmt() takes care of that, so you can use it to visit statements
*    (blocks).
*  - add every accessed type to the @c accessedTypes set to avoid looping
*    over the same types. Also, when a type is accessed, it should
*    check this set before accessing any of its "nested types".
*  - remember that whenever you override some visit() function which takes a
*    statement as its parameter, you have to manually call @code
*    visitStmt(stmt->getSuccessor()) @endcode to visit its (possible) successor.
*
* Instances of this class have reference object semantics.
*
* By default, the functions from the Visitor interface go through all
* statements and expressions, calling @c value->accept(this) on each value.
*/
class OrderedAllVisitor: public Visitor {
public:
	/// @name Visitor Interface
	/// @{
	virtual void visit(GlobalVarDef* varDef) override;
	virtual void visit(Function* func) override;
	// Statements
	virtual void visit(AssignStmt* stmt) override;
	virtual void visit(BreakStmt* stmt) override;
	virtual void visit(CallStmt* stmt) override;
	virtual void visit(ContinueStmt* stmt) override;
	virtual void visit(EmptyStmt* stmt) override;
	virtual void visit(ForLoopStmt* stmt) override;
	virtual void visit(UForLoopStmt* stmt) override;
	virtual void visit(GotoStmt* stmt) override;
	virtual void visit(IfStmt* stmt) override;
	virtual void visit(ReturnStmt* stmt) override;
	virtual void visit(SwitchStmt* stmt) override;
	virtual void visit(UnreachableStmt* stmt) override;
	virtual void visit(VarDefStmt* stmt) override;
	virtual void visit(WhileLoopStmt* stmt) override;
	// Expressions
	virtual void visit(AddOpExpr* expr) override;
	virtual void visit(AddressOpExpr* expr) override;
	virtual void visit(AndOpExpr* expr) override;
	virtual void visit(ArrayIndexOpExpr* expr) override;
	virtual void visit(AssignOpExpr* expr) override;
	virtual void visit(BitAndOpExpr* expr) override;
	virtual void visit(BitOrOpExpr* expr) override;
	virtual void visit(BitShlOpExpr* expr) override;
	virtual void visit(BitShrOpExpr* expr) override;
	virtual void visit(BitXorOpExpr* expr) override;
	virtual void visit(CallExpr* expr) override;
	virtual void visit(CommaOpExpr* expr) override;
	virtual void visit(DerefOpExpr* expr) override;
	virtual void visit(DivOpExpr* expr) override;
	virtual void visit(EqOpExpr* expr) override;
	virtual void visit(GtEqOpExpr* expr) override;
	virtual void visit(GtOpExpr* expr) override;
	virtual void visit(LtEqOpExpr* expr) override;
	virtual void visit(LtOpExpr* expr) override;
	virtual void visit(ModOpExpr* expr) override;
	virtual void visit(MulOpExpr* expr) override;
	virtual void visit(NegOpExpr* expr) override;
	virtual void visit(NeqOpExpr* expr) override;
	virtual void visit(NotOpExpr* expr) override;
	virtual void visit(OrOpExpr* expr) override;
	virtual void visit(StructIndexOpExpr* expr) override;
	virtual void visit(SubOpExpr* expr) override;
	virtual void visit(TernaryOpExpr* expr) override;
	virtual void visit(Variable* var) override;
	// Casts
	virtual void visit(BitCastExpr* expr) override;
	virtual void visit(ExtCastExpr* expr) override;
	virtual void visit(FPToIntCastExpr* expr) override;
	virtual void visit(IntToFPCastExpr* expr) override;
	virtual void visit(IntToPtrCastExpr* expr) override;
	virtual void visit(PtrToIntCastExpr* expr) override;
	virtual void visit(TruncCastExpr* expr) override;
	// Constants
	virtual void visit(ConstArray* constant) override;
	virtual void visit(ConstBool* constant) override;
	virtual void visit(ConstFloat* constant) override;
	virtual void visit(ConstInt* constant) override;
	virtual void visit(ConstNullPointer* constant) override;
	virtual void visit(ConstString* constant) override;
	virtual void visit(ConstStruct* constant) override;
	virtual void visit(ConstSymbol* constant) override;
	// Types
	virtual void visit(ArrayType* type) override;
	virtual void visit(FloatType* type) override;
	virtual void visit(IntType* type) override;
	virtual void visit(PointerType* type) override;
	virtual void visit(StringType* type) override;
	virtual void visit(StructType* type) override;
	virtual void visit(FunctionType* type) override;
	virtual void visit(VoidType* type) override;
	virtual void visit(UnknownType* type) override;
	/// @}

protected:
	OrderedAllVisitor(bool visitSuccessors = true, bool visitNestedStmts = true);

	virtual void visitStmt(Statement* stmt, bool visitSuccessors = true,
		bool visitNestedStmts = true);

	void restart(bool visitSuccessors = true, bool visitNestedStmts = true);
	bool makeAccessedAndCheckIfAccessed(Type* type);

protected:
	/// Statement that has been accessed as the last one.
	Statement* lastStmt = nullptr;

	/// A set of all accessed statements.
	StmtUSet accessedStmts;

	/// A set of all accessed types.
	TypeUSet accessedTypes;

	/// Should statements' successor be accessed?
	bool visitSuccessors;

	/// Should nested statements be accessed?
	bool visitNestedStmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
