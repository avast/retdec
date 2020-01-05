/**
* @file include/retdec/llvmir2hll/support/visitor.h
* @brief A base class of all visitors.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_VISITOR_H
#define RETDEC_LLVMIR2HLL_SUPPORT_VISITOR_H

#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class AddOpExpr;
class AddressOpExpr;
class AndOpExpr;
class ArrayIndexOpExpr;
class ArrayType;
class AssignOpExpr;
class AssignStmt;
class BitAndOpExpr;
class BitCastExpr;
class BitOrOpExpr;
class BitShlOpExpr;
class BitShrOpExpr;
class BitXorOpExpr;
class BreakStmt;
class CallExpr;
class CallStmt;
class CommaOpExpr;
class ConstArray;
class ConstBool;
class ConstFloat;
class ConstInt;
class ConstNullPointer;
class ConstString;
class ConstStruct;
class ConstSymbol;
class ContinueStmt;
class DerefOpExpr;
class DivOpExpr;
class EmptyStmt;
class EqOpExpr;
class Expression;
class ExtCastExpr;
class FPToIntCastExpr;
class FloatConst;
class FloatType;
class ForLoopStmt;
class Function;
class FunctionType;
class GlobalVarDef;
class GotoStmt;
class GtEqOpExpr;
class GtOpExpr;
class IfStmt;
class IntToFPCastExpr;
class IntToPtrCastExpr;
class IntType;
class LtEqOpExpr;
class LtOpExpr;
class ModOpExpr;
class Module;
class MulOpExpr;
class NegOpExpr;
class NeqOpExpr;
class NotOpExpr;
class OrOpExpr;
class PointerType;
class PtrToIntCastExpr;
class ReturnStmt;
class Statement;
class StringType;
class StructIndexOpExpr;
class StructType;
class SubOpExpr;
class SwitchStmt;
class TernaryOpExpr;
class TruncCastExpr;
class UForLoopStmt;
class UnknownType;
class UnreachableStmt;
class VarDefStmt;
class Variable;
class VoidType;
class WhileLoopStmt;

/**
* @brief A base class of all visitors.
*
* This class implements the Visitor design pattern to circumvent the lack of
* double dispatch in C++.
*/
class Visitor {
public:
	virtual ~Visitor() = default;

	virtual void visit(GlobalVarDef* varDef) = 0;
	virtual void visit(Function* func) = 0;
	// Statements
	virtual void visit(AssignStmt* stmt) = 0;
	virtual void visit(BreakStmt* stmt) = 0;
	virtual void visit(CallStmt* stmt) = 0;
	virtual void visit(ContinueStmt* stmt) = 0;
	virtual void visit(EmptyStmt* stmt) = 0;
	virtual void visit(ForLoopStmt* stmt) = 0;
	virtual void visit(UForLoopStmt* stmt) = 0;
	virtual void visit(GotoStmt* stmt) = 0;
	virtual void visit(IfStmt* stmt) = 0;
	virtual void visit(ReturnStmt* stmt) = 0;
	virtual void visit(SwitchStmt* stmt) = 0;
	virtual void visit(UnreachableStmt* stmt) = 0;
	virtual void visit(VarDefStmt* stmt) = 0;
	virtual void visit(WhileLoopStmt* stmt) = 0;
	// Expressions
	virtual void visit(AddOpExpr* expr) = 0;
	virtual void visit(AddressOpExpr* expr) = 0;
	virtual void visit(AndOpExpr* expr) = 0;
	virtual void visit(ArrayIndexOpExpr* expr) = 0;
	virtual void visit(AssignOpExpr* expr) = 0;
	virtual void visit(BitAndOpExpr* expr) = 0;
	virtual void visit(BitOrOpExpr* expr) = 0;
	virtual void visit(BitShlOpExpr* expr) = 0;
	virtual void visit(BitShrOpExpr* expr) = 0;
	virtual void visit(BitXorOpExpr* expr) = 0;
	virtual void visit(CallExpr* expr) = 0;
	virtual void visit(CommaOpExpr* expr) = 0;
	virtual void visit(DerefOpExpr* expr) = 0;
	virtual void visit(DivOpExpr* expr) = 0;
	virtual void visit(EqOpExpr* expr) = 0;
	virtual void visit(GtEqOpExpr* expr) = 0;
	virtual void visit(GtOpExpr* expr) = 0;
	virtual void visit(LtEqOpExpr* expr) = 0;
	virtual void visit(LtOpExpr* expr) = 0;
	virtual void visit(ModOpExpr* expr) = 0;
	virtual void visit(MulOpExpr* expr) = 0;
	virtual void visit(NegOpExpr* expr) = 0;
	virtual void visit(NeqOpExpr* expr) = 0;
	virtual void visit(NotOpExpr* expr) = 0;
	virtual void visit(OrOpExpr* expr) = 0;
	virtual void visit(StructIndexOpExpr* expr) = 0;
	virtual void visit(SubOpExpr* expr) = 0;
	virtual void visit(TernaryOpExpr* expr) = 0;
	virtual void visit(Variable* var) = 0;
	// Casts
	virtual void visit(BitCastExpr* expr) = 0;
	virtual void visit(ExtCastExpr* expr) = 0;
	virtual void visit(FPToIntCastExpr* expr) = 0;
	virtual void visit(IntToFPCastExpr* expr) = 0;
	virtual void visit(IntToPtrCastExpr* expr) = 0;
	virtual void visit(PtrToIntCastExpr* expr) = 0;
	virtual void visit(TruncCastExpr* expr) = 0;
	// Constants
	virtual void visit(ConstArray* constant) = 0;
	virtual void visit(ConstBool* constant) = 0;
	virtual void visit(ConstFloat* constant) = 0;
	virtual void visit(ConstInt* constant) = 0;
	virtual void visit(ConstNullPointer* constant) = 0;
	virtual void visit(ConstString* constant) = 0;
	virtual void visit(ConstStruct* constant) = 0;
	virtual void visit(ConstSymbol* constant) = 0;
	// Types
	virtual void visit(ArrayType* type) = 0;
	virtual void visit(FloatType* type) = 0;
	virtual void visit(IntType* type) = 0;
	virtual void visit(PointerType* type) = 0;
	virtual void visit(StringType* type) = 0;
	virtual void visit(StructType* type) = 0;
	virtual void visit(FunctionType* type) = 0;
	virtual void visit(VoidType* type) = 0;
	virtual void visit(UnknownType* type) = 0;

protected:
	Visitor() = default;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
