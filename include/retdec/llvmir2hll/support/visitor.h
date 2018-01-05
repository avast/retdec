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
	virtual ~Visitor() = 0;

	virtual void visit(ShPtr<GlobalVarDef> varDef) = 0;
	virtual void visit(ShPtr<Function> func) = 0;
	// Statements
	virtual void visit(ShPtr<AssignStmt> stmt) = 0;
	virtual void visit(ShPtr<BreakStmt> stmt) = 0;
	virtual void visit(ShPtr<CallStmt> stmt) = 0;
	virtual void visit(ShPtr<ContinueStmt> stmt) = 0;
	virtual void visit(ShPtr<EmptyStmt> stmt) = 0;
	virtual void visit(ShPtr<ForLoopStmt> stmt) = 0;
	virtual void visit(ShPtr<UForLoopStmt> stmt) = 0;
	virtual void visit(ShPtr<GotoStmt> stmt) = 0;
	virtual void visit(ShPtr<IfStmt> stmt) = 0;
	virtual void visit(ShPtr<ReturnStmt> stmt) = 0;
	virtual void visit(ShPtr<SwitchStmt> stmt) = 0;
	virtual void visit(ShPtr<UnreachableStmt> stmt) = 0;
	virtual void visit(ShPtr<VarDefStmt> stmt) = 0;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) = 0;
	// Expressions
	virtual void visit(ShPtr<AddOpExpr> expr) = 0;
	virtual void visit(ShPtr<AddressOpExpr> expr) = 0;
	virtual void visit(ShPtr<AndOpExpr> expr) = 0;
	virtual void visit(ShPtr<ArrayIndexOpExpr> expr) = 0;
	virtual void visit(ShPtr<AssignOpExpr> expr) = 0;
	virtual void visit(ShPtr<BitAndOpExpr> expr) = 0;
	virtual void visit(ShPtr<BitOrOpExpr> expr) = 0;
	virtual void visit(ShPtr<BitShlOpExpr> expr) = 0;
	virtual void visit(ShPtr<BitShrOpExpr> expr) = 0;
	virtual void visit(ShPtr<BitXorOpExpr> expr) = 0;
	virtual void visit(ShPtr<CallExpr> expr) = 0;
	virtual void visit(ShPtr<CommaOpExpr> expr) = 0;
	virtual void visit(ShPtr<DerefOpExpr> expr) = 0;
	virtual void visit(ShPtr<DivOpExpr> expr) = 0;
	virtual void visit(ShPtr<EqOpExpr> expr) = 0;
	virtual void visit(ShPtr<GtEqOpExpr> expr) = 0;
	virtual void visit(ShPtr<GtOpExpr> expr) = 0;
	virtual void visit(ShPtr<LtEqOpExpr> expr) = 0;
	virtual void visit(ShPtr<LtOpExpr> expr) = 0;
	virtual void visit(ShPtr<ModOpExpr> expr) = 0;
	virtual void visit(ShPtr<MulOpExpr> expr) = 0;
	virtual void visit(ShPtr<NegOpExpr> expr) = 0;
	virtual void visit(ShPtr<NeqOpExpr> expr) = 0;
	virtual void visit(ShPtr<NotOpExpr> expr) = 0;
	virtual void visit(ShPtr<OrOpExpr> expr) = 0;
	virtual void visit(ShPtr<StructIndexOpExpr> expr) = 0;
	virtual void visit(ShPtr<SubOpExpr> expr) = 0;
	virtual void visit(ShPtr<TernaryOpExpr> expr) = 0;
	virtual void visit(ShPtr<Variable> var) = 0;
	// Casts
	virtual void visit(ShPtr<BitCastExpr> expr) = 0;
	virtual void visit(ShPtr<ExtCastExpr> expr) = 0;
	virtual void visit(ShPtr<FPToIntCastExpr> expr) = 0;
	virtual void visit(ShPtr<IntToFPCastExpr> expr) = 0;
	virtual void visit(ShPtr<IntToPtrCastExpr> expr) = 0;
	virtual void visit(ShPtr<PtrToIntCastExpr> expr) = 0;
	virtual void visit(ShPtr<TruncCastExpr> expr) = 0;
	// Constants
	virtual void visit(ShPtr<ConstArray> constant) = 0;
	virtual void visit(ShPtr<ConstBool> constant) = 0;
	virtual void visit(ShPtr<ConstFloat> constant) = 0;
	virtual void visit(ShPtr<ConstInt> constant) = 0;
	virtual void visit(ShPtr<ConstNullPointer> constant) = 0;
	virtual void visit(ShPtr<ConstString> constant) = 0;
	virtual void visit(ShPtr<ConstStruct> constant) = 0;
	virtual void visit(ShPtr<ConstSymbol> constant) = 0;
	// Types
	virtual void visit(ShPtr<ArrayType> type) = 0;
	virtual void visit(ShPtr<FloatType> type) = 0;
	virtual void visit(ShPtr<IntType> type) = 0;
	virtual void visit(ShPtr<PointerType> type) = 0;
	virtual void visit(ShPtr<StringType> type) = 0;
	virtual void visit(ShPtr<StructType> type) = 0;
	virtual void visit(ShPtr<FunctionType> type) = 0;
	virtual void visit(ShPtr<VoidType> type) = 0;
	virtual void visit(ShPtr<UnknownType> type) = 0;

protected:
	Visitor();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
