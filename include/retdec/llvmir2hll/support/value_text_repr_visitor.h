/**
* @file include/retdec/llvmir2hll/support/value_text_repr_visitor.h
* @brief A visitor for obtaining a textual representation of a value.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_VALUE_TEXT_REPR_VISITOR_H
#define RETDEC_LLVMIR2HLL_SUPPORT_VALUE_TEXT_REPR_VISITOR_H

#include <sstream>
#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Value;

/**
* @brief A visitor for obtaining a textual representation of a value.
*
* See the description of getTextRepr() for more information.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*
* TODO Merge it with PyWriter? "Create" an instance of this class for each
*      HLL writer?
*/
class ValueTextReprVisitor: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~ValueTextReprVisitor() override;

	static std::string getTextRepr(ShPtr<Value> value);

private:
	ValueTextReprVisitor();

	/// @name Visitor Interface
	/// @{
	virtual void visit(ShPtr<GlobalVarDef> func) override;
	virtual void visit(ShPtr<Function> func) override;
	virtual void visit(ShPtr<Variable> var) override;
	virtual void visit(ShPtr<AddressOpExpr> expr) override;
	virtual void visit(ShPtr<AssignOpExpr> expr) override;
	virtual void visit(ShPtr<ArrayIndexOpExpr> expr) override;
	virtual void visit(ShPtr<StructIndexOpExpr> expr) override;
	virtual void visit(ShPtr<DerefOpExpr> expr) override;
	virtual void visit(ShPtr<NotOpExpr> expr) override;
	virtual void visit(ShPtr<NegOpExpr> expr) override;
	virtual void visit(ShPtr<EqOpExpr> expr) override;
	virtual void visit(ShPtr<NeqOpExpr> expr) override;
	virtual void visit(ShPtr<LtEqOpExpr> expr) override;
	virtual void visit(ShPtr<GtEqOpExpr> expr) override;
	virtual void visit(ShPtr<LtOpExpr> expr) override;
	virtual void visit(ShPtr<GtOpExpr> expr) override;
	virtual void visit(ShPtr<AddOpExpr> expr) override;
	virtual void visit(ShPtr<SubOpExpr> expr) override;
	virtual void visit(ShPtr<MulOpExpr> expr) override;
	virtual void visit(ShPtr<ModOpExpr> expr) override;
	virtual void visit(ShPtr<DivOpExpr> expr) override;
	virtual void visit(ShPtr<AndOpExpr> expr) override;
	virtual void visit(ShPtr<OrOpExpr> expr) override;
	virtual void visit(ShPtr<BitAndOpExpr> expr) override;
	virtual void visit(ShPtr<BitOrOpExpr> expr) override;
	virtual void visit(ShPtr<BitXorOpExpr> expr) override;
	virtual void visit(ShPtr<BitShlOpExpr> expr) override;
	virtual void visit(ShPtr<BitShrOpExpr> expr) override;
	virtual void visit(ShPtr<TernaryOpExpr> expr) override;
	virtual void visit(ShPtr<CallExpr> expr) override;
	virtual void visit(ShPtr<CommaOpExpr> expr) override;
	virtual void visit(ShPtr<ConstBool> constant) override;
	virtual void visit(ShPtr<ConstFloat> constant) override;
	virtual void visit(ShPtr<ConstInt> constant) override;
	virtual void visit(ShPtr<ConstNullPointer> constant) override;
	virtual void visit(ShPtr<ConstString> constant) override;
	virtual void visit(ShPtr<ConstArray> constant) override;
	virtual void visit(ShPtr<ConstStruct> constant) override;
	virtual void visit(ShPtr<ConstSymbol> constant) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<CallStmt> stmt) override;
	virtual void visit(ShPtr<ReturnStmt> stmt) override;
	virtual void visit(ShPtr<EmptyStmt> stmt) override;
	virtual void visit(ShPtr<IfStmt> stmt) override;
	virtual void visit(ShPtr<SwitchStmt> stmt) override;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	virtual void visit(ShPtr<UForLoopStmt> stmt) override;
	virtual void visit(ShPtr<BreakStmt> stmt) override;
	virtual void visit(ShPtr<ContinueStmt> stmt) override;
	virtual void visit(ShPtr<GotoStmt> stmt) override;
	virtual void visit(ShPtr<UnreachableStmt> stmt) override;
	// Types
	virtual void visit(ShPtr<FloatType> type) override;
	virtual void visit(ShPtr<IntType> type) override;
	virtual void visit(ShPtr<PointerType> type) override;
	virtual void visit(ShPtr<StringType> type) override;
	virtual void visit(ShPtr<ArrayType> type) override;
	virtual void visit(ShPtr<StructType> type) override;
	virtual void visit(ShPtr<FunctionType> type) override;
	virtual void visit(ShPtr<VoidType> type) override;
	virtual void visit(ShPtr<UnknownType> type) override;
	// Casts
	virtual void visit(ShPtr<BitCastExpr> expr) override;
	virtual void visit(ShPtr<ExtCastExpr> expr) override;
	virtual void visit(ShPtr<TruncCastExpr> expr) override;
	virtual void visit(ShPtr<FPToIntCastExpr> expr) override;
	virtual void visit(ShPtr<IntToFPCastExpr> expr) override;
	virtual void visit(ShPtr<IntToPtrCastExpr> expr) override;
	virtual void visit(ShPtr<PtrToIntCastExpr> expr) override;
	/// @}

private:
	/// Container to be used during obtaining the value's textual
	/// representation.
	// It is much easier to use a string stream rather than just a string
	// because plain data types, like ints, can be directly converted into a
	// string using a string stream.
	std::stringstream textRepr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
