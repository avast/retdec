/**
* @file include/retdec/llvmir2hll/hll/hll_writers/py_hll_writer.h
* @brief A HLL writer for the Python' language.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_HLL_WRITERS_PY_HLL_WRITER_H
#define RETDEC_LLVMIR2HLL_HLL_HLL_WRITERS_PY_HLL_WRITER_H

#include <string>

#include "retdec/llvmir2hll/hll/hll_writer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class BracketManager;
class CastExpr;
class CompoundOpManager;

/**
* @brief A HLL writer for the Python' language.
*
* The language is based on Python. It is non-typed, block structured, and uses
* whitespace indentation, rather than curly braces or keywords, to delimit
* blocks. It emphasises code readability. Whenever there is no support in
* Python for a specific construction, C-like constructs are used. For example,
* a C-like @c switch statement is used to implement the fall-through
* feature of C. Instead of arrays, we use lists, and instead of structures, we
* utilize dictionaries. We also use the address and dereference operators from
* C. As there are cases when the code cannot be structured by high-level
* constructs only (for example, an irreducible subgraph of the control-flow
* graph is detected), an explicit @c goto represents a necessary addition
* to the language.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class PyHLLWriter: public HLLWriter {
public:
	static ShPtr<HLLWriter> create(llvm::raw_ostream &out);

	virtual std::string getId() const override;

private:
	PyHLLWriter(llvm::raw_ostream &out);

	virtual std::string getCommentPrefix() override;
	virtual bool emitExternalFunction(ShPtr<Function> func) override;
	virtual bool emitFileFooter() override;
	virtual bool emitTargetCode(ShPtr<Module> module) override;

	/// @name Visitor Interface
	/// @{
	virtual void visit(ShPtr<GlobalVarDef> varDef) override;
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

	void emitFunctionDefinition(ShPtr<Function> func);
	void emitBlock(ShPtr<Statement> stmt);
	void emitGlobalDirectives(ShPtr<Function> func);
	void emitDebugComment(std::string comment, bool indent = true);
	void emitDefaultInitializer(ShPtr<Type> type);
	void emitInitializedConstArray(ShPtr<ConstArray> array);
	void emitInitializedConstArrayInline(ShPtr<ConstArray> array);
	void emitInitializedConstArrayInStructuredWay(ShPtr<ConstArray> array);
	void emitUninitializedConstArray(ShPtr<ConstArray> array);
	void emitOperandOfCast(ShPtr<CastExpr> expr);
	void emitGotoLabelIfNeeded(ShPtr<Statement> stmt);
	void emitBody(ShPtr<Statement> body);
	void emitEntryPoint(ShPtr<Function> mainFunc);

private:
	/// Optimizes AssignStmt to compound operator when possible.
	ShPtr<CompoundOpManager> compoundOpManager;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
