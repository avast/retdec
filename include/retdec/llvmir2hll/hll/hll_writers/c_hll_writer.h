/**
* @file include/retdec/llvmir2hll/hll/hll_writers/c_hll_writer.h
* @brief Implementation of the HLL writer for the C language.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_HLL_WRITERS_C_HLL_WRITER_H
#define RETDEC_LLVMIR2HLL_HLL_HLL_WRITERS_C_HLL_WRITER_H

#include <cstddef>
#include <map>
#include <string>

#include "retdec/llvmir2hll/hll/hll_writer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class BracketManager;
class CastExpr;
class CompoundOpManager;
class StructType;

/**
* @brief A HLL writer for the C language (C99).
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class CHLLWriter: public HLLWriter {
public:
	static ShPtr<HLLWriter> create(llvm::raw_ostream &out);

	virtual std::string getId() const override;

	/// @name Options
	/// @{
	void setOptionEmitFunctionPrototypesForNonLibraryFuncs(bool emit = true);
	/// @}

private:
	/// Mapping of a structured type into its name.
	using StructTypeNameMap = std::map<ShPtr<StructType>, std::string>;

private:
	CHLLWriter(llvm::raw_ostream &out);

	virtual std::string getCommentPrefix() override;
	virtual bool emitFileHeader() override;
	virtual bool emitGlobalVariables() override;
	virtual bool emitFunctionPrototypesHeader() override;
	virtual bool emitFunctionPrototypes() override;
	virtual bool emitExternalFunction(ShPtr<Function> func) override;
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

	bool shouldEmitFunctionPrototypesHeader() const;
	bool emitFunctionPrototypes(const FuncSet &funcs);
	bool emitStandardFunctionPrototypes();
	bool emitFunctionPrototypesForNonLibraryFuncs();
	bool emitFunctionPrototype(ShPtr<Function> func);
	void emitFunctionDefinition(ShPtr<Function> func);
	void emitFunctionHeader(ShPtr<Function> func);
	void emitHeaderOfFuncReturningPointerToFunc(ShPtr<Function> func);
	void emitHeaderOfFuncReturningPointerToArray(ShPtr<Function> func);
	void emitFunctionParameters(ShPtr<Function> func);
	void emitVarWithType(ShPtr<Variable> var);
	void emitPointerToFunc(ShPtr<PointerType> pointerToFuncType,
		ShPtr<Variable> var = nullptr);
	void emitArrayOfFuncPointers(ShPtr<ArrayType> arrayType,
		ShPtr<Variable> var = nullptr);
	void emitPointerToArray(ShPtr<PointerType> pointerToArrayType,
		ShPtr<Variable> var = nullptr);
	void emitArrayDimensions(ShPtr<ArrayType> arrayType);
	void emitArrayDimension(std::size_t size);
	void emitInitializedConstArray(ShPtr<ConstArray> array);
	void emitInitializedConstArrayInline(ShPtr<ConstArray> array);
	void emitInitializedConstArrayInStructuredWay(ShPtr<ConstArray> array);
	void emitUninitializedConstArray(ShPtr<ConstArray> array);
	void emitTypeOfElementsInArray(ShPtr<ArrayType> arrayType);
	void emitCastInStandardWay(ShPtr<CastExpr> expr);
	void emitStarsBeforePointedValue(ShPtr<PointerType> ptrType);
	void emitFunctionParameters(ShPtr<FunctionType> funcType);
	void emitReturnType(ShPtr<FunctionType> funcType);
	void emitNameOfVarIfExists(ShPtr<Variable> var);
	void emitAssignment(ShPtr<Expression> lhs, ShPtr<Expression> rhs);
	void emitInitVarDefWhenNeeded(ShPtr<UForLoopStmt> loop);
	void emitConstStruct(ShPtr<ConstStruct> constant, bool emitCast = true);
	void emitStructDeclaration(ShPtr<StructType> structType,
		bool emitInline = false);
	void emitBlock(ShPtr<Statement> stmt);
	void emitGlobalDirectives(ShPtr<Function> func);
	void emitDebugComment(std::string comment, bool indent = true);
	void emitGotoLabelIfNeeded(ShPtr<Statement> stmt);
	void emitConstFloatSuffixIfNeeded(ShPtr<ConstFloat> constant);
	std::string genNameForUnnamedStruct(const StructTypeVector &usedStructTypes);

private:
	/// Optimizes AssignStmt to compound operator when possible.
	ShPtr<CompoundOpManager> compoundOpManager;

	/// Mapping of a structured type into its name.
	StructTypeNameMap structNames;

	/// A counter for unnamed structures.
	/// It is needed for assigning names to unnamed structures.
	std::size_t unnamedStructCounter;

	/// Are we emitting global variables?
	/// This variable is needed because we cannot emit casts of structures
	/// inside the initialization of global variables. See emitConstStruct()
	/// for more details.
	bool emittingGlobalVarDefs;

	/// Emit prototypes for functions which do not have any associated header
	/// file?
	bool optionEmitFunctionPrototypesForNonLibraryFuncs;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
