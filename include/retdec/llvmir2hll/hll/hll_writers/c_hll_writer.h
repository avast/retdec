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
class OutputManager;
class StructType;

/**
* @brief A HLL writer for the C language (C99).
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class CHLLWriter: public HLLWriter {
public:
	static HLLWriter* create(
		llvm::raw_ostream &out,
		const std::string& outputFormat = "");

	virtual std::string getId() const override;

	/// @name Options
	/// @{
	void setOptionEmitFunctionPrototypesForNonLibraryFuncs(bool emit = true);
	/// @}

private:
	/// Mapping of a structured type into its name.
	using StructTypeNameMap = std::map<StructType*, std::string>;

private:
	CHLLWriter(
		llvm::raw_ostream &out,
		const std::string& outputFormat = "");

	virtual std::string getCommentPrefix() override;
	virtual bool emitFileHeader() override;
	virtual bool emitGlobalVariables() override;
	virtual bool emitFunctionPrototypesHeader() override;
	virtual bool emitFunctionPrototypes() override;
	virtual bool emitExternalFunction(Function* func) override;
	virtual bool emitTargetCode(Module* module) override;

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
	virtual void visit(FunctionType* type) override;
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

	bool shouldEmitFunctionPrototypesHeader() const;
	bool emitFunctionPrototypes(const FuncSet &funcs);
	bool emitStandardFunctionPrototypes();
	bool emitFunctionPrototypesForNonLibraryFuncs();
	bool emitFunctionPrototype(Function* func);
	void emitFunctionDefinition(Function* func);
	void emitFunctionHeader(Function* func);
	void emitHeaderOfFuncReturningPointerToFunc(Function* func);
	void emitHeaderOfFuncReturningPointerToArray(Function* func);
	void emitFunctionParameters(Function* func);
	void emitVarWithType(Variable* var);
	void emitPointerToFunc(PointerType* pointerToFuncType,
		Variable* var = nullptr);
	void emitArrayOfFuncPointers(ArrayType* arrayType,
		Variable* var = nullptr);
	void emitPointerToArray(PointerType* pointerToArrayType,
		Variable* var = nullptr);
	void emitArrayDimensions(ArrayType* arrayType);
	void emitArrayDimension(std::size_t size);
	void emitInitializedConstArray(ConstArray* array);
	void emitInitializedConstArrayInline(ConstArray* array);
	void emitInitializedConstArrayInStructuredWay(ConstArray* array);
	void emitUninitializedConstArray(ConstArray* array);
	void emitTypeOfElementsInArray(ArrayType* arrayType);
	void emitCastInStandardWay(CastExpr* expr);
	void emitStarsBeforePointedValue(PointerType* ptrType);
	void emitFunctionParameters(FunctionType* funcType);
	void emitReturnType(FunctionType* funcType);
	void emitNameOfVarIfExists(Variable* var);
	void emitAssignment(Expression* lhs, Expression* rhs);
	void emitInitVarDefWhenNeeded(UForLoopStmt* loop);
	void emitConstStruct(ConstStruct* constant, bool emitCast = true);
	void emitStructDeclaration(StructType* structType,
		bool emitInline = false);
	void emitBlock(Statement* stmt);
	void emitGlobalDirectives(Function* func);
	void emitDebugComment(std::string comment, bool indent = true);
	void emitGotoLabelIfNeeded(Statement* stmt);

	std::string getConstFloatSuffixIfNeeded(ConstFloat* constant);
	std::string genNameForUnnamedStruct(const StructTypeVector &usedStructTypes);

private:
	/// Optimizes AssignStmt to compound operator when possible.
	CompoundOpManager* compoundOpManager = nullptr;

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
