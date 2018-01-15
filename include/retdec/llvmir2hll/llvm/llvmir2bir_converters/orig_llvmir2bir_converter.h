/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter.h
* @brief The original converter of LLVM IR into BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_H

#include <map>
#include <string>

#include <llvm/IR/InstVisitor.h>

#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace llvm {

class Loop;
class Pass;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class GotoStmt;
class LLVMBranchInfo;
class LLVMConverter;
class LabelsHandler;
class Statement;
class Value;
class VarsHandler;

/**
* @brief The original converter of LLVM IR into BIR.
*
* Instances of this class have reference object semantics.
*/
class OrigLLVMIR2BIRConverter: public LLVMIR2BIRConverter,
		private llvm::InstVisitor<OrigLLVMIR2BIRConverter, ShPtr<Value>> {
public:
	static ShPtr<LLVMIR2BIRConverter> create(llvm::Pass *basePass);

	virtual std::string getId() const override;
	virtual ShPtr<Module> convert(llvm::Module *llvmModule,
		const std::string &moduleName, ShPtr<Semantics> semantics,
		ShPtr<Config> config, bool enableDebug) override;

private:
	/// Mapping of basic blocks to how many times they have been processed.
	using BBProcessedMap = std::map<llvm::BasicBlock *, unsigned>;

	/// Goto statements to be patched into a basic block.
	// Note: To make the converted deterministic, we need to use a vector
	//       instead of a map.
	using GotoStmtsToPatch = std::vector<std::pair<ShPtr<GotoStmt>,
		llvm::BasicBlock *>>;

	/// Mapping of basic blocks to statements in BIR.
	using BBStmtMap = std::map<llvm::BasicBlock *, ShPtr<Statement>>;

private:
	OrigLLVMIR2BIRConverter(llvm::Pass *basePass);

	// Instruction visitation functions.
	friend class llvm::InstVisitor<OrigLLVMIR2BIRConverter, ShPtr<Value>>;
	ShPtr<Value> visitReturnInst(llvm::ReturnInst &i);
	ShPtr<Value> visitBranchInst(llvm::BranchInst &i);
	ShPtr<Value> visitSwitchInst(llvm::SwitchInst &i);
	ShPtr<Value> visitCallInst(llvm::CallInst &i);
	ShPtr<Value> visitGetElementPtrInst(llvm::GetElementPtrInst &i);
	ShPtr<Value> visitLoadInst(llvm::LoadInst &i);
	ShPtr<Value> visitStoreInst(llvm::StoreInst &i);
	ShPtr<Value> visitAllocaInst(llvm::AllocaInst &i);
	ShPtr<Value> visitCastInst(llvm::CastInst &i);
	ShPtr<Value> visitInsertValueInst(llvm::InsertValueInst &i);
	ShPtr<Value> visitExtractValueInst(llvm::ExtractValueInst &i);
	ShPtr<Value> visitUnreachableInst(llvm::UnreachableInst &i);
	ShPtr<Value> visitInstruction(llvm::Instruction &i);

	void visitAndAddFunctions();
	void visitAndAddGlobalVariables();
	void visitAndAddFunctionDeclarations();
	void visitAndAddFunction(llvm::Function &f, bool onlyDeclaration = false);

	void makeIdentifiersValid();
	void generateMissingStatements(ShPtr<Statement> funcBody);
	bool isBBMissingStatements(llvm::BasicBlock *bb);
	void generateMissingStatementsForBB(ShPtr<Statement> funcBody,
		llvm::BasicBlock *bb);

	void addGotoStmtToPatch(ShPtr<GotoStmt> gotoStmt, llvm::BasicBlock *bb);
	void patchTargetsOfGotoStmts();
	void setGotoTargetLabel(ShPtr<Statement> target,
		const llvm::BasicBlock *targetBB);

	ShPtr<Statement> visitBasicBlockOrLoop(llvm::BasicBlock *bb,
		bool genTerm = true);
	ShPtr<Statement> visitBasicBlock(llvm::BasicBlock *bb, bool genTerm = true);
	ShPtr<Statement> visitLoop(llvm::Loop *l);

	VarVector getFunctionParams(llvm::Function &f);
	ShPtr<Statement> getFunctionBody(llvm::Function &f);
	ShPtr<Statement> getDefaultSwitchBlock(llvm::BasicBlock *bb,
		llvm::BasicBlock *succ);
	ShPtr<Expression> getSwitchCaseExpression(llvm::Value *v);
	ShPtr<Statement> getLoopEnd(llvm::BasicBlock *currBB,
		llvm::BasicBlock *loopHeader, llvm::BasicBlock *loopEnd,
		llvm::Value *cond, bool isCondNegated = false,
		bool justPHICopies = false);
	llvm::Value *getInitialValueOfIndVar(const llvm::Loop *l) const;
	ShPtr<Statement> getPHICopiesForSuccessor(llvm::BasicBlock *currBB,
		llvm::BasicBlock *succ) const;
	ShPtr<Statement> generateGotoForConditionalBranch(llvm::BasicBlock *bb1,
		llvm::BasicBlock *bb2, llvm::BasicBlock *source, llvm::Value *cond,
		bool negateCond = false);

	static void addStatementToStatementBlock(ShPtr<Statement> stmtToAdd,
		ShPtr<Statement> &firstStmt, ShPtr<Statement> &prevStmt);
	static ShPtr<Statement> addDebugCommentToStatement(
		ShPtr<Statement> stmt, std::string debugComment);

private:
	/// The input LLVM module.
	llvm::Module *llvmModule;

	/// The resulting module in BIR.
	ShPtr<Module> resModule;

	/// Should debugging messages be emitted?
	bool enableDebug;

	/// Handler of variables created during decompilation.
	ShPtr<VarsHandler> varsHandler;

	/// Type and values converter.
	ShPtr<LLVMConverter> converter;

	/// Supportive information about branches and loops.
	ShPtr<LLVMBranchInfo> branchInfo;

	/// Handler of labels.
	UPtr<LabelsHandler> labelsHandler;

	/// Mapping of basic blocks to how many times they have been processed.
	BBProcessedMap processedBBs;

	/// Mapping of basic blocks to the first statement in the
	/// corresponding basic block in BIR.
	BBStmtMap bbStmtMap;

	/// Goto statements whose target has to be patched after the current
	/// function is converted.
	GotoStmtsToPatch gotoStmtsToPatch;

	/// Basic block corresponding to the currently generated loop.
	llvm::BasicBlock *currLoopBB;

	/// Basic block which should be generated after the current loop.
	llvm::BasicBlock *lastLoopExitBB;

	/// Are we generating a switch statement?
	bool generatingSwitchStmt;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
