/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_converter.h
* @brief A converter from LLVM values to values in the backend IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_LLVM_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_LLVM_CONVERTER_H

#include <map>

#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class ConstantArray;
class ConstantDataArray;
class ConstantDataSequential;
class FunctionType;
class Module;
class Type;
class Value;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class AssignStmt;
class CallStmt;
class ConstArray;
class ConstString;
class Constant;
class Expression;
class FunctionType;
class Module;
class Statement;
class TernaryOpExpr;
class Type;
class Value;
class VarsHandler;

/**
* @brief A converter from LLVM values to values in the backend IR.
*
* Instances of this class have reference object semantics. This class is not
* meant to be subclassed.
*/
class LLVMConverter final: private llvm::InstVisitor<LLVMConverter, ShPtr<Value>>,
		private retdec::utils::NonCopyable {
public:
	LLVMConverter(llvm::Module *module, ShPtr<Module> resModule,
		ShPtr<VarsHandler> varsHandler);
	~LLVMConverter();

	// The default value of llvmSigned determines whether integers are signed
	// or unsigned by default.
	ShPtr<Type> llvmTypeToType(llvm::Type *llvmType, bool llvmSigned = true);
	ShPtr<FunctionType> llvmFunctionTypeToFunctionType(llvm::FunctionType *llvmType);
	ShPtr<Expression> llvmConstantToExpression(llvm::Constant *c);
	ShPtr<ConstArray> llvmConstantDataSequentialToConstArray(llvm::ConstantDataSequential *cds);
	ShPtr<Expression> llvmValueToExpression(llvm::Value *v);
	ShPtr<Expression> llvmValueToExpressionDeref(llvm::Value *v);
	ShPtr<ConstArray> llvmConstantArrayToConstArray(llvm::ConstantArray *ca);
	ShPtr<Expression> llvmConstantArrayToExpression(llvm::ConstantArray *ca);
	ShPtr<Expression> llvmLoadInstToExpression(llvm::LoadInst &i);
	ShPtr<AssignStmt> llvmStoreInstToAssignStmt(llvm::StoreInst &i);
	ShPtr<TernaryOpExpr> llvmSelectInstToTernaryOp(llvm::SelectInst &i);
	ShPtr<Expression> llvmBinaryOperatorToExpression(llvm::Instruction &i);
	ShPtr<Expression> llvmICmpInstToExpression(llvm::ICmpInst &i);
	ShPtr<Expression> llvmFCmpInstToExpression(llvm::FCmpInst &i);
	ShPtr<Statement> llvmInsertValueInstToStatement(llvm::InsertValueInst &i);
	ShPtr<Expression> llvmExtractValueInstToExpression(llvm::ExtractValueInst &i);
	ShPtr<Expression> generateAccessesToCompositeType(llvm::CompositeType *ct,
		llvm::ArrayRef<unsigned> indices, ShPtr<Expression> base);
	ShPtr<CallStmt> llvmCallInstToCallStmt(llvm::CallInst &i);
	ShPtr<Expression> llvmGEPInstToExpression(llvm::GetElementPtrInst &i);
	ShPtr<Expression> llvmAllocaInstToExpression(llvm::AllocaInst &i);
	ShPtr<Value> llvmInstructionToValue(llvm::Instruction &i);
	ShPtr<Value> llvmReturnInstToReturnStmt(llvm::ReturnInst &i);

	ShPtr<Expression> getInitializer(llvm::GlobalVariable *v);
	ShPtr<Constant> getDefaultInitializer(llvm::Type *t);

	/// @name Options
	/// @{
	void setOptionStrictFPUSemantics(bool strict = true);
	/// @}

private:
	ShPtr<Expression> llvmValueToExpressionInternal(llvm::Value *v);
	ShPtr<Expression> llvmGEPExpressionToExpressionInternal(llvm::Value *ptr,
		llvm::gep_type_iterator i, llvm::gep_type_iterator e);
	ShPtr<Expression> llvmFCmpBinInstToExpressionStrictFPUSemantics(llvm::FCmpInst &i);
	ShPtr<Expression> llvmFCmpBinInstToExpressionNonStrictFPUSemantics(llvm::FCmpInst &i);

	// Instruction visitation functions.
	friend class llvm::InstVisitor<LLVMConverter, ShPtr<Value>>;
	ShPtr<Value> visitBinaryOperator(llvm::Instruction &i);
	ShPtr<Value> visitCastInst(llvm::CastInst &i);
	ShPtr<Value> visitCallInst(llvm::CallInst &i);
	ShPtr<Value> visitAllocaInst(llvm::AllocaInst &i);
	ShPtr<Value> visitGetElementPtrInst(llvm::GetElementPtrInst &i);
	ShPtr<Value> visitInsertValueInst(llvm::InsertValueInst &i);
	ShPtr<Value> visitExtractValueInst(llvm::ExtractValueInst &i);
	ShPtr<Value> visitICmpInst(llvm::ICmpInst &i);
	ShPtr<Value> visitFCmpInst(llvm::FCmpInst &i);
	ShPtr<Value> visitLoadInst(llvm::LoadInst &i);
	ShPtr<Value> visitStoreInst(llvm::StoreInst &i);
	ShPtr<Value> visitSelectInst(llvm::SelectInst &i);
	ShPtr<Value> visitInstruction(llvm::Instruction &i);

private:
	/// The currently processed LLVM module.
	llvm::Module *module;

	/// The resulting module in our IR.
	ShPtr<Module> resModule;

	/// Handler of variables created during decompilation.
	ShPtr<VarsHandler> varsHandler;

	/// Mapping of an LLVM type into a type in our IR.
	std::map<llvm::Type *, ShPtr<Type>> llvmTypeToTypeMap;
	std::map<llvm::Type *, ShPtr<Type>> llvmTypeToSignedTypeMap;

	/// Use strict FPU semantics?
	bool optionStrictFPUSemantics;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
