/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/basic_block_converter_tests.cpp
* @brief Tests for the @c basic_block_converter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/utils/ir.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c basic_block_converter module.
*/
class BasicBlockConverterTests: public NewLLVMIR2BIRConverterBaseTests {};

TEST_F(BasicBlockConverterTests,
SequenceOfStatementsIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function() {
			call void @test(i32 1)
			call void @test(i32 2)
			call void @test(i32 3)
			ret void
		}
	)");

	//
	// test(1);
	// test(2);
	// test(3);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto call1 = f->getBody();
	ASSERT_TRUE(isCallOfFuncTest(call1, 1));
	auto call2 = call1->getSuccessor();
	ASSERT_TRUE(isCallOfFuncTest(call2, 2));
	ASSERT_TRUE(isCallOfFuncTest(call2->getSuccessor(), 3));
}

//
// Tests for return statement
//

TEST_F(BasicBlockConverterTests,
FunctionWithSingleInstructionWhichReturnsConstantIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function() {
			ret i32 1
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(isIntReturn(f->getBody(), 1));
}

TEST_F(BasicBlockConverterTests,
FunctionWithSingleInstructionWhichReturnsVoidIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function() {
			ret void
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto fRetStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(fRetStmt);
	ASSERT_FALSE(fRetStmt->hasRetVal());
}

TEST_F(BasicBlockConverterTests,
FunctionWithSingleInstructionWhichReturnsTwoNumbersSumIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function(i32 %arg1, i32 %arg2) {
			%result = add i32 %arg1, %arg2
			ret i32 %result
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto fRetStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(fRetStmt);
	auto fRetExpr = cast<AddOpExpr>(fRetStmt->getRetVal());
	ASSERT_TRUE(fRetExpr);
	auto op1 = cast<Variable>(fRetExpr->getFirstOperand());
	ASSERT_TRUE(op1);
	ASSERT_BIR_EQ(op1, f->getParam(1));
	auto op2 = cast<Variable>(fRetExpr->getSecondOperand());
	ASSERT_TRUE(op2);
	ASSERT_BIR_EQ(op2, f->getParam(2));
}

//
// Tests for function calls
//

TEST_F(BasicBlockConverterTests,
FunctionCallWithUsedResultIsConvertedCorrectlyAsAssignStmtWithCallExprInRhs) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @plus(i32, i32)

		define i32 @function(i32 %arg1) {
			%result = call i32 @plus(i32 %arg1, i32 2)
			ret i32 %result
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefStmt = f->getBody();
	ASSERT_TRUE(isVarDef<IntType>(varDefStmt, "result"));
	auto assignStmt = cast<AssignStmt>(varDefStmt->getSuccessor());
	ASSERT_TRUE(assignStmt);
	auto callExpr = cast<CallExpr>(assignStmt->getRhs());
	ASSERT_TRUE(callExpr);
	auto calledExpr = cast<Variable>(callExpr->getCalledExpr());
	ASSERT_TRUE(calledExpr);
	ASSERT_BIR_EQ(module->getFuncByName("plus")->getAsVar(), calledExpr);
	ASSERT_EQ(2, callExpr->getNumOfArgs());
	auto arg1 = cast<Variable>(callExpr->getArg(1));
	ASSERT_TRUE(arg1);
	ASSERT_EQ("arg1"s, arg1->getName());
	auto arg2 = cast<ConstInt>(callExpr->getArg(2));
	ASSERT_TRUE(arg2);
	ASSERT_EQ(2, arg2->getValue());
}

TEST_F(BasicBlockConverterTests,
FunctionCallWithUnusedResultIsConvertedCorrectlyAsCallStmt) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @plus(i32, i32)

		define void @function(i32 %arg1) {
			%result = call i32 @plus(i32 %arg1, i32 2)
			ret void
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt = cast<CallStmt>(f->getBody());
	ASSERT_TRUE(callStmt);
	ASSERT_TRUE(isa<CallExpr>(callStmt->getCall()));
}

TEST_F(BasicBlockConverterTests,
FunctionCallWithIgnoredResultIsConvertedCorrectlyAsCallStmt) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @plus(i32, i32)

		define void @function(i32 %arg1) {
			call i32 @plus(i32 %arg1, i32 2)
			ret void
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt = cast<CallStmt>(f->getBody());
	ASSERT_TRUE(callStmt);
	ASSERT_TRUE(isa<CallExpr>(callStmt->getCall()));
}

TEST_F(BasicBlockConverterTests,
VoidFunctionCallIsConvertedCorrectlyAsCallStmt) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @plus(i32, i32)

		define void @function(i32 %arg1) {
			call void @plus(i32 %arg1, i32 2)
			ret void
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt = cast<CallStmt>(f->getBody());
	ASSERT_TRUE(callStmt);
	ASSERT_TRUE(isa<CallExpr>(callStmt->getCall()));
}

TEST_F(BasicBlockConverterTests,
CallOfFunctionDeclaredAfterCallerIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %arg1) {
			call void @plus(i32 %arg1, i32 2)
			ret void
		}

		declare void @plus(i32, i32)
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt = cast<CallStmt>(f->getBody());
	ASSERT_TRUE(callStmt);
	auto callExpr = cast<CallExpr>(callStmt->getCall());
	ASSERT_TRUE(callExpr);
	auto calledExpr = cast<Variable>(callExpr->getCalledExpr());
	ASSERT_TRUE(calledExpr);
	ASSERT_BIR_EQ(module->getFuncByName("plus")->getAsVar(), calledExpr);
}

TEST_F(BasicBlockConverterTests,
CallOfFunctionWithPointerInParamIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @length(i8*)

		define void @function(i32 %arg1) {
			%str = alloca [256 x i8], align 4
			%ptr = getelementptr inbounds [256 x i8], [256 x i8]* %str, i32 0, i32 10
			call i32 @length(i8* %ptr)
			ret void
		}
	)");

	//
	// int str[256];
	// length(&str[10]);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefStr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefStr, "str"));
	auto varStr = varDefStr->getVar();
	auto callStmt = cast<CallStmt>(varDefStr->getSuccessor());
	ASSERT_TRUE(callStmt);
	auto callExpr = cast<CallExpr>(callStmt->getCall());
	ASSERT_TRUE(callExpr);
	auto calledExpr = cast<Variable>(callExpr->getCalledExpr());
	ASSERT_TRUE(calledExpr);
	ASSERT_BIR_EQ(module->getFuncByName("length")->getAsVar(), calledExpr);
	ASSERT_EQ(1, callExpr->getNumOfArgs());
	auto arg1 = cast<AddressOpExpr>(callExpr->getArg(1));
	ASSERT_TRUE(arg1);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(arg1->getOperand());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(varStr, arrIndexOpExpr->getBase());
	ASSERT_TRUE(isConstInt(arrIndexOpExpr->getIndex(), 10));
}

//
// Tests for alloca, store, and load instructions
//

TEST_F(BasicBlockConverterTests,
AllocaAndStoreAreConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %arg1) {
			%ptr = alloca i32, align 4
			store i32 %arg1, i32* %ptr, align 4
			ret void
		}
	)");

	//
	// int ptr;
	// ptr = arg1;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefPtr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<IntType>(varDefPtr, "ptr"));
	ASSERT_TRUE(isAssignOfVarToVar(varDefPtr->getSuccessor(), varDefPtr->getVar(),
		f->getParam(1)));
}

TEST_F(BasicBlockConverterTests,
AllocaAndLoadAreConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function() {
			%ptr = alloca i32, align 4
			%var = load i32, i32* %ptr, align 4
			ret void
		}
	)");

	//
	// int ptr;
	// int var;
	// var = ptr;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefPtr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<IntType>(varDefPtr, "ptr"));
	auto varDefVar = cast<VarDefStmt>(varDefPtr->getSuccessor());
	ASSERT_TRUE(isVarDef<IntType>(varDefVar, "var"));
	ASSERT_TRUE(isAssignOfVarToVar(varDefVar->getSuccessor(), varDefVar->getVar(),
		varDefPtr->getVar()));
}

TEST_F(BasicBlockConverterTests,
IndirectAllocaAndStoreAreConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %arg1) {
		entry:
			br label %test
		test:
			%ptr = alloca i32, align 4
			store i32 %arg1, i32* %ptr, align 4
			ret void
		}
	)");

	//
	// int *ptr;
	// *ptr = arg1;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefPtr = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<PointerType>(varDefPtr, "ptr"));
	ASSERT_TRUE(isAssignOfVarToVarDeref(getFirstNonEmptySuccOf(varDefPtr),
		varDefPtr->getVar(), f->getParam(1)));
}

TEST_F(BasicBlockConverterTests,
IndirectAllocaAndLoadAreConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function() {
		entry:
			br label %test
		test:
			%ptr = alloca i32, align 4
			%var = load i32, i32* %ptr, align 4
			ret void
		}
	)");

	//
	// int *ptr;
	// int var;
	// var = *ptr;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefPtr = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<PointerType>(varDefPtr, "ptr"));
	auto varDefVar = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefPtr));
	ASSERT_TRUE(isVarDef<IntType>(varDefVar, "var"));
	ASSERT_TRUE(isAssignOfVarDerefToVar(getFirstNonEmptySuccOf(varDefVar),
		varDefVar->getVar(), varDefPtr->getVar()));
}

TEST_F(BasicBlockConverterTests,
StoreToGlobVarIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1
		define void @function(i32 %arg1) {
			store i32 %arg1, i32* @g, align 4
			ret void
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(isAssignOfVarToVar(f->getBody(), module->getGlobalVarByName("g"),
		f->getParam(1)));
}

TEST_F(BasicBlockConverterTests,
LoadFromGlobVarIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1
		define void @function() {
			%var = load i32, i32* @g, align 4
			ret void
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefVar = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<IntType>(varDefVar, "var"));
	ASSERT_TRUE(isAssignOfVarToVar(varDefVar->getSuccessor(), varDefVar->getVar(),
		module->getGlobalVarByName("g")));
}

TEST_F(BasicBlockConverterTests,
StoreToOnedimensionalArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %index, i32 %value) {
			%arr = alloca [10 x i32], align 4
			%elemPtr = getelementptr inbounds [10 x i32], [10 x i32]* %arr, i64 0, i32 %index
			store i32 %value, i32* %elemPtr, align 4
			ret void
		}
	)");

	//
	// int arr[10];
	// arr[index] = value;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefArr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefArr, "arr"));
	auto storeStmt = cast<AssignStmt>(varDefArr->getSuccessor());
	ASSERT_TRUE(storeStmt);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(storeStmt->getLhs());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(varDefArr->getVar(), arrIndexOpExpr->getBase());
	ASSERT_BIR_EQ(f->getParam(1), arrIndexOpExpr->getIndex());
	ASSERT_BIR_EQ(f->getParam(2), storeStmt->getRhs());
}

TEST_F(BasicBlockConverterTests,
LoadFromOnedimensionalArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %index) {
			%arr = alloca [10 x i32], align 4
			%elemPtr = getelementptr inbounds [10 x i32], [10 x i32]* %arr, i64 0, i32 %index
			%var = load i32, i32* %elemPtr, align 4
			ret void
		}
	)");

	//
	// int arr[10];
	// int var;
	// var = arr[index];
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefArr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefArr, "arr"));
	auto varDefVar = cast<VarDefStmt>(varDefArr->getSuccessor());
	ASSERT_TRUE(isVarDef<IntType>(varDefVar, "var"));
	auto loadStmt = cast<AssignStmt>(varDefVar->getSuccessor());
	ASSERT_TRUE(loadStmt);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(loadStmt->getRhs());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(varDefVar->getVar(), loadStmt->getLhs());
	ASSERT_BIR_EQ(varDefArr->getVar(), arrIndexOpExpr->getBase());
	ASSERT_BIR_EQ(f->getParam(1), arrIndexOpExpr->getIndex());
}

TEST_F(BasicBlockConverterTests,
StoreToMultidimensionalArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %index, i32 %index2, i32 %value) {
			%arr = alloca [10 x [10 x i32]], align 4
			%elemPtr = getelementptr inbounds [10 x [10 x i32]], [10 x [10 x i32]]* %arr, i64 0, i32 %index, i32 %index2
			store i32 %value, i32* %elemPtr, align 4
			ret void
		}
	)");

	//
	// int arr[10][10];
	// arr[index][index2] = value;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefArr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefArr, "arr"));
	auto storeStmt = cast<AssignStmt>(varDefArr->getSuccessor());
	ASSERT_TRUE(storeStmt);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(storeStmt->getLhs());
	ASSERT_TRUE(arrIndexOpExpr);
	auto innerArrIndexOpExpr = cast<ArrayIndexOpExpr>(arrIndexOpExpr->getBase());
	ASSERT_TRUE(innerArrIndexOpExpr);
	ASSERT_BIR_EQ(varDefArr->getVar(), innerArrIndexOpExpr->getBase());
	ASSERT_BIR_EQ(f->getParam(1), innerArrIndexOpExpr->getIndex());
	ASSERT_BIR_EQ(f->getParam(2), arrIndexOpExpr->getIndex());
	ASSERT_BIR_EQ(f->getParam(3), storeStmt->getRhs());
}

TEST_F(BasicBlockConverterTests,
LoadFromMultidimensionalArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %index, i32 %index2) {
			%arr = alloca [10 x [10 x i32]], align 4
			%elemPtr = getelementptr inbounds [10 x [10 x i32]], [10 x [10 x i32]]* %arr, i64 0, i32 %index, i32 %index2
			%var = load i32, i32* %elemPtr, align 4
			ret void
		}
	)");

	//
	// int arr[10][10];
	// int var;
	// var = arr[index][index2];
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefArr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefArr, "arr"));
	auto varDefVar = cast<VarDefStmt>(varDefArr->getSuccessor());
	ASSERT_TRUE(isVarDef<IntType>(varDefVar, "var"));
	auto loadStmt = cast<AssignStmt>(varDefVar->getSuccessor());
	ASSERT_TRUE(loadStmt);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(loadStmt->getRhs());
	ASSERT_TRUE(arrIndexOpExpr);
	auto innerArrIndexOpExpr = cast<ArrayIndexOpExpr>(arrIndexOpExpr->getBase());
	ASSERT_TRUE(innerArrIndexOpExpr);
	ASSERT_BIR_EQ(varDefVar->getVar(), loadStmt->getLhs());
	ASSERT_BIR_EQ(varDefArr->getVar(), innerArrIndexOpExpr->getBase());
	ASSERT_BIR_EQ(f->getParam(1), innerArrIndexOpExpr->getIndex());
	ASSERT_BIR_EQ(f->getParam(2), arrIndexOpExpr->getIndex());
}

TEST_F(BasicBlockConverterTests,
StoreToStructIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }
		define void @function(i32 %value) {
			%a = alloca %s, align 4
			%elemPtr = getelementptr inbounds %s, %s* %a, i64 0, i32 1
			store i32 %value, i32* %elemPtr, align 4
			ret void
		}
	)");

	//
	// struct s {int a, int b} a;
	// a.b = value;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefA = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<StructType>(varDefA, "a"));
	auto storeStmt = cast<AssignStmt>(varDefA->getSuccessor());
	ASSERT_TRUE(storeStmt);
	auto structIndexOpExpr = cast<StructIndexOpExpr>(storeStmt->getLhs());
	ASSERT_TRUE(structIndexOpExpr);
	ASSERT_BIR_EQ(varDefA->getVar(), structIndexOpExpr->getFirstOperand());
	ASSERT_BIR_EQ(f->getParam(1), storeStmt->getRhs());
	ASSERT_TRUE(isa<ConstInt>(structIndexOpExpr->getSecondOperand()));
}

TEST_F(BasicBlockConverterTests,
LoadFromStructIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }
		define void @function() {
			%a = alloca %s, align 4
			%elemPtr = getelementptr inbounds %s, %s* %a, i64 0, i32 1
			%var = load i32, i32* %elemPtr, align 4
			ret void
		}
	)");

	//
	// struct s {int a, int b} a;
	// int var;
	// var = a.b;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefA = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<StructType>(varDefA, "a"));
	auto varDefVar = cast<VarDefStmt>(varDefA->getSuccessor());
	ASSERT_TRUE(isVarDef<IntType>(varDefVar, "var"));
	auto loadStmt = cast<AssignStmt>(varDefVar->getSuccessor());
	ASSERT_TRUE(loadStmt);
	auto structIndexOpExpr = cast<StructIndexOpExpr>(loadStmt->getRhs());
	ASSERT_TRUE(structIndexOpExpr);
	ASSERT_BIR_EQ(varDefVar->getVar(), loadStmt->getLhs());
	ASSERT_BIR_EQ(varDefA->getVar(), structIndexOpExpr->getFirstOperand());
	ASSERT_TRUE(isa<ConstInt>(structIndexOpExpr->getSecondOperand()));
}

TEST_F(BasicBlockConverterTests,
StoreToArrayOfStructsIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }
		define void @function(i32 %index, i32 %value) {
			%arr = alloca [10 x %s], align 4
			%elemPtr = getelementptr inbounds [10 x %s], [10 x %s]* %arr, i64 0, i32 %index, i32 1
			store i32 %value, i32* %elemPtr, align 4
			ret void
		}
	)");

	//
	// struct s {int a, int b} arr[10];
	// arr[index].b = value;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefArr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefArr, "arr"));
	auto storeStmt = cast<AssignStmt>(varDefArr->getSuccessor());
	ASSERT_TRUE(storeStmt);
	auto structIndexOpExpr = cast<StructIndexOpExpr>(storeStmt->getLhs());
	ASSERT_TRUE(structIndexOpExpr);
	ASSERT_TRUE(isa<ConstInt>(structIndexOpExpr->getSecondOperand()));
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(structIndexOpExpr->getFirstOperand());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(varDefArr->getVar(), arrIndexOpExpr->getBase());
	ASSERT_BIR_EQ(f->getParam(1), arrIndexOpExpr->getIndex());
	ASSERT_BIR_EQ(f->getParam(2), storeStmt->getRhs());
}

TEST_F(BasicBlockConverterTests,
LoadFromArrayOfStructsIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }
		define void @function(i32 %index) {
			%arr = alloca [10 x %s], align 4
			%elemPtr = getelementptr inbounds [10 x %s], [10 x %s]* %arr, i64 0, i32 %index, i32 1
			%var = load i32, i32* %elemPtr, align 4
			ret void
		}
	)");

	//
	// struct s {int a, int b} arr[10];
	// int var;
	// var = arr[index].b;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefArr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefArr, "arr"));
	auto varDefVar = cast<VarDefStmt>(varDefArr->getSuccessor());
	ASSERT_TRUE(isVarDef<IntType>(varDefVar, "var"));
	auto loadStmt = cast<AssignStmt>(varDefVar->getSuccessor());
	ASSERT_TRUE(loadStmt);
	ASSERT_BIR_EQ(varDefVar->getVar(), loadStmt->getLhs());
	auto structIndexOpExpr = cast<StructIndexOpExpr>(loadStmt->getRhs());
	ASSERT_TRUE(structIndexOpExpr);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(structIndexOpExpr->getFirstOperand());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(varDefArr->getVar(), arrIndexOpExpr->getBase());
	ASSERT_BIR_EQ(f->getParam(1), arrIndexOpExpr->getIndex());
	ASSERT_TRUE(isa<ConstInt>(structIndexOpExpr->getSecondOperand()));
}

TEST_F(BasicBlockConverterTests,
VariableUsedInVolatileStoreLhsIsCorrectlyMarkedAsExternal) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %arg1) {
			%ptr = alloca i32, align 4
			store volatile i32 %arg1, i32* %ptr, align 4
			ret void
		}
	)");

	//
	// int ptr; // marked as external
	// ptr = arg1;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefPtr = cast<VarDefStmt>(f->getBody());
	auto varPtr = varDefPtr->getVar();
	ASSERT_TRUE(isVarDef<IntType>(varDefPtr, "ptr"));
	ASSERT_TRUE(varPtr->isExternal());
	ASSERT_TRUE(isAssignOfVarToVar(varDefPtr->getSuccessor(), varPtr,
		f->getParam(1)));
}

TEST_F(BasicBlockConverterTests,
VariableUsedVolatileLoadLhsIsCorrectlyMarkedAsExternal) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function() {
			%ptr = alloca i32, align 4
			%var = load volatile i32, i32* %ptr, align 4
			ret void
		}
	)");

	//
	// int ptr;
	// int var; // marked as external
	// var = ptr;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefPtr = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<IntType>(varDefPtr, "ptr"));
	auto varDefVar = cast<VarDefStmt>(varDefPtr->getSuccessor());
	auto varVar = varDefVar->getVar();
	ASSERT_TRUE(isVarDef<IntType>(varDefVar, "var"));
	ASSERT_TRUE(varVar->isExternal());
	ASSERT_TRUE(isAssignOfVarToVar(varDefVar->getSuccessor(), varVar,
		varDefPtr->getVar()));
}

//
// Tests for insertvalue and extractvalue instructions
//

TEST_F(BasicBlockConverterTests,
InsertValueToOnedimensionalArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function([10 x i32] %arr, i32 %value) {
			%a = insertvalue [10 x i32] %arr, i32 %value, 3
			ret void
		}
	)");

	//
	// int a[10];
	// a = arr;
	// a[3] = value;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefA = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefA, "a"));
	auto assignStmt = varDefA->getSuccessor();
	ASSERT_TRUE(isAssignOfVarToVar(assignStmt, varDefA->getVar(), f->getParam(1)));
	auto insertValStmt = cast<AssignStmt>(assignStmt->getSuccessor());
	ASSERT_TRUE(insertValStmt);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(insertValStmt->getLhs());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(varDefA->getVar(), arrIndexOpExpr->getBase());
	ASSERT_BIR_EQ(f->getParam(2), insertValStmt->getRhs());
	ASSERT_TRUE(isa<ConstInt>(arrIndexOpExpr->getIndex()));
}

TEST_F(BasicBlockConverterTests,
ExtractValueFromOnedimensionalArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function([10 x i32] %arr) {
			%x = extractvalue [10 x i32] %arr, 3
			ret i32 %x
		}
	)");

	//
	// return arr[3];
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(f->getParam(1), arrIndexOpExpr->getBase());
	ASSERT_TRUE(isa<ConstInt>(arrIndexOpExpr->getIndex()));
}

TEST_F(BasicBlockConverterTests,
InsertValueToMultidimensionalArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function([10 x [10 x i32]] %arr, i32 %value) {
			%a = insertvalue [10 x [10 x i32]] %arr, i32 %value, 3, 4
			ret void
		}
	)");

	//
	// int a[10][10];
	// a = arr;
	// a[3][4] = value;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefA = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefA, "a"));
	auto assignStmt = varDefA->getSuccessor();
	ASSERT_TRUE(isAssignOfVarToVar(assignStmt, varDefA->getVar(), f->getParam(1)));
	auto insertValStmt = cast<AssignStmt>(assignStmt->getSuccessor());
	ASSERT_TRUE(insertValStmt);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(insertValStmt->getLhs());
	ASSERT_TRUE(arrIndexOpExpr);
	auto innerArrIndexOpExpr = cast<ArrayIndexOpExpr>(arrIndexOpExpr->getBase());
	ASSERT_TRUE(innerArrIndexOpExpr);
	ASSERT_BIR_EQ(varDefA->getVar(), innerArrIndexOpExpr->getBase());
	auto index1 = cast<ConstInt>(innerArrIndexOpExpr->getIndex());
	ASSERT_TRUE(index1);
	ASSERT_EQ(3, index1->getValue());
	auto index2 = cast<ConstInt>(arrIndexOpExpr->getIndex());
	ASSERT_TRUE(index2);
	ASSERT_EQ(4, index2->getValue());
	ASSERT_BIR_EQ(f->getParam(2), insertValStmt->getRhs());
}

TEST_F(BasicBlockConverterTests,
ExtractValueFromMultidimensionalArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function([10 x [10 x i32]] %arr) {
			%x = extractvalue [10 x [10 x i32]] %arr, 3, 4
			ret i32 %x
		}
	)");

	//
	// return arr[3][4];
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(arrIndexOpExpr);
	auto innerArrIndexOpExpr = cast<ArrayIndexOpExpr>(arrIndexOpExpr->getBase());
	ASSERT_TRUE(innerArrIndexOpExpr);
	ASSERT_BIR_EQ(f->getParam(1), innerArrIndexOpExpr->getBase());
	auto index1 = cast<ConstInt>(innerArrIndexOpExpr->getIndex());
	ASSERT_TRUE(index1);
	ASSERT_EQ(3, index1->getValue());
	auto index2 = cast<ConstInt>(arrIndexOpExpr->getIndex());
	ASSERT_TRUE(index2);
	ASSERT_EQ(4, index2->getValue());
}

TEST_F(BasicBlockConverterTests,
InsertValueToStructIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }
		define void @function(%s %struct, i32 %value) {
			%a = insertvalue %s %struct, i32 %value, 1
			ret void
		}
	)");

	//
	// struct s {int a, int b} a;
	// a = struct;
	// a.b = value;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefA = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<StructType>(varDefA, "a"));
	auto assignStmt = varDefA->getSuccessor();
	ASSERT_TRUE(isAssignOfVarToVar(assignStmt, varDefA->getVar(), f->getParam(1)));
	auto insertValStmt = cast<AssignStmt>(assignStmt->getSuccessor());
	ASSERT_TRUE(insertValStmt);
	auto structIndexOpExpr = cast<StructIndexOpExpr>(insertValStmt->getLhs());
	ASSERT_TRUE(structIndexOpExpr);
	ASSERT_BIR_EQ(varDefA->getVar(), structIndexOpExpr->getFirstOperand());
	ASSERT_BIR_EQ(f->getParam(2), insertValStmt->getRhs());
	ASSERT_TRUE(isa<ConstInt>(structIndexOpExpr->getSecondOperand()));
}

TEST_F(BasicBlockConverterTests,
ExtractValueFromStructIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }
		define i32 @function(%s %struct) {
			%x = extractvalue %s %struct, 1
			ret i32 %x
		}
	)");

	//
	// return a.b;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto structIndexOpExpr = cast<StructIndexOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(structIndexOpExpr);
	ASSERT_BIR_EQ(f->getParam(1), structIndexOpExpr->getFirstOperand());
	ASSERT_TRUE(isa<ConstInt>(structIndexOpExpr->getSecondOperand()));
}

TEST_F(BasicBlockConverterTests,
InsertValueToArrayOfStructsIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }
		define void @function([10 x %s] %arr, i32 %value) {
			%a = insertvalue [10 x %s] %arr, i32 %value, 3, 1
			ret void
		}
	)");

	//
	// struct s {int a, int b} a[10];
	// a = arr;
	// a[3].b = value;
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefA = cast<VarDefStmt>(f->getBody());
	ASSERT_TRUE(isVarDef<ArrayType>(varDefA, "a"));
	auto assignStmt = varDefA->getSuccessor();
	ASSERT_TRUE(isAssignOfVarToVar(assignStmt, varDefA->getVar(), f->getParam(1)));
	auto insertValStmt = cast<AssignStmt>(assignStmt->getSuccessor());
	ASSERT_TRUE(insertValStmt);
	auto structIndexOpExpr = cast<StructIndexOpExpr>(insertValStmt->getLhs());
	ASSERT_TRUE(structIndexOpExpr);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(structIndexOpExpr->getFirstOperand());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(varDefA->getVar(), arrIndexOpExpr->getFirstOperand());
	auto index1 = cast<ConstInt>(arrIndexOpExpr->getIndex());
	ASSERT_TRUE(index1);
	ASSERT_EQ(3, index1->getValue());
	auto index2 = cast<ConstInt>(structIndexOpExpr->getSecondOperand());
	ASSERT_TRUE(index2);
	ASSERT_EQ(1, index2->getValue());
	ASSERT_BIR_EQ(f->getParam(2), insertValStmt->getRhs());
}

TEST_F(BasicBlockConverterTests,
ExtractValueFromArrayOfStructsIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }
		define i32 @function([10 x %s] %arr) {
			%x = extractvalue [10 x %s] %arr, 3, 1
			ret i32 %x
		}
	)");

	//
	// return arr[3].b;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto structIndexOpExpr = cast<StructIndexOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(structIndexOpExpr);
	auto arrIndexOpExpr = cast<ArrayIndexOpExpr>(structIndexOpExpr->getFirstOperand());
	ASSERT_TRUE(arrIndexOpExpr);
	ASSERT_BIR_EQ(f->getParam(1), arrIndexOpExpr->getFirstOperand());
	auto index1 = cast<ConstInt>(arrIndexOpExpr->getIndex());
	ASSERT_TRUE(index1);
	ASSERT_EQ(3, index1->getValue());
	auto index2 = cast<ConstInt>(structIndexOpExpr->getSecondOperand());
	ASSERT_TRUE(index2);
	ASSERT_EQ(1, index2->getValue());
}

//
// Tests for unreachable statement
//

TEST_F(BasicBlockConverterTests,
FunctionWithSingleUnreachableInstructionIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function() {
			unreachable
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(isa<UnreachableStmt>(f->getBody()));
}

//
// Tests for emission of the debug comments
//

TEST_F(BasicBlockConverterTests,
BasicBlockHasCorrectlySetDebugComment) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function() {
		dec_label_pc_8907f00:
			ret i32 1
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto body = f->getBody();
	ASSERT_TRUE(body);
	ASSERT_EQ("0x8907f00"s, body->getMetadata());
}

TEST_F(BasicBlockConverterTests,
EmptyBasicBlockHasCorrectlySetDebugComment) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function() {
		dec_label_pc_8907f00:
			br label %dec_label_pc_8907f08
		dec_label_pc_8907f08:
			ret i32 1
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto body = cast<EmptyStmt>(f->getBody());
	ASSERT_TRUE(body);
	ASSERT_EQ("0x8907f00"s, body->getMetadata());
	auto succ = body->getSuccessor();
	ASSERT_TRUE(succ);
	ASSERT_EQ("0x8907f08"s, succ->getMetadata());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
