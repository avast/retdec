/**
 * @file tests/bin2llvmir/utils/tests/instruction_tests.cpp
 * @brief Tests for the @c instruction utils module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>
#include <llvm/IR/Verifier.h>

#include "retdec/bin2llvmir/utils/instruction.h"
#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c instruction module.
 */
class InstructionTests: public LlvmIrTests
{

};

//
// isDirectCall(Instruction&)
// isDirectCall(Instruction*)
//

TEST_F(InstructionTests, isDirectCallReturnsTrueForDirectCall)
{
	parseInput(R"(
		define void @fnc() {
			call void @fnc()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_TRUE(isDirectCall(c));
	EXPECT_TRUE(isDirectCall(*c));
}

TEST_F(InstructionTests, isDirectCallReturnsFalseForIndirectCall)
{
	parseInput(R"(
		@r = global void()* null
		define void @fnc() {
			%c = load void()*, void()** @r
			call void %c()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_FALSE(isDirectCall(*c));
	EXPECT_FALSE(isDirectCall(c));
}

TEST_F(InstructionTests, isDirectCallReturnsFalseForNullptr)
{
	EXPECT_FALSE(isDirectCall(nullptr));
}

//
// isIndirectCall(Instruction&)
// isIndirectCall(Instruction*)
//

TEST_F(InstructionTests, isIndirectCallReturnsTrueForIndirectCall)
{
	parseInput(R"(
		@r = global void()* null
		define void @fnc() {
			%c = load void()*, void()** @r
			call void %c()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_TRUE(isIndirectCall(c));
	EXPECT_TRUE(isIndirectCall(c));
}

TEST_F(InstructionTests, isIndirectCallReturnsFalseForDirectCall)
{
	parseInput(R"(
		define void @fnc() {
			call void @fnc()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_FALSE(isIndirectCall(c));
	EXPECT_FALSE(isIndirectCall(c));
}

TEST_F(InstructionTests, isIndirectCallReturnsFalseForNullptr)
{
	EXPECT_FALSE(isIndirectCall(nullptr));
}

//
// isFncDeclarationCall(Instruction&)
// isFncDeclarationCall(Instruction*)
//

TEST_F(InstructionTests, isFncDeclarationCallReturnsTrueForFncDeclarationCall)
{
	parseInput(R"(
		declare void @import()
		define void @fnc() {
			call void @import()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_TRUE(isFncDeclarationCall(c));
	EXPECT_TRUE(isFncDeclarationCall(*c));
}

TEST_F(InstructionTests, isFncDeclarationCallReturnsFalseForFncDefinitionCall)
{
	parseInput(R"(
		define void @fnc() {
			call void @fnc()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_FALSE(isFncDeclarationCall(*c));
	EXPECT_FALSE(isFncDeclarationCall(c));
}

TEST_F(InstructionTests, isFncDeclarationCallReturnsFalseForIndirectCall)
{
	parseInput(R"(
		@r = global void()* null
		define void @fnc() {
			%c = load void()*, void()** @r
			call void %c()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_FALSE(isFncDeclarationCall(*c));
	EXPECT_FALSE(isFncDeclarationCall(c));
}

TEST_F(InstructionTests, isFncDeclarationCallReturnsFalseForNullptr)
{
	EXPECT_FALSE(isFncDeclarationCall(nullptr));
}

//
// isFncDefinitionCall(Instruction&)
// isFncDefinitionCall(Instruction*)
//

TEST_F(InstructionTests, isFncDefinitionCallReturnsTrueForFncDefinitionCall)
{
	parseInput(R"(
		define void @fnc() {
			call void @fnc()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_TRUE(isFncDefinitionCall(c));
	EXPECT_TRUE(isFncDefinitionCall(*c));
}

TEST_F(InstructionTests, isFncDefinitionCallReturnsFalseForFncDeclarationCall)
{
	parseInput(R"(
		declare void @import()
		define void @fnc() {
			call void @import()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_FALSE(isFncDefinitionCall(*c));
	EXPECT_FALSE(isFncDefinitionCall(c));
}

TEST_F(InstructionTests, isFncDefinitionCallReturnsFalseForIndirectCall)
{
	parseInput(R"(
		@r = global void()* null
		define void @fnc() {
			%c = load void()*, void()** @r
			call void %c()
			ret void
		}
	)");
	auto* c = getNthInstruction<CallInst>();

	EXPECT_FALSE(isFncDefinitionCall(*c));
	EXPECT_FALSE(isFncDefinitionCall(c));
}

TEST_F(InstructionTests, isFncDefinitionCallReturnsFalseForNullptr)
{
	EXPECT_FALSE(isFncDefinitionCall(nullptr));
}

//
// modifyReturnInst
//

TEST_F(InstructionTests, modifyReturnInstSucceedsWhenFunctionReturnTypeReturned)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");

	auto* i32 = Type::getInt32Ty(context);
	auto* r = ConstantInt::get(i32, 123);
	auto* fnc = cast<Function>(getValueByName("fnc"));
	auto c = Config::empty(module.get());
	modifyFunction(&c, fnc, i32, {});
	auto* ret = getNthInstruction<ReturnInst>();
	modifyReturnInst(ret, r);

	std::string exp = R"(
		@0 = external global i32
		define i32 @fnc() {
			ret i32 123
		}
		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyReturnInstSucceedsWhenFunctionReturnTypeNotReturned)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");

	auto* f = Type::getFloatTy(context);
	auto* i32 = Type::getInt32Ty(context);
	auto* r = ConstantInt::get(i32, 123);
	auto* fnc = cast<Function>(getValueByName("fnc"));
	auto c = Config::empty(module.get());
	modifyFunction(&c, fnc, f, {});
	auto* ret = getNthInstruction<ReturnInst>();
	modifyReturnInst(ret, r);

	std::string exp = R"(
		@0 = external global i32
		define float @fnc() {
			%1 = bitcast i32 123 to float
			ret float %1
		}
		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// modifyCallInst()
//

TEST_F(InstructionTests, modifyIndirectCallOnlyReturn)
{
	parseInput(R"(
		define void @fnc() {
			%a = alloca i32
			%b = bitcast i32* %a to void(i32, i32)*
			call void %b(i32 123, i32 456)
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	modifyCallInst(call, Type::getInt32Ty(context));

	std::string exp = R"(
		define void @fnc() {
			%a = alloca i32
			%b = bitcast i32* %a to void(i32, i32)*
			%1 = bitcast void(i32, i32)* %b to i32(i32, i32)*
			%2 = call i32 %1(i32 123, i32 456)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyDirectCallOnlyReturn)
{
	parseInput(R"(
		declare void @import(i32, i32)
		define void @fnc() {
			call void @import(i32 123, i32 456)
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	modifyCallInst(call, Type::getInt32Ty(context));

	std::string exp = R"(
		declare void @import(i32, i32)
		define void @fnc() {
			%1 = bitcast void(i32, i32)* @import to i32(i32, i32)*
			call i32 %1(i32 123, i32 456)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyIndirectCallOnlyArguments)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			%a = alloca i32
			%b = bitcast i32* %a to i32()*
			%c = call i32 %b()
			store i32 %c, i32* @r
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	auto* a1 = ConstantInt::get(Type::getInt32Ty(context), 123);
	auto* a2 = ConstantInt::get(Type::getInt32Ty(context), 456);
	modifyCallInst(call, {a1, a2});

	std::string exp = R"(
		@r = global i32 0
		define void @fnc() {
			%a = alloca i32
			%b = bitcast i32* %a to i32()*
			%1 = bitcast i32()* %b to i32(i32, i32)*
			%2 = call i32 %1(i32 123, i32 456)
			store i32 %2, i32* @r
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyDirectCallOnlyArguments)
{
	parseInput(R"(
		@r = global i32 0
		declare i32 @import()
		define void @fnc() {
			%a = call i32 @import()
			store i32 %a, i32* @r
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	auto* a1 = ConstantInt::get(Type::getInt32Ty(context), 123);
	auto* a2 = ConstantInt::get(Type::getInt32Ty(context), 456);
	modifyCallInst(call, {a1, a2});

	std::string exp = R"(
		@r = global i32 0
		declare i32 @import()
		define void @fnc() {
			%1 = bitcast i32()* @import to i32(i32, i32)*
			%2 = call i32 %1(i32 123, i32 456)
			store i32 %2, i32* @r
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyIndirectCallInstOfVoidCall)
{
	parseInput(R"(
		define void @fnc() {
			%a = alloca i32
			%b = bitcast i32* %a to void()*
			call void %b()
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	auto* a1 = ConstantInt::get(Type::getInt32Ty(context), 123);
	auto* a2 = ConstantInt::get(Type::getInt32Ty(context), 456);
	modifyCallInst(call, Type::getInt32Ty(context), {a1, a2});

	std::string exp = R"(
		define void @fnc() {
			%a = alloca i32
			%b = bitcast i32* %a to void()*
			%1 = bitcast void()* %b to i32(i32, i32)*
			%2 = call i32 %1(i32 123, i32 456)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyDirectCallInstOfVoidCall)
{
	parseInput(R"(
		declare void @import()
		define void @fnc() {
			call void @import()
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	auto* a1 = ConstantInt::get(Type::getInt32Ty(context), 123);
	auto* a2 = ConstantInt::get(Type::getInt32Ty(context), 456);
	modifyCallInst(call, Type::getInt32Ty(context), {a1, a2});

	std::string exp = R"(
		declare void @import()
		define void @fnc() {
			%1 = bitcast void()* @import to i32(i32, i32)*
			%2 = call i32 %1(i32 123, i32 456)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyIndirectCallFullModification)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			%a = alloca i32
			%b = bitcast i32* %a to i32(i32)*
			%a1 = load i32, i32* @r
			%c = call i32 %b(i32 %a1)
			store i32 %c, i32* @r
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	auto* a1 = ConstantInt::get(Type::getInt32Ty(context), 123);
	auto* a2 = ConstantInt::get(Type::getInt32Ty(context), 456);
	modifyCallInst(call, Type::getFloatTy(context), {a1, a2});

	std::string exp = R"(
		@r = global i32 0
		define void @fnc() {
			%a = alloca i32
			%b = bitcast i32* %a to i32(i32)*
			%a1 = load i32, i32* @r
			%1 = bitcast i32(i32)* %b to float(i32, i32)*
			%2 = call float %1(i32 123, i32 456)
			%3 = bitcast float %2 to i32
			store i32 %3, i32* @r
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyDirectCallFullModification)
{
	parseInput(R"(
		@r = global i32 0
		declare i32 @import(i32)
		define void @fnc() {
			%a1 = load i32, i32* @r
			%c = call i32 @import(i32 %a1)
			store i32 %c, i32* @r
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	auto* a1 = ConstantInt::get(Type::getInt32Ty(context), 123);
	auto* a2 = ConstantInt::get(Type::getInt32Ty(context), 456);
	modifyCallInst(call, Type::getFloatTy(context), {a1, a2});

	std::string exp = R"(
		@r = global i32 0
		declare i32 @import(i32)
		define void @fnc() {
			%a1 = load i32, i32* @r
			%1 = bitcast i32(i32)* @import to float(i32, i32)*
			%2 = call float %1(i32 123, i32 456)
			%3 = bitcast float %2 to i32
			store i32 %3, i32* @r
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// addToVariadicCallInst()
//

TEST_F(InstructionTests, addToVariadicCallInstAddsNewArguments)
{
	parseInput(R"(
		@r = global i32 0
		@format = constant [6 x i8] c"\25d \25d\00"
		declare i32 @scanf (i8*, ...)
		define void @fnc() {
			%c = call i32 (i8*, ...) @scanf(i8* getelementptr inbounds([6 x i8], [6 x i8]* @format, i64 0, i64 0))
			store i32 %c, i32* @r
			ret void
		}
	)");
	auto* call = getNthInstruction<CallInst>();

	auto* a1 = ConstantInt::get(Type::getInt32Ty(context), 123);
	auto* a2 = ConstantInt::get(Type::getInt32Ty(context), 456);
	addToVariadicCallInst(call, {a1, a2});

	std::string exp = R"(
		@r = global i32 0
		@format = constant [6 x i8] c"\25d \25d\00"
		declare i32 @scanf (i8*, ...)
		define void @fnc() {
			%1 = call i32 (i8*, ...) @scanf(i8* getelementptr inbounds([6 x i8], [6 x i8]* @format, i64 0, i64 0), i32 123, i32 456)
			store i32 %1, i32* @r
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// modifyFunction
//

TEST_F(InstructionTests, modifyFunctionVoid)
{
	parseInput(R"(
		declare void @import()
		define void @fnc1() {
			call void @import()
			ret void
		}
		define void @fnc2() {
			call void @import()
			ret void
		}
	)");
	auto* import = cast<Function>(getValueByName("import"));
	auto* call1 = getNthInstruction<CallInst>();
	auto* call2 = getNthInstruction<CallInst>(1);

	auto* i32 = Type::getInt32Ty(context);
	auto* a1 = ConstantInt::get(i32, 123);
	auto* a2 = ConstantInt::get(i32, 456);

	auto c = Config::empty(module.get());
	modifyFunction(
			&c,
			import,
			i32,
			{i32},
			false,
			std::map<ReturnInst*, Value*>(),
			{{call1, {a1}}, {call2, {a2}}});

	std::string exp = R"(
		declare i32 @import(i32)
		declare void @0()
		define void @fnc1() {
			%1 = call i32 @import(i32 123)
			ret void
		}
		define void @fnc2() {
			%1 = call i32 @import(i32 456)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyFunctionWithZeroArguments)
{
	parseInput(R"(
		define void @userDef() {
			ret void
		}
		define void @fnc1() {
			call void @userDef()
			ret void
		}
		define void @fnc2() {
			call void @userDef()
			ret void
		}
	)");
	auto* call1 = getNthInstruction<CallInst>();
	auto* call2 = getNthInstruction<CallInst>(1);
	auto* ret = getNthInstruction<ReturnInst>();
	auto* i32 = Type::getInt32Ty(context);
	auto* a1 = ConstantInt::get(i32, 123);
	auto* a2 = ConstantInt::get(i32, 456);
	auto* r = ConstantInt::get(i32, 789);
	auto* userDef = cast<Function>(getValueByName("userDef"));

	auto c = Config::empty(module.get());
	modifyFunction(
			&c,
			userDef,
			i32,
			{i32},
			false,
			{{ret, r}},
			{{call1, {a1}}, {call2, {a2}}});

	std::string exp = R"(
		define i32 @userDef(i32 %arg1) {
			ret i32 789
		}
		declare void @0()
		define void @fnc1() {
			%1 = call i32 @userDef(i32 123)
			ret void
		}
		define void @fnc2() {
			%1 = call i32 @userDef(i32 456)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyFunctionWithExistingArguments)
{
	parseInput(R"(
		define i32 @fnc(i32 %a1, i32 %a2, i32 %a3) {
			ret i32 0
			ret i32 1
		}
		define i32 @fnc1() {
			%1 = call i32 @fnc(i32 1, i32 2, i32 3)
			ret i32 %1
		}
		define i32 @fnc2() {
			%1 = call i32 @fnc(i32 4, i32 5, i32 6)
			ret i32 %1
		}
	)");
	auto* fnc = cast<Function>(getValueByName("fnc"));

	auto* i32 = Type::getInt32Ty(context);
	auto* f = Type::getFloatTy(context);
	auto* d = Type::getDoubleTy(context);
	auto c = Config::empty(module.get());
	modifyFunction(&c, fnc, f, {f, i32, d});

	std::string exp = R"(
		define float @fnc(float %a1, i32 %a2, double %a3) {
			%1 = bitcast i32 0 to float
			ret float %1
			%3 = bitcast i32 1 to float
			ret float %3
		}
		declare i32 @0(i32, i32, i32)
		define i32 @fnc1() {
			%1 = bitcast i32 1 to float
			%2 = sext i32 3 to i64
			%3 = bitcast i64 %2 to double
			%4 = call float @fnc(float %1, i32 2, double %3)
			%5 = bitcast float %4 to i32
			ret i32 %5
		}
		define i32 @fnc2() {
			%1 = bitcast i32 4 to float
			%2 = sext i32 6 to i64
			%3 = bitcast i64 %2 to double
			%4 = call float @fnc(float %1, i32 5, double %3)
			%5 = bitcast float %4 to i32
			ret i32 %5
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, modifyFunctionVariadic)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
		define i32 @fnc1() {
			call void @fnc()
			ret i32 0
		}
		define i32 @fnc2() {
			call void @fnc()
			ret i32 0
		}
	)");
	auto* fnc = cast<Function>(getValueByName("fnc"));
	auto* c1 = getNthInstruction<CallInst>();
	auto* c2 = getNthInstruction<CallInst>(1);
	auto* ret = getNthInstruction<ReturnInst>();
	auto* i32 = Type::getInt32Ty(context);
	auto* ci = ConstantInt::get(i32, 0);

	auto c = Config::empty(module.get());
	modifyFunction(
			&c,
			fnc,
			i32,
			{i32},
			true,
			{{ret, ci}},
			{{c1, {ci, ci}}, {c2, {ci, ci, ci, ci}}});

	std::string exp = R"(
		target datalayout = "e-p:32:32:32-f80:32:32"
		define i32 @fnc(i32 %arg1, ...) {
			ret i32 0
		}
		declare void @0()
		define i32 @fnc1() {
			%1 = call i32 (i32, ...) @fnc(i32 0, i32 0)
			ret i32 0
		}
		define i32 @fnc2() {
			%1 = call i32 (i32, ...) @fnc(i32 0, i32 0, i32 0, i32 0)
			ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// insertAtBegin
//

TEST_F(InstructionTests, insertAtBeginOfNonEmptyBasicBlock)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	auto* ret = getNthInstruction<ReturnInst>();

	auto* i32 = Type::getInt32Ty(context);
	auto* v = ConstantInt::get(i32, 123);
	auto* add = BinaryOperator::CreateAdd(v, v);
	insertAtBegin(add, ret->getParent());

	std::string exp = R"(
		define void @fnc() {
			%1 = add i32 123, 123
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, insertAtBeginOfEmptyBasicBlock)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	auto* fnc = cast<Function>(getValueByName("fnc"));
	auto* b = BasicBlock::Create(context, "", fnc);
	EXPECT_TRUE(b->empty());

	auto* i32 = Type::getInt32Ty(context);
	auto* v = ConstantInt::get(i32, 123);
	auto* add = BinaryOperator::CreateAdd(v, v);
	insertAtBegin(add, b);

	EXPECT_FALSE(b->empty());
	EXPECT_EQ(add, &b->front());
}

//
// splitFunctionOn()
//

TEST_F(InstructionTests, splitFunctionOnBasic)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 0, 0
			%b = add i32 0, 0
			ret void
		}
	)");
	auto* b = getInstructionByName("b");

	auto* newFnc = splitFunctionOn(b);

	std::string exp = R"(
		define void @fnc() {
			%a = add i32 0, 0
			ret void
		}
		define void @0() {
			%b = add i32 0, 0
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	ASSERT_NE(nullptr, newFnc);
	EXPECT_TRUE(newFnc->getName().empty());
}

TEST_F(InstructionTests, splitFunctionOnWithName)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 0, 0
			%b = add i32 0, 0
			ret void
		}
	)");
	auto* b = getInstructionByName("b");

	splitFunctionOn(b, "new_func_name");

	std::string exp = R"(
		define void @fnc() {
			%a = add i32 0, 0
			ret void
		}
		define void @new_func_name() {
			%b = add i32 0, 0
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, splitFunctionOnReturnFloat)
{
	parseInput(R"(
		define float @fnc() {
			%a = add i32 0, 0
			%b = add i32 0, 0
			ret float 1.25
		}
	)");
	auto* b = getInstructionByName("b");

	splitFunctionOn(b);

	std::string exp = R"(
		define float @fnc() {
			%a = add i32 0, 0
			ret float 0.000000e+00
		}
		define float @0() {
			%b = add i32 0, 0
			ret float 1.25
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, splitFunctionOnBasicBlockStart)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 0, 0
			br label %dec_label_pc_1
		dec_label_pc_1:
			%b = add i32 0, 0
			ret void
		}
	)");
	auto* b = getInstructionByName("b");

	splitFunctionOn(b);

	std::string exp = R"(
		target datalayout = "e-p:32:32:32-f80:32:32"
		define void @fnc() {
			%a = add i32 0, 0
			br label %dec_label_pc_1
		dec_label_pc_1:
			ret void
		}
		define void @0() {
			%b = add i32 0, 0
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, splitFunctionMultipleBbs)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i1 0, 0
			%b = add i1 0, 0
			br label %lab_1
		lab_1:
			%c = add i1 0, 0
			br i1 %c, label %lab_true, label %lab_after
		lab_true:
			%d = add i32 0, 0
			br label %lab_after
		lab_after:
			ret void
		}
	)");
	auto* b = getInstructionByName("b");

	splitFunctionOn(b);

	std::string exp = R"(
		define void @fnc() {
			%a = add i1 0, 0
			ret void
		}
		define void @0() {
			%b = add i1 0, 0
			br label %lab_1
		lab_1:
			%c = add i1 0, 0
			br i1 %c, label %lab_true, label %lab_after
		lab_true:
			%d = add i32 0, 0
			br label %lab_after
		lab_after:
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstructionTests, splitFunctionOnReferencedBb)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 0, 0
			br label %dec_label_pc_0
		dec_label_pc_0:
			%b = add i32 0, 0
			br label %dec_label_pc_0
			ret void
		}
	)");
	auto* b = getInstructionByName("b");

	splitFunctionOn(b);

	std::string exp = R"(
		define void @fnc() {
			%a = add i32 0, 0
			br label %dec_label_pc_0
		dec_label_pc_0:
			ret void
		}
		define void @0() {
			br label %1
			%b = add i32 0, 0
			br label %1
			ret void
		}
	)";

	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
