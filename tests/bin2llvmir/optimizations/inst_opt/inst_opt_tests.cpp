/**
* @file tests/bin2llvmir/optimizations/inst_opt/tests/inst_opt_tests.cpp
* @brief Tests for the @c InstOpt pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c InstOpt pass.
 */
class InstOptTests : public LlvmIrTests
{
	protected:
		InstOpt pass;
};

////
//// registerNotRedefinedBetweenTwoLoads
////
//
//TEST_F(InstOptTests, registerNotRedefinedBetweenTwoLoads)
//{
//	auto module = addModuleToContext();
//
//	auto* func = cast<Function>(module->getOrInsertFunction(
//			"func",
//			Type::getVoidTy(context),
//			AttributeSet(),
//			nullptr));
//
//	auto* glob = cast<GlobalVariable>(module->getOrInsertGlobal(
//			"r",
//			Type::getInt32Ty(context)));
//
//	BasicBlock* bb = BasicBlock::Create(
//			context,
//			"bb",
//			func);
//
//	auto* l1 = new LoadInst(glob, "", bb);
//	auto* l2 = new LoadInst(glob, "", bb);
//	auto* op = BinaryOperator::CreateAdd(l1, l2, "", bb);
//
//	EXPECT_TRUE( pass.registerNotRedefinedBetweenTwoLoads(op, l1, l2) );
//
//	new StoreInst(l1, glob, l2);
//
//	EXPECT_FALSE( pass.registerNotRedefinedBetweenTwoLoads(op, l1, l2) );
//}
//
////
//// optimizeXorZeroIdiom
////
//
//TEST_F(InstOptTests, optimizeXorZeroIdiomReplacesXorByZeroAndRemovesUnusedInstructions)
//{
//	auto module = parseInput(R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			%b = load i32, i32* @r
//			%c = xor i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)");
//
//	pass.runOnModuleCustom(*module);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @func() {
//			%d = add i32 0, 1
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}
//
//TEST_F(InstOptTests, optimizeXorZeroIdiomReplacesXorByZeroButDoesNotRemoveUsedInstructions)
//{
//	auto module = parseInput(R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			%b = load i32, i32* @r
//			%c = xor i32 %a, %b
//			%d = add i32 %c, %a
//			ret void
//		}
//	)");
//
//	pass.runOnModuleCustom(*module);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			%d = add i32 0, %a
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}
//
//TEST_F(InstOptTests, optimizeXorZeroIdiomDoesNotReplaceXorByZeroIfRegisterRedefined)
//{
//	auto module = parseInput(R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			store i32 %a, i32* @r
//			%b = load i32, i32* @r
//			%c = xor i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)");
//
//	pass.runOnModuleCustom(*module);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			store i32 %a, i32* @r
//			%b = load i32, i32* @r
//			%c = xor i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}
//
//TEST_F(InstOptTests, optimizeXorZeroIdiomDoesNotReplaceXorByZeroIfDefsInDifferentBBs)
//{
//	auto module = parseInput(R"(
//		@r = global i32 0
//		define void @func() {
//		br label %b1
//		b1: ; preds = %0
//			%a = load i32, i32* @r
//		br label %b2
//		b2: ; preds = %b1
//			%b = load i32, i32* @r
//			%c = xor i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)");
//
//	pass.runOnModuleCustom(*module);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @func() {
//		br label %b1
//		b1: ; preds = %0
//			%a = load i32, i32* @r
//		br label %b2
//		b2: ; preds = %b1
//			%b = load i32, i32* @r
//			%c = xor i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}
//
////
//// optimizeOrIdiom
////
//
//TEST_F(InstOptTests, optimizeOrIdiomReplacesOrByFirstOperandAndRemovesUnusedInstructions)
//{
//	auto module = parseInput(R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			%b = load i32, i32* @r
//			%c = or i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)");
//
//	pass.runOnModuleCustom(*module);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			%d = add i32 %a, 1
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}
//
//TEST_F(InstOptTests, optimizeOrIdiomReplacesOrByFirstOperandButDoesNotRemoveUsedInstructions)
//{
//	auto module = parseInput(R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			%b = load i32, i32* @r
//			%c = or i32 %a, %b
//			%d = add i32 %c, %b
//			ret void
//		}
//	)");
//
//	pass.runOnModuleCustom(*module);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			%b = load i32, i32* @r
//			%d = add i32 %a, %b
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}
//
//TEST_F(InstOptTests, optimizeOrIdiomDoesNotReplaceOrByFirstOperandIfRegisterRedefined)
//{
//	auto module = parseInput(R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			store i32 %a, i32* @r
//			%b = load i32, i32* @r
//			%c = or i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)");
//
//	pass.runOnModuleCustom(*module);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @func() {
//			%a = load i32, i32* @r
//			store i32 %a, i32* @r
//			%b = load i32, i32* @r
//			%c = or i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}
//
//TEST_F(InstOptTests, optimizeOrIdiomDoesNotReplaceOrByFirstOperandIfDefsInDifferentBBs)
//{
//	auto module = parseInput(R"(
//		@r = global i32 0
//		define void @func() {
//		br label %b1
//		b1: ; preds = %0
//			%a = load i32, i32* @r
//		br label %b2
//		b2: ; preds = %b1
//			%b = load i32, i32* @r
//			%c = or i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)");
//
//	pass.runOnModuleCustom(*module);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @func() {
//		br label %b1
//		b1: ; preds = %0
//			%a = load i32, i32* @r
//		br label %b2
//		b2: ; preds = %b1
//			%b = load i32, i32* @r
//			%c = or i32 %a, %b
//			%d = add i32 %c, 1
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}

///**
// * @brief Tests for the @c InstOpt pass.
// */
//class DecfrontFixerTests: public LlvmIrTests
//{
//	protected:
//		DecfrontFixer pass;
//};
//
////
//// runOnModule()
////
//
//TEST_F(DecfrontFixerTests, passDoesNotSegfaultAndReturnsFalseIfConfigForModuleDoesNotExists)
//{
//	auto m = addModuleToContext();
//	bool b = pass.runOnModule(*m);
//
//	EXPECT_FALSE(b);
//}
//
//TEST_F(DecfrontFixerTests, passDoesNotSegfaultAndReturnsFalseIfNullptrConfigPassed)
//{
//	auto m = addModuleToContext();
//	bool b = pass.runOnModuleCustom(*m, nullptr);
//
//	EXPECT_FALSE(b);
//}
//
////
//// fixX86RepAnalysis()
////
//
//TEST_F(DecfrontFixerTests, fixX86RepAnalysis)
//{
//	auto module = parseInput(R"(
//		@eax = global i32 0
//		@edi = global i32 0
//		@ecx = global i32 0
//		@esi = global i32 0
//		@zf = global i1 false
//		define void @fnc() {
//			store volatile i64  0, i64* @llvm2asm, !asm !0
//			%a = add i32 0, 0
//			store volatile i64 10, i64* @llvm2asm, !asm !1
//			%b = add i32 0, 0
//			%c = add i32 0, 0
//			%d = add i32 0, 0
//			store volatile i64 20, i64* @llvm2asm, !asm !2
//			store volatile i64 30, i64* @llvm2asm, !asm !3
//			store volatile i64 40, i64* @llvm2asm, !asm !4
//			store volatile i64 50, i64* @llvm2asm, !asm !5
//			store volatile i64 60, i64* @llvm2asm, !asm !6
//			store volatile i64 70, i64* @llvm2asm, !asm !7
//			ret void
//		}
//
//		!0 = !{ !"some_dummy_name_1", i64  0, i64 10, !"asm", !"anot" }
//		!1 = !{ !"decode__instr_grp_rep__instr_stosd__", i64 10, i64 10, !"asm", !"anot" }
//		!2 = !{ !"decode__instr_grp_rep__instr_stosb__", i64 20, i64 10, !"asm", !"anot" }
//		!3 = !{ !"decode__instr_grp_repe__instr_cmpsb__", i64 30, i64 10, !"asm", !"anot" }
//		!4 = !{ !"decode__instr_grp_rep__instr_movsd__", i64 40, i64 10, !"asm", !"anot" }
//		!5 = !{ !"decode__instr_grp_rep__instr_movsb__", i64 50, i64 10, !"asm", !"anot" }
//		!6 = !{ !"decode__instr_grp_repne__instr_scasb__", i64 60, i64 10, !"asm", !"anot" }
//		!7 = !{ !"some_dummy_name_2", i64 70, i64 10, !"asm", !"anot" }
//		!8 = !{ !"llvm2asm" }
//		!llvmToAsmGlobalVariableName = !{ !8 }
//		@llvm2asm = global i64 0
//	)");
//	auto c = Config::fromJsonString(module.get(), R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "little",
//			"name" : "x86"
//		},
//		"llvmToAsmGlobalVariableName" : "llvm2asm",
//		"functions" : [
//			{
//				"endAddr" : 100,
//				"name" : "fnc",
//				"startAddr" : 0
//			}
//		],
//		"registers" : [
//			{
//				"name" : "eax",
//				"realName" : "eax",
//				"storage" : { "type" : "register", "value" : "eax",
//							"registerClass" : "gpr", "registerNumber" : 0 }
//			},
//			{
//				"name" : "ecx",
//				"realName" : "ecx",
//				"storage" : { "type" : "register", "value" : "ecx",
//							"registerClass" : "gpr", "registerNumber" : 1 }
//			},
//			{
//				"name" : "esi",
//				"realName" : "esi",
//				"storage" : { "type" : "register", "value" : "esi",
//							"registerClass" : "gpr", "registerNumber" : 6 }
//			},
//			{
//				"name" : "edi",
//				"realName" : "edi",
//				"storage" : { "type" : "register", "value" : "edi",
//							"registerClass" : "gpr", "registerNumber" : 7 }
//			},
//			{
//				"name" : "zf",
//				"realName" : "zf",
//				"storage" : { "type" : "register", "value" : "zf",
//							"registerClass" : "zf", "registerNumber" : 0 }
//			}
//		]
//	})");
//
//	auto* llvm2asmGv = getGlobalByName(module.get(), "llvm2asm");
//	c.setLlvmToAsmGlobalVariable(llvm2asmGv);
//
//	bool b = pass.runOnModuleCustom(*module, &c);
//
//	std::string exp = R"(
//		@eax = global i32 0
//		@edi = global i32 0
//		@ecx = global i32 0
//		@esi = global i32 0
//		@zf = global i1 false
//		define void @fnc() {
//			store volatile i64 0, i64* @llvm2asm, !asm !0
//			%a = add i32 0, 0
//			store volatile i64 10, i64* @llvm2asm, !asm !1
//			%1 = load i32, i32* @edi
//			%2 = load i32, i32* @eax
//			%3 = load i32, i32* @ecx
//			%4 = inttoptr i32 %1 to i8*
//			%5 = call i8* @memset(i8* %4, i32 %2, i32 %3)
//			%6 = ptrtoint i8* %5 to i32
//			store i32 %6, i32* @ecx
//			store volatile i64 20, i64* @llvm2asm, !asm !2
//			%7 = load i32, i32* @edi
//			%8 = load i32, i32* @eax
//			%9 = load i32, i32* @ecx
//			%10 = inttoptr i32 %7 to i8*
//			%11 = call i8* @memset(i8* %10, i32 %8, i32 %9)
//			%12 = ptrtoint i8* %11 to i32
//			store i32 %12, i32* @ecx
//			store volatile i64 30, i64* @llvm2asm, !asm !3
//			%13 = load i32, i32* @esi
//			%14 = load i32, i32* @edi
//			%15 = load i32, i32* @ecx
//			%16 = inttoptr i32 %14 to i8*
//			%17 = inttoptr i32 %13 to i8*
//			%18 = call i32 @strncmp(i8* %17, i8* %16, i32 %15)
//			store i32 %18, i32* @ecx
//			%19 = trunc i32 %18 to i1
//			%20 = xor i1 %19, true
//			store i1 %20, i1* @zf
//			store volatile i64 40, i64* @llvm2asm, !asm !4
//			%21 = load i32, i32* @edi
//			%22 = load i32, i32* @esi
//			%23 = load i32, i32* @ecx
//			%24 = inttoptr i32 %22 to i8*
//			%25 = inttoptr i32 %21 to i8*
//			%26 = call i8* @memcpy(i8* %25, i8* %24, i32 %23)
//			%27 = ptrtoint i8* %26 to i32
//			store i32 %27, i32* @ecx
//			store volatile i64 50, i64* @llvm2asm, !asm !5
//			%28 = load i32, i32* @edi
//			%29 = load i32, i32* @esi
//			%30 = load i32, i32* @ecx
//			%31 = inttoptr i32 %29 to i8*
//			%32 = inttoptr i32 %28 to i8*
//			%33 = call i8* @memcpy(i8* %32, i8* %31, i32 %30)
//			%34 = ptrtoint i8* %33 to i32
//			store i32 %34, i32* @ecx
//			store volatile i64 60, i64* @llvm2asm, !asm !6
//			%35 = load i32, i32* @edi
//			%36 = inttoptr i32 %35 to i8*
//			%37 = call i32 @strlen(i8* %36)
//			%38 = mul i32 %37, -1
//			%39 = sub i32 %38, 2
//			store i32 %39, i32* @ecx
//			store volatile i64 70, i64* @llvm2asm, !asm !7
//			ret void
//		}
//		declare i8* @memset(i8*, i32, i32)
//		declare i32 @strncmp(i8*, i8*, i32)
//		declare i8* @memcpy(i8*, i8*, i32)
//		declare i32 @strlen(i8*)
//		!0 = !{ !"some_dummy_name_1", i64  0, i64 10, !"asm", !"anot" }
//		!1 = !{ !"decode__instr_grp_rep__instr_stosd__", i64 10, i64 10, !"asm", !"anot" }
//		!2 = !{ !"decode__instr_grp_rep__instr_stosb__", i64 20, i64 10, !"asm", !"anot" }
//		!3 = !{ !"decode__instr_grp_repe__instr_cmpsb__", i64 30, i64 10, !"asm", !"anot" }
//		!4 = !{ !"decode__instr_grp_rep__instr_movsd__", i64 40, i64 10, !"asm", !"anot" }
//		!5 = !{ !"decode__instr_grp_rep__instr_movsb__", i64 50, i64 10, !"asm", !"anot" }
//		!6 = !{ !"decode__instr_grp_repne__instr_scasb__", i64 60, i64 10, !"asm", !"anot" }
//		!7 = !{ !"some_dummy_name_2", i64 70, i64 10, !"asm", !"anot" }
//		!8 = !{ !"llvm2asm" }
//		!llvmToAsmGlobalVariableName = !{ !8 }
//		@llvm2asm = global i64 0
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//	EXPECT_TRUE(b);
//}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
