/**
 * @file tests/bin2llvmir/providers/tests/asm_instruction_tests.cpp
 * @brief Tests for the @c AsmInstruction class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c instruction module.
 */
class AsmInstructionTests: public LlvmIrTests
{

};

//
// getLlvmToAsmGlobalVariable()
//

TEST_F(AsmInstructionTests, getLlvmToAsmGlobalVariableReturnsNullptrIfNullptrModule)
{
	auto* gv = AsmInstruction::getLlvmToAsmGlobalVariable(nullptr);

	EXPECT_EQ(nullptr, gv);
}

TEST_F(AsmInstructionTests, getLlvmToAsmGlobalVariableFindsGlobal)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* ref = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), ref);
	auto* gv = AsmInstruction::getLlvmToAsmGlobalVariable(module.get());

	EXPECT_NE(nullptr, gv);
	EXPECT_EQ(ref, gv);
}

TEST_F(AsmInstructionTests, getLlvmToAsmGlobalVariableDoesNotFindGlobal)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* gv = AsmInstruction::getLlvmToAsmGlobalVariable(module.get());

	EXPECT_EQ(nullptr, gv);
}

//
// getInstructionAddress()
//

TEST_F(AsmInstructionTests, getInstructionAddressReturnsUndefAddressForNUllptr)
{
	auto addr = AsmInstruction::getInstructionAddress(nullptr);

	EXPECT_TRUE(addr.isUndefined());
}

TEST_F(AsmInstructionTests, getInstructionAddressReturnsUndefAddressIfNotAddrInfo)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 0, 1
			ret void
		}
	)");
	auto* a = getInstructionByName("a");

	auto addr = AsmInstruction::getInstructionAddress(a);

	ASSERT_NE(nullptr, a);
	EXPECT_TRUE(addr.isUndefined());
}

TEST_F(AsmInstructionTests, getInstructionAddressReturnsAddressIfAddrInfoAvailable)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 0, 1
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* a = getInstructionByName("a");

	auto addr = AsmInstruction::getInstructionAddress(a);

	ASSERT_NE(nullptr, a);
	EXPECT_TRUE(addr.isDefined());
	EXPECT_EQ(1234, addr);
}

//
// getBasicBlockAddress()
//

TEST_F(AsmInstructionTests, getBasicBlockAddressReturnsUndefAddressIfNotAddrInfo)
{
	parseInput(R"(
		define void @fnc() {
		bb:
			%a = add i32 0, 1
			ret void
		}
	)");
	auto* bb = getInstructionByName("a")->getParent();
	ASSERT_NE(nullptr, bb);

	auto addr = AsmInstruction::getBasicBlockAddress(bb);
	EXPECT_TRUE(addr.isUndefined());
}

TEST_F(AsmInstructionTests, getBasicBlockAddressReturnsAddressIfAddrInfoAvailable)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 0, 1
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* bb = getInstructionByName("a")->getParent();
	ASSERT_NE(nullptr, bb);

	auto addr = AsmInstruction::getBasicBlockAddress(bb);

	EXPECT_TRUE(addr.isDefined());
	EXPECT_EQ(1234, addr);
}

//
// isLlvmToAsmInstruction()
//

TEST_F(AsmInstructionTests, isLlvmToAsmInstructionReturnsFalseForNullptr)
{
	bool b = AsmInstruction::isLlvmToAsmInstruction(nullptr);

	EXPECT_FALSE(b);
}

TEST_F(AsmInstructionTests, isLlvmToAsmInstructionReturnsTrueForMapInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* ref = getNthInstruction<StoreInst>();
	bool b = AsmInstruction::isLlvmToAsmInstruction(ref);

	EXPECT_TRUE(b);
}

TEST_F(AsmInstructionTests, isLlvmToAsmInstructionReturnsFalseForNotMapInstructions)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i64 1234, 0
			store volatile i64 %a, i64* @gv
			ret void
		}
		@gv = global i64 0
	)");
	auto* a = getNthInstruction<BinaryOperator>();
	auto* s = getNthInstruction<StoreInst>();
	auto* r = getNthInstruction<ReturnInst>();

	EXPECT_FALSE(AsmInstruction::isLlvmToAsmInstruction(a));
	EXPECT_FALSE(AsmInstruction::isLlvmToAsmInstruction(s));
	EXPECT_FALSE(AsmInstruction::isLlvmToAsmInstruction(r));
}

//
// AsmInstruction()
//

TEST_F(AsmInstructionTests, AsmInstructionDefaultCtor)
{
	auto a = AsmInstruction();

	EXPECT_FALSE(a.isValid());
	EXPECT_FALSE(a);
	EXPECT_TRUE(a.isInvalid());
}

//
// AsmInstruction(llvm::Instruction*)
//

TEST_F(AsmInstructionTests, AsmInstructionCtorInstructionConstructsInvalidForNullptr)
{
	llvm::Instruction* i = nullptr;
	auto a = AsmInstruction(i);

	EXPECT_FALSE(a.isValid());
	EXPECT_FALSE(a);
	EXPECT_TRUE(a.isInvalid());
}

TEST_F(AsmInstructionTests, AsmInstructionCtorInstructionConstructsValidForMapInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* ref = getNthInstruction<StoreInst>();
	auto a = AsmInstruction(ref);

	EXPECT_TRUE(a.isValid());
	EXPECT_TRUE(a);
	EXPECT_FALSE(a.isInvalid());
	EXPECT_EQ(ref, a.getLlvmToAsmInstruction());
}

TEST_F(AsmInstructionTests, AsmInstructionCtorInstructionConstructsValidForOrdinaryInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			%b = mul i32 %a, 3
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* ref = getNthInstruction<StoreInst>();
	auto* ret = getNthInstruction<ReturnInst>();
	auto a = AsmInstruction(ret);

	EXPECT_TRUE(a.isValid());
	EXPECT_TRUE(a);
	EXPECT_EQ(ref, a.getLlvmToAsmInstruction());
}

TEST_F(AsmInstructionTests, AsmInstructionCtorInstructionConstructsValidIfInDifferentBbs)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			%a = add i32 1, 2
			%b = mul i32 %a, 3
			br label %lab_1
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* ref = getNthInstruction<StoreInst>();
	auto* ret = getNthInstruction<ReturnInst>();
	auto a = AsmInstruction(ret);

	EXPECT_TRUE(a.isValid());
	EXPECT_TRUE(a);
	EXPECT_EQ(ref, a.getLlvmToAsmInstruction());
}

//
// AsmInstruction(llvm::Module*, retdec::utils::Address)
//

TEST_F(AsmInstructionTests, AsmInstructionCtorAddressConstructsInvalidForNullptr)
{
	auto a = AsmInstruction(nullptr, 0x1234);

	EXPECT_FALSE(a.isValid());
	EXPECT_TRUE(a.isInvalid());
}

TEST_F(AsmInstructionTests, AsmInstructionCtorAddressConstructsInvalidForBadAddress)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 123);

	EXPECT_TRUE(a.isInvalid());
}

TEST_F(AsmInstructionTests, AsmInstructionCtorAddressConstructsInvalidForBadButUsedAddress)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @gv
			ret void
		}
		@gv = global i64 0
	)");
	auto a = AsmInstruction(module.get(), 1234);

	EXPECT_TRUE(a.isInvalid());
}

TEST_F(AsmInstructionTests, AsmInstructionCtorAddressConstructsValidForGoodAddress)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* ref = getNthInstruction<StoreInst>();
	auto a = AsmInstruction(module.get(), 1234);

	EXPECT_TRUE(a.isValid());
	EXPECT_FALSE(a.isInvalid());
	EXPECT_EQ(ref, a.getLlvmToAsmInstruction());
}

//
// AsmInstruction(llvm::Function*)
//

TEST_F(AsmInstructionTests, AsmInstructionCtorFunctionConstructsInvalidForNullptr)
{
	llvm::Function* f = nullptr;
	auto a = AsmInstruction(f);

	EXPECT_FALSE(a.isValid());
	EXPECT_TRUE(a.isInvalid());
}

TEST_F(AsmInstructionTests, AsmInstructionCtorFunctionConstructsValidForMapInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* ref = getNthInstruction<StoreInst>();
	auto* f = getFunctionByName("fnc");
	auto a = AsmInstruction(f);

	EXPECT_TRUE(a.isValid());
	EXPECT_FALSE(a.isInvalid());
	EXPECT_EQ(ref, a.getLlvmToAsmInstruction());
}

TEST_F(AsmInstructionTests, AsmInstructionCtorFunctionConstructsInvalidIfNoSpecialInstructionInFunction)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 1, 2
			%b = mul i32 %a, 3
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* f = getFunctionByName("fnc");
	auto a = AsmInstruction(f);

	EXPECT_TRUE(a.isInvalid());
}

//
// operator==()
//

TEST_F(AsmInstructionTests, AsmInstructionInvalidEq)
{
	auto a1 = AsmInstruction();
	auto a2 = AsmInstruction();

	EXPECT_TRUE(a1.isInvalid());
	EXPECT_EQ(a1, a2);
	EXPECT_FALSE(a1 != a2);
}

TEST_F(AsmInstructionTests, AsmInstructionValidEq)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a1 = AsmInstruction(module.get(), 1234);
	auto a2 = AsmInstruction(module.get(), 1234);

	EXPECT_TRUE(a1.isValid());
	EXPECT_EQ(a1, a2);
	EXPECT_FALSE(a1 != a2);
}

//
// operator!=()
//

TEST_F(AsmInstructionTests, AsmInstructionValidInvalidNeq)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a1 = AsmInstruction(module.get(), 1234);
	auto a2 = AsmInstruction();

	EXPECT_TRUE(a1.isValid());
	EXPECT_TRUE(a2.isInvalid());
	EXPECT_NE(a1, a2);
	EXPECT_FALSE(a1 == a2);
}

TEST_F(AsmInstructionTests, AsmInstructionValidValidNeq)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a1 = AsmInstruction(module.get(), 1234);
	auto a2 = AsmInstruction(module.get(), 5678);

	EXPECT_TRUE(a1.isValid());
	EXPECT_TRUE(a2.isValid());
	EXPECT_NE(a1, a2);
	EXPECT_FALSE(a1 == a2);
}

//
// getInstructions()
//

TEST_F(AsmInstructionTests, getInstructionsReturnsCorrectInstructions)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			br label %lab_1
			store volatile i64 5678, i64* @llvm2asm
			%d = mul i32 1, 2
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto* a = getInstructionByName("a");
	auto* b0 = getNthInstruction<BranchInst>();
	auto* b1 = getNthInstruction<BranchInst>(1);
	auto* b = getInstructionByName("b");
	auto* c = getInstructionByName("c");
	auto* b2 = getNthInstruction<BranchInst>(2);
	auto* d = getInstructionByName("d");
	auto* r = getNthInstruction<ReturnInst>();
	std::vector<llvm::Instruction*> a1Inst = {a, b0, b1, b, c, b2};
	std::vector<llvm::Instruction*> a2Inst = {d, r};
	auto a1 = AsmInstruction(module.get(), 1234);
	auto a2 = AsmInstruction(module.get(), 5678);

	EXPECT_TRUE(a1.isValid());
	EXPECT_EQ(a1Inst, a1.getInstructions());
	EXPECT_TRUE(a2.isValid());
	EXPECT_EQ(a2Inst, a2.getInstructions());
}

TEST_F(AsmInstructionTests, getInstructionsReturnsEmptyIfNoInstructions)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			%a = mul i32 1, 2
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);

	EXPECT_TRUE(a.isValid());
	EXPECT_TRUE(a.getInstructions().empty());
}

//
// instructionsCanBeErased()
//

TEST_F(AsmInstructionTests, instructionCanBeErasedWhenEmpty)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			%a = mul i32 1, 2
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);

	EXPECT_TRUE(a.isValid());
	EXPECT_TRUE(a.instructionsCanBeErased());
}

TEST_F(AsmInstructionTests, instructionCanBeErased)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			%b = mul i32 %a, %b
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);

	EXPECT_TRUE(a.isValid());
	EXPECT_TRUE(a.instructionsCanBeErased());
}

TEST_F(AsmInstructionTests, instructionCanNotBeErased)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			store volatile i64 5678, i64* @llvm2asm
			%b = mul i32 %a, 3
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);

	EXPECT_TRUE(a.isValid());
	EXPECT_FALSE(a.instructionsCanBeErased());
}

TEST_F(AsmInstructionTests, instructionCanNotBeErasedBecauseOfTerminatingBranch)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 123, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_456
		lab_456:
			%b = add i32 1, 2
			store volatile i64 456, i64* @llvm2asm
			%c = add i32 1, 2
			store volatile i64 789, i64* @llvm2asm
			br label %lab_456
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 123);

	EXPECT_TRUE(a.isValid());
	EXPECT_FALSE(a.instructionsCanBeErased());
}

TEST_F(AsmInstructionTests, instructionCanBeErasedEvenIfBbStartInTheMiddle)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			%b = mul i32 %a, 3
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);

	EXPECT_TRUE(a.isValid());
	EXPECT_TRUE(a.instructionsCanBeErased());
}

//
// eraseInstructions()
//

TEST_F(AsmInstructionTests, eraseInstructionsSuccessfullyErasesAllInstructions)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			%b = mul i32 %a, 3
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);
	bool b = a.eraseInstructions();

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_TRUE(b);
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, eraseInstructionsFailsToEraseInstructionsButDoesNotChangeThem)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			store volatile i64 5678, i64* @llvm2asm
			%b = mul i32 %a, 3
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);
	bool b = a.eraseInstructions();

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			store volatile i64 5678, i64* @llvm2asm
			%b = mul i32 %a, 3
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_FALSE(b);
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, eraseInstructionsBasicBlocks1)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 123, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			store volatile i64 456, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 123);
	bool b = a.eraseInstructions();

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 123, i64* @llvm2asm
			br label %lab_0
		lab_0:
			store volatile i64 456, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_TRUE(b);
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, eraseInstructionsBasicBlocks2)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 123, i64* @llvm2asm
			br i1 1, label %true, label %false
		true:
			%a = add i32 1, 2
			br label %false
		false:
			store volatile i64 456, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 123);
	bool b = a.eraseInstructions();

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 123, i64* @llvm2asm
			br label %false
		false:
			store volatile i64 456, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_TRUE(b);
	checkModuleAgainstExpectedIr(exp);
}

//
// getNext()
//

TEST_F(AsmInstructionTests, getNextReturnInvalidForInvalid)
{
	auto a = AsmInstruction();
	auto b = a.getNext();

	EXPECT_TRUE(b.isInvalid());
}

TEST_F(AsmInstructionTests, getNextReturnValidNext)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			br label %lab_1
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ref = AsmInstruction(module.get(), 5678);
	auto a1 = AsmInstruction(module.get(), 1234);
	auto a2 = a1.getNext();

	EXPECT_TRUE(a2.isValid());
	EXPECT_EQ(ref, a2);
}

TEST_F(AsmInstructionTests, getNextReturnInvalidNextForLast)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a1 = AsmInstruction(module.get(), 1234);
	auto a2 = a1.getNext();

	EXPECT_TRUE(a1.isValid());
	EXPECT_TRUE(a2.isInvalid());
}

//
// getPrev()
//

TEST_F(AsmInstructionTests, getPrevReturnInvalidForInvalid)
{
	auto a = AsmInstruction();
	auto b = a.getPrev();

	EXPECT_TRUE(b.isInvalid());
}

TEST_F(AsmInstructionTests, getPrevReturnValidprev)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			br label %lab_1
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ref = AsmInstruction(module.get(), 1234);
	auto a1 = AsmInstruction(module.get(), 5678);
	auto a2 = a1.getPrev();

	EXPECT_TRUE(a2.isValid());
	EXPECT_EQ(ref, a2);
}

TEST_F(AsmInstructionTests, getPrevReturnInvalidNextForFirst)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a1 = AsmInstruction(module.get(), 1234);
	auto a2 = a1.getPrev();

	EXPECT_TRUE(a1.isValid());
	EXPECT_TRUE(a2.isInvalid());
}

//
// front()
//

TEST_F(AsmInstructionTests, frontForInvalidReturnsNullptr)
{
	auto a = AsmInstruction();

	ASSERT_TRUE(a.isInvalid());
	EXPECT_EQ(nullptr, a.front());
}

TEST_F(AsmInstructionTests, frontForValidButEmptyReturnsNullptr)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);

	ASSERT_TRUE(a.isValid());
	EXPECT_EQ(nullptr, a.front());
}

TEST_F(AsmInstructionTests, frontForValidNonEmptyReturnsFirstInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);
	auto* ref = getInstructionByName("a");

	ASSERT_NE(nullptr, ref);
	EXPECT_EQ(ref, a.front());
}

//
// back()
//

TEST_F(AsmInstructionTests, backForInvalidReturnsNullptr)
{
	auto a = AsmInstruction();

	ASSERT_TRUE(a.isInvalid());
	EXPECT_EQ(nullptr, a.back());
}

TEST_F(AsmInstructionTests, backForValidButEmptyReturnsNullptr)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);

	ASSERT_TRUE(a.isValid());
	EXPECT_EQ(nullptr, a.back());
}

TEST_F(AsmInstructionTests, backForValidNonEmptyReturnsLastInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			br label %lab_1
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);
	auto* ref = getNthInstruction<BranchInst>(2);

	ASSERT_NE(nullptr, ref);
	EXPECT_EQ(ref, a.back());
}

//
// insertBack()
//

TEST_F(AsmInstructionTests, insertBackForInvalidDoesNotInsert)
{
	auto a = AsmInstruction();
	auto* i = new AllocaInst(Type::getInt32Ty(module->getContext()));

	ASSERT_TRUE(a.isInvalid());
	ASSERT_NE(nullptr, i);
	EXPECT_EQ(nullptr, a.front());
	EXPECT_EQ(nullptr, a.back());

	a.insertBack(i);

	EXPECT_EQ(nullptr, a.front());
	EXPECT_EQ(nullptr, a.back());
	delete i;
}

TEST_F(AsmInstructionTests, insertBackForValidComplexAsmInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);
	auto* i = new AllocaInst(Type::getInt32Ty(module->getContext()), "test");

	a.insertBack(i);

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			%test = alloca i32
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// insertBackSafe()
//

TEST_F(AsmInstructionTests, insertBackSafeForInvalidDoesNotInsert)
{
	auto a = AsmInstruction();
	auto* i = new AllocaInst(Type::getInt32Ty(module->getContext()));

	ASSERT_TRUE(a.isInvalid());
	ASSERT_NE(nullptr, i);
	EXPECT_EQ(nullptr, a.front());
	EXPECT_EQ(nullptr, a.back());

	a.insertBackSafe(i);

	EXPECT_EQ(nullptr, a.front());
	EXPECT_EQ(nullptr, a.back());
	delete i;
}

TEST_F(AsmInstructionTests, insertBackSafeForValidComplexAsmInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);
	auto* i = new AllocaInst(Type::getInt32Ty(module->getContext()), "test");

	a.insertBackSafe(i);

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			%test = alloca i32
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, insertBackSafeForTerminatorAsmInstruction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto a = AsmInstruction(module.get(), 1234);
	auto* i = new AllocaInst(Type::getInt32Ty(module->getContext()), "test");

	a.insertBackSafe(i);

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%test = alloca i32
			ret void
		}
		@llvm2asm = global i64 0
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// iterator
//

TEST_F(AsmInstructionTests, iteratorInvalid)
{
	auto ai = AsmInstruction();

	EXPECT_EQ(ai.end(), ai.begin());
}

TEST_F(AsmInstructionTests, riteratorInvalid)
{
	auto ai = AsmInstruction();

	EXPECT_EQ(ai.rend(), ai.rbegin());
}

TEST_F(AsmInstructionTests, iteratorEmpty)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);

	EXPECT_EQ(ai.end(), ai.begin());
}

TEST_F(AsmInstructionTests, riteratorEmpty)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);

	EXPECT_EQ(ai.rend(), ai.rbegin());
}

TEST_F(AsmInstructionTests, iteratorComplex)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			br label %lab_1
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);
	auto* a = getInstructionByName("a");
	auto* br1 = getNthInstruction<BranchInst>();
	auto* br2 = getNthInstruction<BranchInst>(1);
	auto* b = getInstructionByName("b");
	auto* c = getInstructionByName("c");
	auto* br3 = getNthInstruction<BranchInst>(2);

	// ++
	//
	auto it = ai.begin();
	auto eIt = ai.end();
	EXPECT_NE(it, eIt);
	EXPECT_EQ(a, &*it);
	++it;
	EXPECT_EQ(br1, &*it);
	it++;
	EXPECT_EQ(br2, &*(it++));
	EXPECT_EQ(b, &*it);
	++it;
	EXPECT_EQ(c, &*it);
	it++;
	EXPECT_EQ(br3, &*it);
	++it;
	EXPECT_EQ(eIt, it);
	++it;
	EXPECT_EQ(eIt, it);

	// --
	//
	EXPECT_EQ(eIt, it);
	--it;
	EXPECT_EQ(br3, &*it);
	it--;
	EXPECT_EQ(c, &*it);
	--it;
	EXPECT_EQ(b, &*(it--));
	EXPECT_EQ(br2, &*it);
	it--;
	EXPECT_EQ(br1, &*it);
	--it;
	EXPECT_EQ(a, &*it);
	EXPECT_EQ(ai.begin(), it);
}

TEST_F(AsmInstructionTests, riteratorComplex)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			%b = add i32 1, 2
			%c = mul i32 %b, 3
			br label %lab_1
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);
	auto* a = getInstructionByName("a");
	auto* br1 = getNthInstruction<BranchInst>();
	auto* br2 = getNthInstruction<BranchInst>(1);
	auto* b = getInstructionByName("b");
	auto* c = getInstructionByName("c");
	auto* br3 = getNthInstruction<BranchInst>(2);

	// ++
	//
	auto it = ai.rbegin();
	auto eIt = ai.rend();
	EXPECT_NE(it, eIt);
	EXPECT_EQ(br3, &*it);
	++it;
	EXPECT_EQ(c, &*it);
	it++;
	EXPECT_EQ(b, &*(it++));
	EXPECT_EQ(br2, &*it);
	++it;
	EXPECT_EQ(br1, &*it);
	it++;
	EXPECT_EQ(a, &*it);
	++it;
	EXPECT_EQ(eIt, it);

	// --
	//
	EXPECT_EQ(eIt, it);
	--it;
	EXPECT_EQ(a, &*it);
	it--;
	EXPECT_EQ(br1, &*it);
	--it;
	EXPECT_EQ(br2, &*(it--));
	EXPECT_EQ(b, &*it);
	it--;
	EXPECT_EQ(c, &*it);
	--it;
	EXPECT_EQ(br3, &*it);
	EXPECT_EQ(ai.rbegin(), it);
}

//
// makeTerminal()
//

TEST_F(AsmInstructionTests, makeTerminalOnLastInFunction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			br label %lab_0
		lab_0:
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);
	auto* ret = getNthInstruction<ReturnInst>();
	auto* t = ai.makeTerminal();

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			br label %lab_0
		lab_0:
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_EQ(ret, t);
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, makeTerminalOnLastInBb)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);
	auto* br = getNthInstruction<BranchInst>(1);
	auto* t = ai.makeTerminal();

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			br label %lab_0
		lab_0:
			br label %lab_1
		lab_1:
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_EQ(br, t);
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, makeTerminalOnAsmInTheMiddle)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);
	auto* t = ai.makeTerminal();
	auto* br = getNthInstruction<BranchInst>();

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %dec_label_pc_162e
			dec_label_pc_162e:                                      ; preds = %0
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_EQ(br, t);
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, makeTerminalOnAsmWithMultipleBb)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_1
		lab_1:
			%b = add i32 1, 2
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);
	auto* t = ai.makeTerminal();
	auto* br = getNthInstruction<BranchInst>(1);

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			%a = add i32 1, 2
			br label %lab_1
		lab_1:                                            ; preds = %0
			%b = add i32 1, 2
			br label %dec_label_pc_162e
		dec_label_pc_162e:                                ; preds = %lab_1
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_EQ(br, t);
	checkModuleAgainstExpectedIr(exp);
}

//
// makeStart()
//

TEST_F(AsmInstructionTests, makeStartOnFirstInFunction)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);
	auto* orig = ai.getBasicBlock();
	auto* ret = ai.makeStart("lab_0");

	std::string exp = R"(
		define void @fnc() {
		lab_0:
			store volatile i64 1234, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_EQ(orig, ret);
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, makeStartOnFirstBb)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			br label %lab_0
		lab_0:
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 5678);
	auto* orig = ai.getBasicBlock();
	auto* ret = ai.makeStart("lab_0");

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			br label %lab_0
		lab_0:
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_EQ(orig, ret);
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(AsmInstructionTests, makeStartInTheMeddleOfBb)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 5678);
	auto* orig = ai.getBasicBlock();
	auto* ret = ai.makeStart();

	std::string exp = R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			br label %dec_label_pc_162e
			dec_label_pc_162e:                                      ; preds = %0
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)";
	EXPECT_NE(orig, ret);
	checkModuleAgainstExpectedIr(exp);
}

//
// containsInstruction()
//

TEST_F(AsmInstructionTests, containsInstructionInvalidDoesNotContainAnything)
{
	AsmInstruction ai;

	ASSERT_TRUE(ai.isInvalid());
	EXPECT_FALSE(ai.containsInstruction<llvm::CallInst>());
}

TEST_F(AsmInstructionTests, containsInstructionSpecialInstructionIsNotTakenIntoAccount)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);

	ASSERT_TRUE(ai.isValid());
	EXPECT_FALSE(ai.containsInstruction<llvm::StoreInst>());
}

TEST_F(AsmInstructionTests, containsInstructionReturnsTrueIfItContainsInstruction)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store i32 0, i32* @r
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);

	ASSERT_TRUE(ai.isValid());
	EXPECT_TRUE(ai.containsInstruction<llvm::StoreInst>());
}

TEST_F(AsmInstructionTests, containsInstructionReturnsFalseIfItDoesNotContainInstruction)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store i32 0, i32* @r
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);

	ASSERT_TRUE(ai.isValid());
	EXPECT_FALSE(ai.containsInstruction<llvm::CallInst>());
}

//
// getInstructionFirst()
//

TEST_F(AsmInstructionTests, getInstructionFirstReturnsNullptrOnInvalidInstruction)
{
	AsmInstruction ai;

	ASSERT_TRUE(ai.isInvalid());
	EXPECT_EQ(nullptr, ai.getInstructionFirst<llvm::CallInst>());
}

TEST_F(AsmInstructionTests, getInstructionFirstSpecialInstructionIsNotTakenIntoAccount)
{
	parseInput(R"(
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);

	ASSERT_TRUE(ai.isValid());
	EXPECT_EQ(nullptr, ai.getInstructionFirst<llvm::StoreInst>());
}

TEST_F(AsmInstructionTests, getInstructionFirstReturnsContainedInstruction)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store i32 0, i32* @r
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);
	auto* s = getNthInstruction<StoreInst>(1);

	ASSERT_TRUE(ai.isValid());
	EXPECT_EQ(s, ai.getInstructionFirst<llvm::StoreInst>());
}

TEST_F(AsmInstructionTests, getInstructionFirstReturnsNullptrIfItDoesNotContainInstruction)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			store volatile i64 1234, i64* @llvm2asm
			store i32 0, i32* @r
			store volatile i64 5678, i64* @llvm2asm
			ret void
		}
		@llvm2asm = global i64 0
	)");
	auto* mapGv = getGlobalByName("llvm2asm");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), mapGv);
	auto ai = AsmInstruction(module.get(), 1234);

	ASSERT_TRUE(ai.isValid());
	EXPECT_EQ(nullptr, ai.getInstructionFirst<llvm::CallInst>());
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
