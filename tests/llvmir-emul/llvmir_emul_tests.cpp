/**
* @file tests/llvmir-emul/llvmir_emul_tests.cpp
* @brief Tests for the @c LlvmIrEmulator class.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir-emul/llvmir_emul.h"
#include "llvmir-emul/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace llvmir_emul {
namespace tests {

/**
 * @brief Tests for the @c LlvmIrEmulator class.
 */
class LlvmIrEmulatorTests: public LlvmIrTests
{

};

//
// getVisitedInstructions()
// getVisitedBasicBlocks()
// wasInstructionVisited()
// wasBasicBlockVisited()
//

TEST_F(LlvmIrEmulatorTests, getVisitedInstructionsSimple)
{
	parseInput(R"(
		define i32 @f1() {
			%a = add i32 1, 2
			%b = add i32 %a, 3
			%c = mul i32 %a, %b
			ret i32 %c
		}
		define i32 @f2() {
			%d = add i32 1, 2
			ret i32 %d
		}
	)");
	auto* f1 = getFunctionByName("f1");
	auto* f2 = getFunctionByName("f2");
	auto* bb1 = &f1->front();
	auto* bb2 = &f2->front();
	auto* a = getInstructionByName("a");
	auto* b = getInstructionByName("b");
	auto* c = getInstructionByName("c");
	auto* r = getNthInstruction<ReturnInst>();
	auto* d = getInstructionByName("d");

	LlvmIrEmulator emu(module.get());
	emu.runFunction(f1);

	auto vis = emu.getVisitedInstructions();
	auto vbs = emu.getVisitedBasicBlocks();

	std::list<Instruction*> exVis = {a, b, c, r};
	EXPECT_EQ(exVis, vis);
	std::list<BasicBlock*> exVbs = {bb1};
	EXPECT_EQ(exVbs, vbs);
	EXPECT_TRUE(emu.wasInstructionVisited(a));
	EXPECT_TRUE(emu.wasInstructionVisited(b));
	EXPECT_TRUE(emu.wasInstructionVisited(c));
	EXPECT_TRUE(emu.wasInstructionVisited(r));
	EXPECT_TRUE(emu.wasBasicBlockVisited(bb1));
	EXPECT_FALSE(emu.wasInstructionVisited(d));
	EXPECT_FALSE(emu.wasBasicBlockVisited(bb2));
}

TEST_F(LlvmIrEmulatorTests, getVisitedInstructionsComplex)
{
	parseInput(R"(
		@eax = global i32 3
		define i32 @fnc() {
			%a = add i32 1, 2
			%b = load i32, i32* @eax
			%c = icmp eq i32 %a, %b
			br i1 %c, label %lab_1, label %lab_2
		lab_1:
			%d = add i32 1, 2
			br label %lab_3
		lab_2:
			%e = add i32 1, 2
			br label %lab_3
		lab_3:
			%f = add i32 1, 2
			ret i32 0
		}
	)");
	auto* fnc = getFunctionByName("fnc");
	auto* a = getInstructionByName("a");
	auto* d = getInstructionByName("d");
	auto* e = getInstructionByName("e");
	auto* f = getInstructionByName("f");

	LlvmIrEmulator emu(module.get());
	emu.runFunction(fnc);

	EXPECT_TRUE(emu.wasInstructionVisited(a));
	EXPECT_TRUE(emu.wasBasicBlockVisited(a->getParent()));
	EXPECT_TRUE(emu.wasInstructionVisited(d));
	EXPECT_TRUE(emu.wasBasicBlockVisited(d->getParent()));
	EXPECT_FALSE(emu.wasInstructionVisited(e));
	EXPECT_FALSE(emu.wasBasicBlockVisited(e->getParent()));
	EXPECT_TRUE(emu.wasInstructionVisited(f));
	EXPECT_TRUE(emu.wasBasicBlockVisited(f->getParent()));
}

//
// getExitValue()
//

TEST_F(LlvmIrEmulatorTests, getExitValueZero)
{
	parseInput(R"(
		define i32 @f() {
			ret i32 0
		}
	)");
	auto* f = getFunctionByName("f");

	LlvmIrEmulator emu(module.get());
	emu.runFunction(f);

	EXPECT_EQ(0, emu.getExitValue().IntVal.getZExtValue());
}

TEST_F(LlvmIrEmulatorTests, getExitValueNonZero)
{
	parseInput(R"(
		define i32 @f() {
			%a = add i32 1, 2    ; 1 + 2 = 3
			%b = add i32 %a, 3   ; 3 + 3 = 6
			%c = mul i32 %a, %b  ; 3 * 6 = 18
			ret i32 %c
		}
	)");
	auto* f = getFunctionByName("f");

	LlvmIrEmulator emu(module.get());
	emu.runFunction(f);

	EXPECT_EQ(18, emu.getExitValue().IntVal.getZExtValue());
}

//
// getCallEntries()
// wasValueCalled()
// getCallEntry()
//

TEST_F(LlvmIrEmulatorTests, getCallEntries)
{
	parseInput(R"(
		define i32 @f1() {
			ret i32 0
		}
		define i32 @f2() {
			ret i32 0
		}
		declare i32 @f3(i32 %a, i32 %b)
		declare i32 @f4(i32 %a, i32 %b)

		define i32 @fnc() {
			call i32 @f1()
			%a = add i32 1, 2    ; 1 + 2 = 3
			%b = add i32 %a, 3   ; 3 + 3 = 6
			%c = mul i32 %a, %b  ; 3 * 6 = 18
			call i32 @f3(i32 %a, i32 %b) ; (3, 6)
			call i32 @f3(i32 %b, i32 %c) ; (6, 18)
			ret i32 0
		}
	)");
	auto* fnc = getFunctionByName("fnc");
	auto* f1 = getFunctionByName("f1");
	auto* f2 = getFunctionByName("f2");
	auto* f3 = getFunctionByName("f3");
	auto* f4 = getFunctionByName("f4");

	LlvmIrEmulator emu(module.get());
	emu.runFunction(fnc);

	EXPECT_TRUE(emu.wasValueCalled(f1));
	EXPECT_FALSE(emu.wasValueCalled(f2));
	EXPECT_TRUE(emu.wasValueCalled(f3));
	EXPECT_FALSE(emu.wasValueCalled(f4));
	EXPECT_EQ(3, emu.getCallEntries().size());

	auto* ce1 = emu.getCallEntry(f3);
	auto* ce2 = emu.getCallEntry(f3, 1);
	EXPECT_NE(ce1, ce2);
	EXPECT_NE(nullptr, ce1);
	EXPECT_NE(nullptr, ce2);
	EXPECT_EQ(f3, ce2->calledValue);
	EXPECT_EQ(2, ce2->calledArguments.size());
	EXPECT_EQ(6, ce2->calledArguments[0].IntVal.getZExtValue());
	EXPECT_EQ(18, ce2->calledArguments[1].IntVal.getZExtValue());
}

//
// wasGlobalVariableLoaded()
// wasGlobalVariableStored()
// getGlobalVariableValue()
//

TEST_F(LlvmIrEmulatorTests, getGlobalVariableValue)
{
	parseInput(R"(
		@eax = global i32 10         ; 10
		@ecx = global i32 0
		define i32 @f() {
			%a = load i32, i32* @eax ; 10
			%b = add i32 %a, 3       ; 10 + 3 = 13
			%c = mul i32 %a, %b      ; 10 * 13 = 130
			store i32 %c, i32* @eax
			ret i32 0
		}
	)");
	auto* f = getFunctionByName("f");
	auto* eax = getGlobalByName("eax");
	auto* ecx = getGlobalByName("ecx");

	LlvmIrEmulator emu(module.get());
	emu.runFunction(f);

	EXPECT_TRUE(emu.wasGlobalVariableLoaded(eax));
	EXPECT_TRUE(emu.wasGlobalVariableStored(eax));
	EXPECT_FALSE(emu.wasGlobalVariableLoaded(ecx));
	EXPECT_FALSE(emu.wasGlobalVariableStored(ecx));
	EXPECT_EQ(130, emu.getGlobalVariableValue(eax).IntVal.getZExtValue());
}

//
// setGlobalVariableValue()
//

TEST_F(LlvmIrEmulatorTests, setGlobalVariableValue)
{
	parseInput(R"(
		@eax = global i32 10         ; 10, but set to 20
		@ecx = global i32 0
		define i32 @f() {
			%a = load i32, i32* @eax ; 20
			%b = add i32 %a, 3       ; 20 + 3 = 23
			%c = mul i32 %a, %b      ; 20 * 23 = 460
			store i32 %c, i32* @eax
			ret i32 0
		}
	)");
	auto* f = getFunctionByName("f");
	auto* eax = getGlobalByName("eax");
	GenericValue val;
	val.IntVal = APInt(32, 20);

	LlvmIrEmulator emu(module.get());
	emu.setGlobalVariableValue(eax, val);
	emu.runFunction(f);

	EXPECT_EQ(460, emu.getGlobalVariableValue(eax).IntVal.getZExtValue());
}

//
// wasMemoryLoaded()
// wasMemoryStored()
// getMemoryValue()
//

TEST_F(LlvmIrEmulatorTests, getMemoryValue)
{
	parseInput(R"(
		define i32 @f() {
			%a = add i32 7, 3         ; 7 + 3 = 10
			%b = mul i32 %a, %a       ; 10 * 10 = 100
			%mem1 = inttoptr i32 1000 to i32*
			store i32 %b, i32* %mem1  ; 100
			%c = load i32, i32* %mem1 ; 100
			%d = mul i32 %c, %a       ; 100 * 10 = 1000
			%mem2 = inttoptr i32 2000 to i32*
			store i32 %d, i32* %mem2  ; 1000
			ret i32 0
		}
	)");
	auto* f = getFunctionByName("f");

	LlvmIrEmulator emu(module.get());
	emu.runFunction(f);

	EXPECT_TRUE(emu.wasMemoryLoaded(1000));
	EXPECT_TRUE(emu.wasMemoryStored(1000));
	EXPECT_FALSE(emu.wasMemoryLoaded(2000));
	EXPECT_TRUE(emu.wasMemoryStored(2000));
	EXPECT_FALSE(emu.wasMemoryLoaded(3000));
	EXPECT_FALSE(emu.wasMemoryStored(3000));
	EXPECT_EQ(100, emu.getMemoryValue(1000).IntVal.getZExtValue());
	EXPECT_EQ(1000, emu.getMemoryValue(2000).IntVal.getZExtValue());
	EXPECT_EQ(GenericValue().IntVal, emu.getMemoryValue(3000).IntVal);
}

//
// setMemoryValue()
//

TEST_F(LlvmIrEmulatorTests, setMemoryValue)
{
	parseInput(R"(
		define i32 @f() {
			%mem1 = inttoptr i32 1000 to i32*
			%a = load i32, i32* %mem1 ; set to 20
			%b = mul i32 %a, 10       ; 20 * 10 = 200
			%mem2 = inttoptr i32 2000 to i32*
			store i32 %b, i32* %mem2  ; 200
			ret i32 0
		}
	)");
	auto* f = getFunctionByName("f");
	GenericValue val;
	val.IntVal = APInt(32, 20);

	LlvmIrEmulator emu(module.get());
	emu.setMemoryValue(1000, val);
	emu.runFunction(f);

	EXPECT_EQ(20, emu.getMemoryValue(1000).IntVal.getZExtValue());
	EXPECT_EQ(200, emu.getMemoryValue(2000).IntVal.getZExtValue());
}

//
// x86_fp80 test
//

TEST_F(LlvmIrEmulatorTests, usingOf_x86_fp80_Type)
{
	parseInput(R"(
		@st0 = internal global x86_fp80 0xK00000000000000000000
		@st1 = internal global x86_fp80 0xK00000000000000000000
		define i32 @f() {
			%a = load x86_fp80, x86_fp80* @st0
			%b = load x86_fp80, x86_fp80* @st1
			%c = fadd x86_fp80 %a, %b
			store x86_fp80 %c, x86_fp80* @st0
			ret i32 0
		}
	)");
	auto* f = getFunctionByName("f");
	auto* st0 = getGlobalByName("st0");
	auto* st1 = getGlobalByName("st1");
	GenericValue st0Val;
	st0Val.DoubleVal = 1.0;
	GenericValue st1Val;
	st1Val.DoubleVal = 2.0;

	LlvmIrEmulator emu(module.get());
	emu.setGlobalVariableValue(st0, st0Val);
	emu.setGlobalVariableValue(st1, st1Val);
	emu.runFunction(f);

	EXPECT_DOUBLE_EQ(3.0, emu.getGlobalVariableValue(st0).DoubleVal);
}

} // tests
} // llvmir_emul
} // retdec
