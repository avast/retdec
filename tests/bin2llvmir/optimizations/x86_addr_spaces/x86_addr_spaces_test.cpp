/**
* @file tests/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces_test.cpp
* @brief Tests for the @c x86_addr_spaces::optimize().
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c x86_addr_spaces::optimize().
 */
class X86AddrSpaceOptimizeTests: public LlvmIrTests
{

};

//
// read FS
//

TEST_F(X86AddrSpaceOptimizeTests, __readfsbyte)
{
	parseInput(R"(
		define i8 @fnc() {
			%a = load i8, i8 addrspace(257)* inttoptr (i32 24 to i8 addrspace(257)*)
			ret i8 %a
		}
	)");
	auto* i = getInstructionByName("a");
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define i8 @fnc() {
			%a = call i8 @__readfsbyte(i32 24)
			ret i8 %a
		}
		declare i8 @__readfsbyte(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __readfsword)
{
	parseInput(R"(
		define i16 @fnc() {
			%a = load i16, i16 addrspace(257)* inttoptr (i32 24 to i16 addrspace(257)*)
			ret i16 %a
		}
	)");
	auto* i = getInstructionByName("a");
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define i16 @fnc() {
			%a = call i16 @__readfsword(i32 24)
			ret i16 %a
		}
		declare i16 @__readfsword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __readfsdword)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = load i32, i32 addrspace(257)* inttoptr (i32 24 to i32 addrspace(257)*)
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define i32 @fnc() {
			%a = call i32 @__readfsdword(i32 24)
			ret i32 %a
		}
		declare i32 @__readfsdword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __readfsqword)
{
	parseInput(R"(
		define i64 @fnc() {
			%a = load i64, i64 addrspace(257)* inttoptr (i32 24 to i64 addrspace(257)*)
			ret i64 %a
		}
	)");
	auto* i = getInstructionByName("a");
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define i64 @fnc() {
			%a = call i64 @__readfsqword(i32 24)
			ret i64 %a
		}
		declare i64 @__readfsqword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

//
// read GS
//

TEST_F(X86AddrSpaceOptimizeTests, __readgsbyte)
{
	parseInput(R"(
		define i8 @fnc() {
			%a = load i8, i8 addrspace(256)* inttoptr (i32 24 to i8 addrspace(256)*)
			ret i8 %a
		}
	)");
	auto* i = getInstructionByName("a");
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define i8 @fnc() {
			%a = call i8 @__readgsbyte(i32 24)
			ret i8 %a
		}
		declare i8 @__readgsbyte(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __readgsword)
{
	parseInput(R"(
		define i16 @fnc() {
			%a = load i16, i16 addrspace(256)* inttoptr (i32 24 to i16 addrspace(256)*)
			ret i16 %a
		}
	)");
	auto* i = getInstructionByName("a");
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define i16 @fnc() {
			%a = call i16 @__readgsword(i32 24)
			ret i16 %a
		}
		declare i16 @__readgsword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __readgsdword)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = load i32, i32 addrspace(256)* inttoptr (i32 24 to i32 addrspace(256)*)
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define i32 @fnc() {
			%a = call i32 @__readgsdword(i32 24)
			ret i32 %a
		}
		declare i32 @__readgsdword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __readgsqword)
{
	parseInput(R"(
		define i64 @fnc() {
			%a = load i64, i64 addrspace(256)* inttoptr (i32 24 to i64 addrspace(256)*)
			ret i64 %a
		}
	)");
	auto* i = getInstructionByName("a");
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define i64 @fnc() {
			%a = call i64 @__readgsqword(i32 24)
			ret i64 %a
		}
		declare i64 @__readgsqword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

//
// write FS
//

TEST_F(X86AddrSpaceOptimizeTests, __writefsbyte)
{
	parseInput(R"(
		define void @fnc() {
			store i8 123, i8 addrspace(257)* inttoptr (i32 24 to i8 addrspace(257)*)
			ret void
		}
	)");
	auto* i = getNthInstruction<StoreInst>();
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define void @fnc() {
			call void @__writefsbyte(i32 24, i8 123)
			ret void
		}
		declare void @__writefsbyte(i32, i8)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __writefsword)
{
	parseInput(R"(
		define void @fnc() {
			store i16 123, i16 addrspace(257)* inttoptr (i32 24 to i16 addrspace(257)*)
			ret void
		}
	)");
	auto* i = getNthInstruction<StoreInst>();
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define void @fnc() {
			call void @__writefsword(i32 24, i16 123)
			ret void
		}
		declare void @__writefsword(i32, i16)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __writefsdword)
{
	parseInput(R"(
		define void @fnc() {
			store i32 123, i32 addrspace(257)* inttoptr (i32 24 to i32 addrspace(257)*)
			ret void
		}
	)");
	auto* i = getNthInstruction<StoreInst>();
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define void @fnc() {
			call void @__writefsdword(i32 24, i32 123)
			ret void
		}
		declare void @__writefsdword(i32, i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __writefsqword)
{
	parseInput(R"(
		define void @fnc() {
			store i64 123, i64 addrspace(257)* inttoptr (i32 24 to i64 addrspace(257)*)
			ret void
		}
	)");
	auto* i = getNthInstruction<StoreInst>();
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define void @fnc() {
			call void @__writefsqword(i32 24, i64 123)
			ret void
		}
		declare void @__writefsqword(i32, i64)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

//
// write GS
//

TEST_F(X86AddrSpaceOptimizeTests, __writegsbyte)
{
	parseInput(R"(
		define void @fnc() {
			store i8 123, i8 addrspace(256)* inttoptr (i32 24 to i8 addrspace(256)*)
			ret void
		}
	)");
	auto* i = getNthInstruction<StoreInst>();
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define void @fnc() {
			call void @__writegsbyte(i32 24, i8 123)
			ret void
		}
		declare void @__writegsbyte(i32, i8)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __writegsword)
{
	parseInput(R"(
		define void @fnc() {
			store i16 123, i16 addrspace(256)* inttoptr (i32 24 to i16 addrspace(256)*)
			ret void
		}
	)");
	auto* i = getNthInstruction<StoreInst>();
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define void @fnc() {
			call void @__writegsword(i32 24, i16 123)
			ret void
		}
		declare void @__writegsword(i32, i16)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __writegsdword)
{
	parseInput(R"(
		define void @fnc() {
			store i32 123, i32 addrspace(256)* inttoptr (i32 24 to i32 addrspace(256)*)
			ret void
		}
	)");
	auto* i = getNthInstruction<StoreInst>();
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define void @fnc() {
			call void @__writegsdword(i32 24, i32 123)
			ret void
		}
		declare void @__writegsdword(i32, i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

TEST_F(X86AddrSpaceOptimizeTests, __writegsqword)
{
	parseInput(R"(
		define void @fnc() {
			store i64 123, i64 addrspace(256)* inttoptr (i32 24 to i64 addrspace(256)*)
			ret void
		}
	)");
	auto* i = getNthInstruction<StoreInst>();
	auto c = Config::empty(module.get());

	llvm::Instruction* ret = x86_addr_spaces::optimize(i, &c);

	std::string exp = R"(
		define void @fnc() {
			call void @__writegsqword(i32 24, i64 123)
			ret void
		}
		declare void @__writegsqword(i32, i64)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_NE(nullptr, ret);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
