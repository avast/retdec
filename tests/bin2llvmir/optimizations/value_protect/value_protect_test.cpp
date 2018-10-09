/**
* @file tests/bin2llvmir/optimizations/value_protect/value_protect_test.cpp
* @brief Tests for the @c ValueProtect pass.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/value_protect/value_protect.h"
#include "retdec/bin2llvmir/providers/abi/x86.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c ValueProtect pass.
 */
class ValueProtectTests: public LlvmIrTests
{
	protected:
	ValueProtect pass;
};

TEST_F(ValueProtectTests, noOptimizationReturnsFalse)
{
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	EXPECT_FALSE(ret);
}

//
// read nullptr
//

TEST_F(ValueProtectTests, loadNullptrByte)
{
	parseInput(R"(
		define i8 @fnc() {
			%a = load i8, i8* null
			ret i8 %a
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define i8 @fnc() {
			%a = call i8 @__readNullptrByte()
			ret i8 %a
		}
		declare i8 @__readNullptrByte()
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, loadNullptrWord)
{
	parseInput(R"(
		define i16 @fnc() {
			%a = load i16, i16* null
			ret i16 %a
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define i16 @fnc() {
			%a = call i16 @__readNullptrWord()
			ret i16 %a
		}
		declare i16 @__readNullptrWord()
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, loadNullptrDword)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = load i32, i32* null
			ret i32 %a
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define i32 @fnc() {
			%a = call i32 @__readNullptrDword()
			ret i32 %a
		}
		declare i32 @__readNullptrDword()
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, loadNullptrQword)
{
	parseInput(R"(
		define i64 @fnc() {
			%a = load i64, i64* null
			ret i64 %a
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define i64 @fnc() {
			%a = call i64 @__readNullptrQword()
			ret i64 %a
		}
		declare i64 @__readNullptrQword()
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// read undef
//

TEST_F(ValueProtectTests, loadUndefByte)
{
	parseInput(R"(
		define i8 @fnc() {
			%a = load i8, i8* undef
			ret i8 %a
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define i8 @fnc() {
			%a = call i8 @__readUndefByte()
			ret i8 %a
		}
		declare i8 @__readUndefByte()
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, loadUndefWord)
{
	parseInput(R"(
		define i16 @fnc() {
			%a = load i16, i16* undef
			ret i16 %a
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define i16 @fnc() {
			%a = call i16 @__readUndefWord()
			ret i16 %a
		}
		declare i16 @__readUndefWord()
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, loadUndefDword)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = load i32, i32* undef
			ret i32 %a
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define i32 @fnc() {
			%a = call i32 @__readUndefDword()
			ret i32 %a
		}
		declare i32 @__readUndefDword()
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, loadUndefQword)
{
	parseInput(R"(
		define i64 @fnc() {
			%a = load i64, i64* undef
			ret i64 %a
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define i64 @fnc() {
			%a = call i64 @__readUndefQword()
			ret i64 %a
		}
		declare i64 @__readUndefQword()
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// write nullptr
//

TEST_F(ValueProtectTests, storeNullptrByte)
{
	parseInput(R"(
		define void @fnc() {
			store i8 123, i8* null
			ret void
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define void @fnc() {
			call void @__writeNullptrByte(i8 123)
			ret void
		}
		declare void @__writeNullptrByte(i8)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, storeNullptrWord)
{
	parseInput(R"(
		define void @fnc() {
			store i16 123, i16* null
			ret void
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define void @fnc() {
			call void @__writeNullptrWord(i16 123)
			ret void
		}
		declare void @__writeNullptrWord(i16)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, storeNullptrDword)
{
	parseInput(R"(
		define void @fnc() {
			store i32 123, i32* null
			ret void
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define void @fnc() {
			call void @__writeNullptrDword(i32 123)
			ret void
		}
		declare void @__writeNullptrDword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, storeNullptrQword)
{
	parseInput(R"(
		define void @fnc() {
			store i64 123, i64* null
			ret void
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define void @fnc() {
			call void @__writeNullptrQword(i64 123)
			ret void
		}
		declare void @__writeNullptrQword(i64)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// write undef
//

TEST_F(ValueProtectTests, storeUndefByte)
{
	parseInput(R"(
		define void @fnc() {
			store i8 123, i8* undef
			ret void
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define void @fnc() {
			call void @__writeUndefByte(i8 123)
			ret void
		}
		declare void @__writeUndefByte(i8)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, storeUndefWord)
{
	parseInput(R"(
		define void @fnc() {
			store i16 123, i16* undef
			ret void
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define void @fnc() {
			call void @__writeUndefWord(i16 123)
			ret void
		}
		declare void @__writeUndefWord(i16)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, storeUndefDword)
{
	parseInput(R"(
		define void @fnc() {
			store i32 123, i32* undef
			ret void
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define void @fnc() {
			call void @__writeUndefDword(i32 123)
			ret void
		}
		declare void @__writeUndefDword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(ValueProtectTests, storeUndefQword)
{
	parseInput(R"(
		define void @fnc() {
			store i64 123, i64* undef
			ret void
		}
	)");
	// architecture does not matter here
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();
	AbiX86 abi(module.get(), &c);

	bool ret = pass.runOnModuleCustom(*module, &c, &abi);

	std::string exp = R"(
		define void @fnc() {
			call void @__writeUndefQword(i64 123)
			ret void
		}
		declare void @__writeUndefQword(i64)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
