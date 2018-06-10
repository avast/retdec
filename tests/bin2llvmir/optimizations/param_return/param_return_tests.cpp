/**
* @file tests/bin2llvmir/optimizations/param_return/tests/param_return_tests.cpp
* @brief Tests for the @c ParamReturn pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/param_return/param_return.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c ParamReturn pass.
 */
class ParamReturnTests: public LlvmIrTests
{
	protected:
		ParamReturn pass;
};

//
// x86
//

TEST_F(ParamReturnTests, x86PtrCallBasicFunctionality)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* %stack_-8
			%2 = load i32, i32* %stack_-4
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86PtrCallPrevBbIsUsedOnlyIfItIsASinglePredecessor)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
		br label %lab1
		lab1:
			store i32 123, i32* %stack_-4
		br label %lab2
		lab2:
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
		br label %lab1
		lab1:
			store i32 123, i32* %stack_-4
		br label %lab2
		lab2:
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* %stack_-8
			%2 = load i32, i32* %stack_-4
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86PtrCallPrevBbIsNotUsedIfItIsNotASinglePredecessor)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
		br label %lab1
		lab1:
			store i32 123, i32* %stack_-4
		br label %lab2
		lab2:
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			call void %a()
			br label %lab2
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
		br label %lab1
		lab1:
			store i32 123, i32* %stack_-4
		br label %lab2
		lab2:
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* %stack_-8
			%2 = bitcast void ()* %a to void (i32)*
			call void %2(i32 %1)
			br label %lab2
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86PtrCallOnlyStackStoresAreUsed)
{
	parseInput(R"(
		@eax = global i32 0
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%local = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %local
			store i32 789, i32* @eax
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					}
				]
			}
		],
		"registers" : [
			{
				"name" : "eax",
				"storage" : { "type" : "register", "value" : "eax",
							"registerClass" : "gpr", "registerNumber" : 0 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@eax = global i32 0
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%local = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %local
			store i32 789, i32* @eax
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* %stack_-4
			%2 = bitcast void ()* %a to void (i32)*
			call void %2(i32 %1)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86PtrCallStackAreUsedAsArgumentsInCorrectOrder)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 456, i32* %stack_-8
			store i32 123, i32* %stack_-4
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 456, i32* %stack_-8
			store i32 123, i32* %stack_-4
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* %stack_-8
			%2 = load i32, i32* %stack_-4
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86PtrCallOnlyContinuousStackOffsetsAreUsed)
{
	parseInput(R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-16 = alloca i32
			%stack_-20 = alloca i32
			%stack_-24 = alloca i32
			store i32 1, i32* %stack_-16
			store i32 2, i32* %stack_-20
			store i32 3, i32* %stack_-24
			store i32 4, i32* %stack_-4
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-16",
						"storage" : { "type" : "stack", "value" : -16 }
					},
					{
						"name" : "stack_-20",
						"storage" : { "type" : "stack", "value" : -20 }
					},
					{
						"name" : "stack_-24",
						"storage" : { "type" : "stack", "value" : -24 }
					}
				]
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-16 = alloca i32
			%stack_-20 = alloca i32
			%stack_-24 = alloca i32
			store i32 1, i32* %stack_-16
			store i32 2, i32* %stack_-20
			store i32 3, i32* %stack_-24
			store i32 4, i32* %stack_-4
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* %stack_-24
			%2 = load i32, i32* %stack_-20
			%3 = load i32, i32* %stack_-16
			%4 = bitcast void ()* %a to void (i32, i32, i32)*
			call void %4(i32 %1, i32 %2, i32 %3)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86ExternalCallBasicFunctionality)
{
	parseInput(R"(
		declare void @print()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		declare void @print(i32, i32)
		declare void @0()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%1 = load i32, i32* %stack_-8
			%2 = load i32, i32* %stack_-4
			call void @print(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86ExternalCallFixOnMultiplePlaces)
{
	parseInput(R"(
		declare void @print()
		define void @fnc1() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			call void @print()
			ret void
		}
		define void @fnc2() {
			%stack_-16 = alloca i32
			%stack_-20 = alloca i32
			%stack_-24 = alloca i32
			store i32 456, i32* %stack_-20
			store i32 123, i32* %stack_-16
			store i32 123, i32* %stack_-24
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc1",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			},
			{
				"name" : "fnc2",
				"locals" : [
					{
						"name" : "stack_-16",
						"storage" : { "type" : "stack", "value" : -16 }
					},
					{
						"name" : "stack_-20",
						"storage" : { "type" : "stack", "value" : -20 }
					},
					{
						"name" : "stack_-24",
						"storage" : { "type" : "stack", "value" : -24 }
					}
				]
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		declare void @print(i32, i32)
		declare void @0()
		define void @fnc1() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%1 = load i32, i32* %stack_-8
			%2 = load i32, i32* %stack_-4
			call void @print(i32 %1, i32 %2)
			ret void
		}
		define void @fnc2() {
			%stack_-16 = alloca i32
			%stack_-20 = alloca i32
			%stack_-24 = alloca i32
			store i32 456, i32* %stack_-20
			store i32 123, i32* %stack_-16
			store i32 123, i32* %stack_-24
			%1 = load i32, i32* %stack_-24
			%2 = load i32, i32* %stack_-20
			call void @print(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//TEST_F(ParamReturnTests, x86ExternalCallSomeFunctionCallsAreNotModified)
//{
//	auto module = parseInput(R"(
//		declare void @print1()
//		declare void @print2()
//		declare void @print3(i32)
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			store i32 123, i32* %stack_-4
//			call void @print1()
//			store i32 123, i32* %stack_-4
//			call void @print2()
//			store i32 123, i32* %stack_-4
//			call void @print3(i32 123)
//			ret void
//		}
//	)");
//	auto config = Config::fromJsonString(module.get(), R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "little",
//			"name" : "x86"
//		},
//		"functions" : [
//			{
//				"name" : "fnc",
//				"locals" : [
//					{
//						"name" : "stack_-4",
//						"storage" : { "type" : "stack", "value" : -4 }
//					}
//				]
//			},
//			{
//				"name" : "print1",
//				"fncType" : "dynamicallyLinked",
//				"declarationStr" : "whatever"
//			},
//			{
//				"name" : "print2",
//				"fncType" : "dynamicallyLinked",
//				"isFromDebug" : true
//			},
//			{
//				"name" : "print3",
//				"fncType" : "dynamicallyLinked"
//			}
//		]
//	})");
//
//	pass.runOnModuleCustom(*module, &config, abi);
//
//	std::string exp = R"(
//		declare void @print1()
//		declare void @print2()
//		declare void @print3(i32)
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			store i32 123, i32* %stack_-4
//			call void @print1()
//			store i32 123, i32* %stack_-4
//			call void @print2()
//			store i32 123, i32* %stack_-4
//			call void @print3(i32 123)
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp, module.get());
//}

//
// PowerPC
//

TEST_F(ParamReturnTests, ppcPtrCallBasicFunctionality)
{
	parseInput(R"(
		@r = global i32 0
		@r3 = global i32 0
		@r4 = global i32 0
		define void @fnc() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		},
		"registers" : [
			{
				"name" : "r3",
				"storage" : { "type" : "register", "value" : "r3",
							"registerClass" : "gpregs", "registerNumber" : 3 }
			},
			{
				"name" : "r4",
				"storage" : { "type" : "register", "value" : "r4",
							"registerClass" : "gpregs", "registerNumber" : 4 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r = global i32 0
		@r3 = global i32 0
		@r4 = global i32 0
		define void @fnc() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* @r3
			%2 = load i32, i32* @r4
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppcExternalCallBasicFunctionality)
{
	parseInput(R"(
		@r3 = global i32 0
		@r4 = global i32 0
		declare void @print()
		define void @fnc() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		},
		"registers" : [
			{
				"name" : "r3",
				"storage" : { "type" : "register", "value" : "r3",
							"registerClass" : "gpregs", "registerNumber" : 3 }
			},
			{
				"name" : "r4",
				"storage" : { "type" : "register", "value" : "r4",
							"registerClass" : "gpregs", "registerNumber" : 4 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r3 = global i32 0
		@r4 = global i32 0
		declare void @print(i32, i32)
		declare void @0()
		define void @fnc() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			%1 = load i32, i32* @r3
			%2 = load i32, i32* @r4
			call void @print(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppcExternalCallDoNotUseObjectsIfTheyAreNotRegisters)
{
	parseInput(R"(
		@r3 = global i32 0
		declare void @print()
		define void @fnc() {
			store i32 123, i32* @r3
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		}
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r3 = global i32 0
		declare void @print()
		define void @fnc() {
			store i32 123, i32* @r3
			call void @print()
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppcExternalCallFilterRegistersOnMultiplePlaces)
{
	parseInput(R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@r5 = global i32 0
		declare void @print()
		define void @fnc1() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			call void @print()
			ret void
		}
		define void @fnc2() {
			store i32 123, i32* @r3
			store i32 456, i32* @r5
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		},
		"registers" : [
			{
				"name" : "r3",
				"storage" : { "type" : "register", "value" : "r3",
							"registerClass" : "gpregs", "registerNumber" : 3 }
			},
			{
				"name" : "r4",
				"storage" : { "type" : "register", "value" : "r4",
							"registerClass" : "gpregs", "registerNumber" : 4 }
			},
			{
				"name" : "r5",
				"storage" : { "type" : "register", "value" : "r5",
							"registerClass" : "gpregs", "registerNumber" : 5 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@r5 = global i32 0
		declare void @print(i32)
		declare void @0()
		define void @fnc1() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			%1 = load i32, i32* @r3
			call void @print(i32 %1)
			ret void
		}
		define void @fnc2() {
			store i32 123, i32* @r3
			store i32 456, i32* @r5
			%1 = load i32, i32* @r3
			call void @print(i32 %1)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppcExternalCallDoNotUseAllRegisters)
{
	parseInput(R"(
		@r1 = global i32 0
		@r2 = global i32 0
		@r3 = global i32 0
		declare void @print()
		define void @fnc() {
			store i32 123, i32* @r1
			store i32 456, i32* @r3
			store i32 789, i32* @r2
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		},
		"registers" : [
			{
				"name" : "r1",
				"storage" : { "type" : "register", "value" : "r1",
							"registerClass" : "gpregs", "registerNumber" : 1 }
			},
			{
				"name" : "r2",
				"storage" : { "type" : "register", "value" : "r2",
							"registerClass" : "gpregs", "registerNumber" : 2 }
			},
			{
				"name" : "r3",
				"storage" : { "type" : "register", "value" : "r3",
							"registerClass" : "gpregs", "registerNumber" : 3 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r1 = global i32 0
		@r2 = global i32 0
		@r3 = global i32 0
		declare void @print(i32)
		declare void @0()
		define void @fnc() {
			store i32 123, i32* @r1
			store i32 456, i32* @r3
			store i32 789, i32* @r2
			%1 = load i32, i32* @r3
			call void @print(i32 %1)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppcExternalCallSortRegistersIntoCorrectOrder)
{
	parseInput(R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@r5 = global i32 0
		declare void @print()
		define void @fnc() {
			store i32 123, i32* @r5
			store i32 456, i32* @r3
			store i32 789, i32* @r4
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		},
		"registers" : [
			{
				"name" : "r3",
				"storage" : { "type" : "register", "value" : "r3",
							"registerClass" : "gpregs", "registerNumber" : 3 }
			},
			{
				"name" : "r4",
				"storage" : { "type" : "register", "value" : "r4",
							"registerClass" : "gpregs", "registerNumber" : 4 }
			},
			{
				"name" : "r5",
				"storage" : { "type" : "register", "value" : "r5",
							"registerClass" : "gpregs", "registerNumber" : 5 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@r5 = global i32 0
		declare void @print(i32, i32, i32)
		declare void @0()
		define void @fnc() {
			store i32 123, i32* @r5
			store i32 456, i32* @r3
			store i32 789, i32* @r4
			%1 = load i32, i32* @r3
			%2 = load i32, i32* @r4
			%3 = load i32, i32* @r5
			call void @print(i32 %1, i32 %2, i32 %3)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppcExternalCallDoNotUseStacksIfLessThan7RegistersUsed)
{
	parseInput(R"(
		@r3 = global i32 0
		declare void @print()
		define void @fnc() {
			%stack_-4 = alloca i32
			store i32 123, i32* @r3
			store i32 456, i32* %stack_-4
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					}
				]
			}
		],
		"registers" : [
			{
				"name" : "r3",
				"storage" : { "type" : "register", "value" : "r3",
							"registerClass" : "gpregs", "registerNumber" : 3 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r3 = global i32 0
		declare void @print(i32)
		declare void @0()
		define void @fnc() {
			%stack_-4 = alloca i32
			store i32 123, i32* @r3
			store i32 456, i32* %stack_-4
			%1 = load i32, i32* @r3
			call void @print(i32 %1)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppcExternalCallUseStacksIf7RegistersUsed)
{
	parseInput(R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@r5 = global i32 0
		@r6 = global i32 0
		@r7 = global i32 0
		@r8 = global i32 0
		@r9 = global i32 0
		@r10 = global i32 0
		declare void @print()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @r3
			store i32 1, i32* @r4
			store i32 1, i32* @r5
			store i32 2, i32* %stack_-4
			store i32 1, i32* @r6
			store i32 1, i32* @r7
			store i32 1, i32* @r8
			store i32 2, i32* %stack_-8
			store i32 1, i32* @r9
			store i32 1, i32* @r10
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			}
		],
		"registers" : [
			{
				"name" : "r3",
				"storage" : { "type" : "register", "value" : "r3",
							"registerClass" : "gpregs", "registerNumber" : 3 }
			},
			{
				"name" : "r4",
				"storage" : { "type" : "register", "value" : "r4",
							"registerClass" : "gpregs", "registerNumber" : 4 }
			},
			{
				"name" : "r5",
				"storage" : { "type" : "register", "value" : "r5",
							"registerClass" : "gpregs", "registerNumber" : 5 }
			},
			{
				"name" : "r6",
				"storage" : { "type" : "register", "value" : "r6",
							"registerClass" : "gpregs", "registerNumber" : 6 }
			},
			{
				"name" : "r7",
				"storage" : { "type" : "register", "value" : "r7",
							"registerClass" : "gpregs", "registerNumber" : 7 }
			},
			{
				"name" : "r8",
				"storage" : { "type" : "register", "value" : "r8",
							"registerClass" : "gpregs", "registerNumber" : 8 }
			},
			{
				"name" : "r9",
				"storage" : { "type" : "register", "value" : "r9",
							"registerClass" : "gpregs", "registerNumber" : 9 }
			},
			{
				"name" : "r10",
				"storage" : { "type" : "register", "value" : "r10",
							"registerClass" : "gpregs", "registerNumber" : 10 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@r5 = global i32 0
		@r6 = global i32 0
		@r7 = global i32 0
		@r8 = global i32 0
		@r9 = global i32 0
		@r10 = global i32 0
		declare void @print(i32, i32, i32, i32, i32, i32, i32, i32, i32)
		declare void @0()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @r3
			store i32 1, i32* @r4
			store i32 1, i32* @r5
			store i32 2, i32* %stack_-4
			store i32 1, i32* @r6
			store i32 1, i32* @r7
			store i32 1, i32* @r8
			store i32 2, i32* %stack_-8
			store i32 1, i32* @r9
			store i32 1, i32* @r10
			%1 = load i32, i32* @r3
			%2 = load i32, i32* @r4
			%3 = load i32, i32* @r5
			%4 = load i32, i32* @r6
			%5 = load i32, i32* @r7
			%6 = load i32, i32* @r8
			%7 = load i32, i32* @r9
			%8 = load i32, i32* %stack_-8
			%9 = load i32, i32* %stack_-4
			call void @print(i32 %1, i32 %2, i32 %3, i32 %4, i32 %5, i32 %6, i32 %7, i32 %8, i32 %9)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// ARM (+THUMB)
//

TEST_F(ParamReturnTests, armPtrCallBasicFunctionality)
{
	parseInput(R"(
		@r = global i32 0
		@r0 = global i32 0
		@r1 = global i32 0
		define void @fnc() {
			store i32 123, i32* @r0
			store i32 456, i32* @r1
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "arm"
		},
		"registers" : [
			{
				"name" : "r0",
				"storage" : { "type" : "register", "value" : "r0",
							"registerClass" : "regs", "registerNumber" : 0 }
			},
			{
				"name" : "r1",
				"storage" : { "type" : "register", "value" : "r1",
							"registerClass" : "regs", "registerNumber" : 1 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r = global i32 0
		@r0 = global i32 0
		@r1 = global i32 0
		define void @fnc() {
			store i32 123, i32* @r0
			store i32 456, i32* @r1
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* @r0
			%2 = load i32, i32* @r1
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, armExternalCallBasicFunctionality)
{
	parseInput(R"(
		@r0 = global i32 0
		@r1 = global i32 0
		declare void @print()
		define void @fnc() {
			store i32 123, i32* @r0
			store i32 456, i32* @r1
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "arm"
		},
		"registers" : [
			{
				"name" : "r0",
				"storage" : { "type" : "register", "value" : "r0",
							"registerClass" : "regs", "registerNumber" : 0 }
			},
			{
				"name" : "r1",
				"storage" : { "type" : "register", "value" : "r1",
							"registerClass" : "regs", "registerNumber" : 1 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r0 = global i32 0
		@r1 = global i32 0
		declare void @print(i32, i32)
		declare void @0()
		define void @fnc() {
			store i32 123, i32* @r0
			store i32 456, i32* @r1
			%1 = load i32, i32* @r0
			%2 = load i32, i32* @r1
			call void @print(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, armExternalCallUseStacksIf4RegistersUsed)
{
	parseInput(R"(
		@r0 = global i32 0
		@r1 = global i32 0
		@r2 = global i32 0
		@r3 = global i32 0
		@r4 = global i32 0
		declare void @print()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @r2
			store i32 1, i32* @r1
			store i32 2, i32* %stack_-4
			store i32 1, i32* @r4
			store i32 1, i32* @r0
			store i32 2, i32* %stack_-8
			store i32 1, i32* @r3
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "arm"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			}
		],
		"registers" : [
			{
				"name" : "r0",
				"storage" : { "type" : "register", "value" : "r0",
							"registerClass" : "regs", "registerNumber" : 0 }
			},
			{
				"name" : "r1",
				"storage" : { "type" : "register", "value" : "r1",
							"registerClass" : "regs", "registerNumber" : 1 }
			},
			{
				"name" : "r2",
				"storage" : { "type" : "register", "value" : "r2",
							"registerClass" : "regs", "registerNumber" : 2 }
			},
			{
				"name" : "r3",
				"storage" : { "type" : "register", "value" : "r3",
							"registerClass" : "regs", "registerNumber" : 3 }
			},
			{
				"name" : "r4",
				"storage" : { "type" : "register", "value" : "r4",
							"registerClass" : "regs", "registerNumber" : 4 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r0 = global i32 0
		@r1 = global i32 0
		@r2 = global i32 0
		@r3 = global i32 0
		@r4 = global i32 0
		declare void @print(i32, i32, i32, i32, i32, i32)
		declare void @0()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @r2
			store i32 1, i32* @r1
			store i32 2, i32* %stack_-4
			store i32 1, i32* @r4
			store i32 1, i32* @r0
			store i32 2, i32* %stack_-8
			store i32 1, i32* @r3
			%1 = load i32, i32* @r0
			%2 = load i32, i32* @r1
			%3 = load i32, i32* @r2
			%4 = load i32, i32* @r3
			%5 = load i32, i32* %stack_-8
			%6 = load i32, i32* %stack_-4
			call void @print(i32 %1, i32 %2, i32 %3, i32 %4, i32 %5, i32 %6)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// MIPS (+Pic32)
//

TEST_F(ParamReturnTests, mipsPtrCallBasicFunctionality)
{
	parseInput(R"(
		@r = global i32 0
		@a0 = global i32 0
		@a1 = global i32 0
		define void @fnc() {
			store i32 123, i32* @a0
			store i32 456, i32* @a1
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "mips"
		},
		"registers" : [
			{
				"name" : "a0",
				"storage" : { "type" : "register", "value" : "a0",
							"registerClass" : "gpregs", "registerNumber" : 4 }
			},
			{
				"name" : "a1",
				"storage" : { "type" : "register", "value" : "a1",
							"registerClass" : "gpregs", "registerNumber" : 5 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r = global i32 0
		@a0 = global i32 0
		@a1 = global i32 0
		define void @fnc() {
			store i32 123, i32* @a0
			store i32 456, i32* @a1
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* @a0
			%2 = load i32, i32* @a1
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, mipsExternalCallBasicFunctionality)
{
	parseInput(R"(
		@a0 = global i32 0
		@a1 = global i32 0
		declare void @print()
		define void @fnc() {
			store i32 123, i32* @a0
			store i32 456, i32* @a1
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "mips"
		},
		"registers" : [
			{
				"name" : "a0",
				"storage" : { "type" : "register", "value" : "a0",
							"registerClass" : "gpregs", "registerNumber" : 4 }
			},
			{
				"name" : "a1",
				"storage" : { "type" : "register", "value" : "a1",
							"registerClass" : "gpregs", "registerNumber" : 5 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@a0 = global i32 0
		@a1 = global i32 0
		declare void @print(i32, i32)
		declare void @0()
		define void @fnc() {
			store i32 123, i32* @a0
			store i32 456, i32* @a1
			%1 = load i32, i32* @a0
			%2 = load i32, i32* @a1
			call void @print(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, mipsExternalCallUseStacksIf4RegistersUsed)
{
	parseInput(R"(
		@a0 = global i32 0
		@a1 = global i32 0
		@a2 = global i32 0
		@a3 = global i32 0
		@t0 = global i32 0
		declare void @print()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @a2
			store i32 1, i32* @a1
			store i32 2, i32* %stack_-4
			store i32 1, i32* @t0
			store i32 1, i32* @a0
			store i32 2, i32* %stack_-8
			store i32 1, i32* @a3
			call void @print()
			ret void
		}
	)");
	auto config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "mips"
		},
		"functions" : [
			{
				"name" : "fnc",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				]
			}
		],
		"registers" : [
			{
				"name" : "a0",
				"storage" : { "type" : "register", "value" : "a0",
							"registerClass" : "gpregs", "registerNumber" : 4 }
			},
			{
				"name" : "a1",
				"storage" : { "type" : "register", "value" : "a1",
							"registerClass" : "gpregs", "registerNumber" : 5 }
			},
			{
				"name" : "a2",
				"storage" : { "type" : "register", "value" : "a2",
							"registerClass" : "gpregs", "registerNumber" : 6 }
			},
			{
				"name" : "a3",
				"storage" : { "type" : "register", "value" : "a3",
							"registerClass" : "gpregs", "registerNumber" : 7 }
			},
			{
				"name" : "t0",
				"storage" : { "type" : "register", "value" : "t0",
							"registerClass" : "gpregs", "registerNumber" : 8 }
			}
		]
	})");
	auto abi = AbiProvider::addAbi(module.get(), &config);

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@a0 = global i32 0
		@a1 = global i32 0
		@a2 = global i32 0
		@a3 = global i32 0
		@t0 = global i32 0
		declare void @print(i32, i32, i32, i32, i32, i32)
		declare void @0()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @a2
			store i32 1, i32* @a1
			store i32 2, i32* %stack_-4
			store i32 1, i32* @t0
			store i32 1, i32* @a0
			store i32 2, i32* %stack_-8
			store i32 1, i32* @a3
			%1 = load i32, i32* @a0
			%2 = load i32, i32* @a1
			%3 = load i32, i32* @a2
			%4 = load i32, i32* @a3
			%5 = load i32, i32* %stack_-8
			%6 = load i32, i32* %stack_-4
			call void @print(i32 %1, i32 %2, i32 %3, i32 %4, i32 %5, i32 %6)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
