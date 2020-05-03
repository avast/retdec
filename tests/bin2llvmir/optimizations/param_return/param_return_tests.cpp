/**
* @file tests/bin2llvmir/optimizations/param_return/tests/param_return_tests.cpp
* @brief Tests for the @c ParamReturn pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/providers/abi/arm64.h"
#include "retdec/bin2llvmir/providers/abi/mips64.h"
#include "retdec/bin2llvmir/providers/abi/powerpc64.h"
#include "retdec/bin2llvmir/providers/demangler.h"

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					}
				]
			}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_EAX, getGlobalByName("eax"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@eax = global i32 0
		@r = global i32 0
		define i32 @fnc() {
			%stack_-4 = alloca i32
			%local = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %local
			store i32 789, i32* @eax
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* %stack_-4
			%2 = bitcast void ()* %a to void (i32)*
			call void %2(i32 %1)
			%3 = load i32, i32* @eax
			ret i32 %3
		}
		declare void @0()
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc1",
				"startAddr" : "0x1234",
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
				"startAddr" : "0x1235",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));
	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
//	parseInput(R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//			store i32 123, i32* %stack_-4
//			store i32 456, i32* %stack_-8
//			%a = bitcast i32* @r to void()*
//			call void %a()
//			ret void
//		}
//	)");
//	auto c = config::Config::fromJsonString(R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "little",
//			"name" : "x86"
//		},
//		"functions" : [
//			{
//				"name" : "fnc",
//				"startAddr" : "0x1234",
//				"locals" : [
//					{
//						"name" : "stack_-4",
//						"storage" : { "type" : "stack", "value" : -4 }
//					},
//					{
//						"name" : "stack_-8",
//						"storage" : { "type" : "stack", "value" : -8 }
//					}
//				]
//			}
//		]
//	})");
//	auto config = Config::fromConfig(module.get(), c);
//	auto abi = AbiProvider::addAbi(module.get(), &config);
//
//	pass.runOnModuleCustom(*module, &config, abi);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//			store i32 123, i32* %stack_-4
//			store i32 456, i32* %stack_-8
//			%a = bitcast i32* @r to void()*
//			%1 = load i32, i32* %stack_-8
//			%2 = load i32, i32* %stack_-4
//			%3 = bitcast void ()* %a to void (i32, i32)*
//			call void %3(i32 %1, i32 %2)
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp);
//}
//
//TEST_F(ParamReturnTests, x86PtrCallPrevBbIsUsedOnlyIfItIsASinglePredecessor)
//{
//	parseInput(R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//		br label %lab1
//		lab1:
//			store i32 123, i32* %stack_-4
//		br label %lab2
//		lab2:
//			store i32 456, i32* %stack_-8
//			%a = bitcast i32* @r to void()*
//			call void %a()
//			ret void
//		}
//	)");
//	auto c = config::Config::fromJsonString(R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "little",
//			"name" : "x86"
//		},
//		"functions" : [
//			{
//				"name" : "fnc",
//				"startAddr" : "0x1234",
//				"locals" : [
//					{
//						"name" : "stack_-4",
//						"storage" : { "type" : "stack", "value" : -4 }
//					},
//					{
//						"name" : "stack_-8",
//						"storage" : { "type" : "stack", "value" : -8 }
//					}
//				]
//			}
//		]
//	})");
//	auto config = Config::fromConfig(module.get(), c);
//	auto abi = AbiProvider::addAbi(module.get(), &config);
//
//	pass.runOnModuleCustom(*module, &config, abi);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//		br label %lab1
//		lab1:
//			store i32 123, i32* %stack_-4
//		br label %lab2
//		lab2:
//			store i32 456, i32* %stack_-8
//			%a = bitcast i32* @r to void()*
//			%1 = load i32, i32* %stack_-8
//			%2 = load i32, i32* %stack_-4
//			%3 = bitcast void ()* %a to void (i32, i32)*
//			call void %3(i32 %1, i32 %2)
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp);
//}
//
//TEST_F(ParamReturnTests, x86PtrCallPrevBbIsNotUsedIfItIsNotASinglePredecessor)
//{
//	parseInput(R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//		br label %lab1
//		lab1:
//			store i32 123, i32* %stack_-4
//		br label %lab2
//		lab2:
//			store i32 456, i32* %stack_-8
//			%a = bitcast i32* @r to void()*
//			call void %a()
//			br label %lab2
//			ret void
//		}
//	)");
//	auto c = config::Config::fromJsonString(R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "little",
//			"name" : "x86"
//		},
//		"functions" : [
//			{
//				"name" : "fnc",
//				"startAddr" : "0x1234",
//				"locals" : [
//					{
//						"name" : "stack_-4",
//						"storage" : { "type" : "stack", "value" : -4 }
//					},
//					{
//						"name" : "stack_-8",
//						"storage" : { "type" : "stack", "value" : -8 }
//					}
//				]
//			}
//		]
//	})");
//	auto config = Config::fromConfig(module.get(), c);
//	auto abi = AbiProvider::addAbi(module.get(), &config);
//
//	pass.runOnModuleCustom(*module, &config, abi);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//		br label %lab1
//		lab1:
//			store i32 123, i32* %stack_-4
//		br label %lab2
//		lab2:
//			store i32 456, i32* %stack_-8
//			%a = bitcast i32* @r to void()*
//			%1 = load i32, i32* %stack_-8
//			%2 = bitcast void ()* %a to void (i32)*
//			call void %2(i32 %1)
//			br label %lab2
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp);
//}
//
//TEST_F(ParamReturnTests, x86PtrCallOnlyStackStoresAreUsed)
//{
//	parseInput(R"(
//		@eax = global i32 0
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%local = alloca i32
//			store i32 123, i32* %stack_-4
//			store i32 456, i32* %local
//			store i32 789, i32* @eax
//			%a = bitcast i32* @r to void()*
//			call void %a()
//			ret void
//		}
//	)");
//	auto c = config::Config::fromJsonString(R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "little",
//			"name" : "x86"
//		},
//		"functions" : [
//			{
//				"name" : "fnc",
//				"startAddr" : "0x1234",
//				"locals" : [
//					{
//						"name" : "stack_-4",
//						"storage" : { "type" : "stack", "value" : -4 }
//					}
//				]
//			}
//		],
//		"registers" : [
//			{
//				"name" : "eax",
//				"storage" : { "type" : "register", "value" : "eax",
//							"registerClass" : "gpr", "registerNumber" : 0 }
//			}
//		]
//	})");
// 	auto config = Config::fromConfig(module.get(), c);
//	auto abi = AbiProvider::addAbi(module.get(), &config);
//
//	pass.runOnModuleCustom(*module, &config, abi);
//
//	std::string exp = R"(
//		@eax = global i32 0
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%local = alloca i32
//			store i32 123, i32* %stack_-4
//			store i32 456, i32* %local
//			store i32 789, i32* @eax
//			%a = bitcast i32* @r to void()*
//			%1 = load i32, i32* %stack_-4
//			%2 = bitcast void ()* %a to void (i32)*
//			call void %2(i32 %1)
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp);
//}
//
//TEST_F(ParamReturnTests, x86PtrCallStackAreUsedAsArgumentsInCorrectOrder)
//{
//	parseInput(R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//			store i32 456, i32* %stack_-8
//			store i32 123, i32* %stack_-4
//			%a = bitcast i32* @r to void()*
//			call void %a()
//			ret void
//		}
//	)");
//	auto c = config::Config::fromJsonString(R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "little",
//			"name" : "x86"
//		},
//		"functions" : [
//			{
//				"name" : "fnc",
//				"startAddr" : "0x1234",
//				"locals" : [
//					{
//						"name" : "stack_-4",
//						"storage" : { "type" : "stack", "value" : -4 }
//					},
//					{
//						"name" : "stack_-8",
//						"storage" : { "type" : "stack", "value" : -8 }
//					}
//				]
//			}
//		]
//	})");
//	auto config = Config::fromConfig(module.get(), c);
//	auto abi = AbiProvider::addAbi(module.get(), &config);
//
//	pass.runOnModuleCustom(*module, &config, abi);
//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//			store i32 456, i32* %stack_-8
//			store i32 123, i32* %stack_-4
//			%a = bitcast i32* @r to void()*
//			%1 = load i32, i32* %stack_-8
//			%2 = load i32, i32* %stack_-4
//			%3 = bitcast void ()* %a to void (i32, i32)*
//			call void %3(i32 %1, i32 %2)
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp);
//}

TEST_F(ParamReturnTests, x86_64PtrCallBasicFunctionality)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r = global i64 0
		@rdi = global i64 0
		@rsi = global i64 0
		@rax = global i64 0
		define void @fnc() {
			store i64 123, i64* @rdi
			store i64 456, i64* @rsi
			%a = bitcast i64* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RDI, getGlobalByName("rdi"));
	abi->addRegister(X86_REG_RSI, getGlobalByName("rsi"));
	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r = global i64 0
		@rdi = global i64 0
		@rsi = global i64 0
		@rax = global i64 0

		define i64 @fnc() {
			store i64 123, i64* @rdi
			store i64 456, i64* @rsi
			%a = bitcast i64* @r to void()*
			%1 = load i64, i64* @rdi
			%2 = load i64, i64* @rsi
			%3 = bitcast void ()* %a to void (i64, i64)*
			call void %3(i64 %1, i64 %2)
			%4 = load i64, i64* @rax
			ret i64 %4
		}

		declare void @0()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86_64PtrCallPrevBbIsUsedOnlyIfItIsASinglePredecessor)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r = global i64 0
		@rdi = global i64 0
		@rsi = global i64 0
		@rax = global i64 0

		define void @fnc() {
		br label %lab1
		lab1:
			store i64 123, i64* @rdi
		br label %lab2
		lab2:
			store i64 456, i64* @rsi
			%a = bitcast i64* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RDI, getGlobalByName("rdi"));
	abi->addRegister(X86_REG_RSI, getGlobalByName("rsi"));
	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r = global i64 0
		@rdi = global i64 0
		@rsi = global i64 0
		@rax = global i64 0

		define i64 @fnc() {
			br label %lab1

		lab1:
			store i64 123, i64* @rdi
			br label %lab2

		lab2:
			store i64 456, i64* @rsi
			%a = bitcast i64* @r to void ()*
			%1 = load i64, i64* @rdi
			%2 = load i64, i64* @rsi
			%3 = bitcast void ()* %a to void (i64, i64)*
			call void %3(i64 %1, i64 %2)
			%4 = load i64, i64* @rax
			ret i64 %4
		}

		declare void @0()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86_64ExternalCallUseStacksIf6RegistersUsed)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rdi = global i64 0
		@rsi = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@r8 = global i64 0
		@r9 = global i64 0
		@r10 = global i64 0
		@rax = global i64 0
		declare void @print()
		define void @fnc() {
			store i64 1, i64* @rdi
			%stack_-8 = alloca i64
			%stack_-16 = alloca i64
			store i64 1, i64* @r9
			store i64 2, i64* @r10
			store i64 1, i64* @r8
			store i64 1, i64* @rsi
			store i64 2, i64* %stack_-8
			store i64 1, i64* @rdx
			store i64 2, i64* %stack_-16
			store i64 1, i64* @rcx
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					},
					{
						"name" : "stack_-16",
						"storage" : { "type" : "stack", "value" : -16 }
					}

				]
			}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));
	abi->addRegister(X86_REG_RDI, getGlobalByName("rdi"));
	abi->addRegister(X86_REG_RSI, getGlobalByName("rsi"));
	abi->addRegister(X86_REG_RCX, getGlobalByName("rcx"));
	abi->addRegister(X86_REG_RDX, getGlobalByName("rdx"));
	abi->addRegister(X86_REG_R8, getGlobalByName("r8"));
	abi->addRegister(X86_REG_R9, getGlobalByName("r9"));
	abi->addRegister(X86_REG_R10, getGlobalByName("r10"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rdi = global i64 0
		@rsi = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@r8 = global i64 0
		@r9 = global i64 0
		@r10 = global i64 0
		@rax = global i64 0

		declare i64 @print(i64, i64, i64, i64, i64, i64, i64, i64)

		declare void @0()

		define i64 @fnc() {
			store i64 1, i64* @rdi
			%stack_-8 = alloca i64
			%stack_-16 = alloca i64
			store i64 1, i64* @r9
			store i64 2, i64* @r10
			store i64 1, i64* @r8
			store i64 1, i64* @rsi
			store i64 2, i64* %stack_-8
			store i64 1, i64* @rdx
			store i64 2, i64* %stack_-16
			store i64 1, i64* @rcx
			%1 = load i64, i64* @rdi
			%2 = load i64, i64* @rsi
			%3 = load i64, i64* @rdx
			%4 = load i64, i64* @rcx
			%5 = load i64, i64* @r8
			%6 = load i64, i64* @r9
			%7 = load i64, i64* %stack_-16
			%8 = load i64, i64* %stack_-8
			%9 = call i64 @print(i64 %1, i64 %2, i64 %3, i64 %4, i64 %5, i64 %6, i64 %7, i64 %8)
			store i64 %9, i64* @rax
			%10 = load i64, i64* @rax
			ret i64 %10
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86_64ExternalCallUsesFPRegistersBasic)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rax = global i64 0
		@xmm0 = global double 0.0
		@xmm1 = global double 0.0

		declare void @print()
		define void @fnc() {
			store double 2.0, double* @xmm1
			store double 2.0, double* @xmm0
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));
	abi->addRegister(X86_REG_XMM0, getGlobalByName("xmm0"));
	abi->addRegister(X86_REG_XMM1, getGlobalByName("xmm1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
	target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

	@rax = global i64 0
	@xmm0 = global double 0.000000e+00
	@xmm1 = global double 0.000000e+00

	declare i64 @print(double, double)

	declare void @0()

	define i64 @fnc() {
		store double 2.000000e+00, double* @xmm1
		store double 2.000000e+00, double* @xmm0
		%1 = load double, double* @xmm0
		%2 = load double, double* @xmm1
		%3 = call i64 @print(double %1, double %2)
		store i64 %3, i64* @rax
		%4 = load i64, i64* @rax
		ret i64 %4
	}

	declare void @1()

	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86_64ExternalCallUsesFPRegisters)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rdi = global i64 0
		@rsi = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@r8 = global i64 0
		@r9 = global i64 0
		@r10 = global i64 0
		@rax = global i64 0
		@xmm0 = global double 0.0
		@xmm1 = global double 0.0

		declare void @print()
		define void @fnc() {
			store i64 1, i64* @rdi
			store i64 1, i64* @r9
			store i64 2, i64* @r10
			store i64 1, i64* @r8
			store i64 1, i64* @rsi
			store double 2.0, double* @xmm1
			store i64 1, i64* @rdx
			store double 2.0, double* @xmm0
			store i64 1, i64* @rcx
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));
	abi->addRegister(X86_REG_RDI, getGlobalByName("rdi"));
	abi->addRegister(X86_REG_RSI, getGlobalByName("rsi"));
	abi->addRegister(X86_REG_RCX, getGlobalByName("rcx"));
	abi->addRegister(X86_REG_RDX, getGlobalByName("rdx"));
	abi->addRegister(X86_REG_R8, getGlobalByName("r8"));
	abi->addRegister(X86_REG_R9, getGlobalByName("r9"));
	abi->addRegister(X86_REG_R10, getGlobalByName("r10"));
	abi->addRegister(X86_REG_XMM0, getGlobalByName("xmm0"));
	abi->addRegister(X86_REG_XMM1, getGlobalByName("xmm1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
	target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

	@rdi = global i64 0
	@rsi = global i64 0
	@rcx = global i64 0
	@rdx = global i64 0
	@r8 = global i64 0
	@r9 = global i64 0
	@r10 = global i64 0
	@rax = global i64 0
	@xmm0 = global double 0.000000e+00
	@xmm1 = global double 0.000000e+00

	declare i64 @print(i64, i64, i64, i64, i64, i64, double, double)

	declare void @0()

	define i64 @fnc() {
		store i64 1, i64* @rdi
		store i64 1, i64* @r9
		store i64 2, i64* @r10
		store i64 1, i64* @r8
		store i64 1, i64* @rsi
		store double 2.000000e+00, double* @xmm1
		store i64 1, i64* @rdx
		store double 2.000000e+00, double* @xmm0
		store i64 1, i64* @rcx
		%1 = load i64, i64* @rdi
		%2 = load i64, i64* @rsi
		%3 = load i64, i64* @rdx
		%4 = load i64, i64* @rcx
		%5 = load i64, i64* @r8
		%6 = load i64, i64* @r9
		%7 = load double, double* @xmm0
		%8 = load double, double* @xmm1
		%9 = call i64 @print(i64 %1, i64 %2, i64 %3, i64 %4, i64 %5, i64 %6, double %7, double %8)
		store i64 %9, i64* @rax
		%10 = load i64, i64* @rax
		ret i64 %10
	}

	declare void @1()

	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86_64UsesJustContinuousSequenceOfRegisters)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rax = global i64 0
		@rdi = global i64 0
		@rsi = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0

		declare void @print()
		define void @fnc() {
			store i64 1, i64* @rdi
			store i64 1, i64* @rdx
			store i64 1, i64* @rcx
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));
	abi->addRegister(X86_REG_RDI, getGlobalByName("rdi"));
	abi->addRegister(X86_REG_RSI, getGlobalByName("rsi"));
	abi->addRegister(X86_REG_RCX, getGlobalByName("rcx"));
	abi->addRegister(X86_REG_RDX, getGlobalByName("rdx"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rax = global i64 0
		@rdi = global i64 0
		@rsi = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0

		declare i64 @print(i64)

		declare void @0()

		define i64 @fnc() {
			store i64 1, i64* @rdi
			store i64 1, i64* @rdx
			store i64 1, i64* @rcx
			%1 = load i64, i64* @rdi
			%2 = call i64 @print(i64 %1)
			store i64 %2, i64* @rax
			%3 = load i64, i64* @rax
			ret i64 %3
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ms_x64PtrCallBasicFunctionality)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@rax = global i64 0
		define void @fnc() {
			store i64 123, i64* @rcx
			store i64 456, i64* @rdx
			%a = bitcast i64* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"fileFormat" : "pe64",
		"tools" :
		[
			{"name" : "gcc"}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RCX, getGlobalByName("rcx"));
	abi->addRegister(X86_REG_RDX, getGlobalByName("rdx"));
	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@rax = global i64 0

		define i64 @fnc() {
			store i64 123, i64* @rcx
			store i64 456, i64* @rdx
			%a = bitcast i64* @r to void()*
			%1 = load i64, i64* @rcx
			%2 = load i64, i64* @rdx
			%3 = bitcast void ()* %a to void (i64, i64)*
			call void %3(i64 %1, i64 %2)
			%4 = load i64, i64* @rax
			ret i64 %4
		}

		declare void @0()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ms_x64PtrCallPrevBbIsUsedOnlyIfItIsASinglePredecessor)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@rax = global i64 0

		define void @fnc() {
		br label %lab1
		lab1:
			store i64 123, i64* @rcx
		br label %lab2
		lab2:
			store i64 456, i64* @rdx
			%a = bitcast i64* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"fileFormat" : "pe64",
		"tools" :
		[
			{"name" : "gcc"}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RCX, getGlobalByName("rcx"));
	abi->addRegister(X86_REG_RDX, getGlobalByName("rdx"));
	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@rax = global i64 0

		define i64 @fnc() {
			br label %lab1

		lab1:
			store i64 123, i64* @rcx
			br label %lab2

		lab2:
			store i64 456, i64* @rdx
			%a = bitcast i64* @r to void ()*
			%1 = load i64, i64* @rcx
			%2 = load i64, i64* @rdx
			%3 = bitcast void ()* %a to void (i64, i64)*
			call void %3(i64 %1, i64 %2)
			%4 = load i64, i64* @rax
			ret i64 %4
		}

		declare void @0()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ms_x64ExternalCallUseStacksIf4RegistersUsed)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rsi = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@r8 = global i64 0
		@r9 = global i64 0
		@rax = global i64 0
		declare void @print()
		define void @fnc() {
			%stack_-8 = alloca i64
			%stack_-16 = alloca i64
			store i64 1, i64* @r9
			store i64 1, i64* @r8
			store i64 1, i64* @rsi
			store i64 2, i64* %stack_-8
			store i64 1, i64* @rdx
			store i64 2, i64* %stack_-16
			store i64 1, i64* @rcx
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					},
					{
						"name" : "stack_-16",
						"storage" : { "type" : "stack", "value" : -16 }
					}

				]
			}
		],
		"fileFormat" : "pe64",
		"tools" :
		[
			{"name" : "gcc"}
		]

	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));
	abi->addRegister(X86_REG_RSI, getGlobalByName("rsi"));
	abi->addRegister(X86_REG_RCX, getGlobalByName("rcx"));
	abi->addRegister(X86_REG_RDX, getGlobalByName("rdx"));
	abi->addRegister(X86_REG_R8, getGlobalByName("r8"));
	abi->addRegister(X86_REG_R9, getGlobalByName("r9"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rsi = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0
		@r8 = global i64 0
		@r9 = global i64 0
		@rax = global i64 0

		declare i64 @print(i64, i64, i64, i64, i64, i64)

		declare void @0()

		define i64 @fnc() {
			%stack_-8 = alloca i64
			%stack_-16 = alloca i64
			store i64 1, i64* @r9
			store i64 1, i64* @r8
			store i64 1, i64* @rsi
			store i64 2, i64* %stack_-8
			store i64 1, i64* @rdx
			store i64 2, i64* %stack_-16
			store i64 1, i64* @rcx
			%1 = load i64, i64* @rcx
			%2 = load i64, i64* @rdx
			%3 = load i64, i64* @r8
			%4 = load i64, i64* @r9
			%5 = load i64, i64* %stack_-16
			%6 = load i64, i64* %stack_-8
			%7 = call i64 @print(i64 %1, i64 %2, i64 %3, i64 %4, i64 %5, i64 %6)
			store i64 %7, i64* @rax
			%8 = load i64, i64* @rax
			ret i64 %8
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ms_x64ExternalCallUsesFPRegisters)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@r8 = global i64 0
		@r9 = global i64 0
		@rax = global i64 0
		@xmm0 = global double 0.0
		@xmm1 = global double 0.0

		declare void @print()
		define void @fnc() {
			store double 2.0, double* @xmm1
			store double 2.0, double* @xmm0
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"fileFormat" : "pe64",
		"tools" :
		[
			{"name" : "gcc"}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));
	abi->addRegister(X86_REG_R8, getGlobalByName("r8"));
	abi->addRegister(X86_REG_R9, getGlobalByName("r9"));
	abi->addRegister(X86_REG_XMM0, getGlobalByName("xmm0"));
	abi->addRegister(X86_REG_XMM1, getGlobalByName("xmm1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
	target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

	@r8 = global i64 0
	@r9 = global i64 0
	@rax = global i64 0
	@xmm0 = global double 0.000000e+00
	@xmm1 = global double 0.000000e+00

	declare i64 @print(double, double)

	declare void @0()

	define i64 @fnc() {
		store double 2.000000e+00, double* @xmm1
		store double 2.000000e+00, double* @xmm0
		%1 = load double, double* @xmm0
		%2 = load double, double* @xmm1
		%3 = call i64 @print(double %1, double %2)
		store i64 %3, i64* @rax
		%4 = load i64, i64* @rax
		ret i64 %4
	}

	declare void @1()

	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ms_x64UsesJustContinuousSequenceOfRegisters)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rax = global i64 0
		@r8 = global i64 0
		@r9 = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0

		declare void @print()
		define void @fnc() {
			store i64 1, i64* @r9
			store i64 1, i64* @r8
			store i64 1, i64* @rcx
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"fileFormat" : "pe64",
		"tools" :
		[
			{"name" : "gcc"}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));
	abi->addRegister(X86_REG_R8, getGlobalByName("r8"));
	abi->addRegister(X86_REG_R9, getGlobalByName("r9"));
	abi->addRegister(X86_REG_RCX, getGlobalByName("rcx"));
	abi->addRegister(X86_REG_RDX, getGlobalByName("rdx"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rax = global i64 0
		@r8 = global i64 0
		@r9 = global i64 0
		@rcx = global i64 0
		@rdx = global i64 0

		declare i64 @print(i64)

		declare void @0()

		define i64 @fnc() {
			store i64 1, i64* @r9
			store i64 1, i64* @r8
			store i64 1, i64* @rcx
			%1 = load i64, i64* @rcx
			%2 = call i64 @print(i64 %1)
			store i64 %2, i64* @rax
			%3 = load i64, i64* @rax
			ret i64 %3
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ms_x64ExternalCallUsesFPRegistersAdvanced)
{
	parseInput(R"(
		target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

		@rcx = global i64 0
		@rdx = global i64 0
		@rax = global i64 0
		@xmm2 = global double 0.0
		@xmm3 = global double 0.0

		declare void @print()
		define void @fnc() {
			store i64 1, i64* @rcx
			store i64 1, i64* @rdx
			store double 2.0, double* @xmm2
			store double 2.0, double* @xmm3
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"fileFormat" : "pe64",
		"tools" :
		[
			{"name" : "gcc"}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(X86_REG_RAX, getGlobalByName("rax"));
	abi->addRegister(X86_REG_RDX, getGlobalByName("rdx"));
	abi->addRegister(X86_REG_RCX, getGlobalByName("rcx"));
	abi->addRegister(X86_REG_XMM2, getGlobalByName("xmm2"));
	abi->addRegister(X86_REG_XMM3, getGlobalByName("xmm3"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
	target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"

	@rcx = global i64 0
	@rdx = global i64 0
	@rax = global i64 0
	@xmm2 = global double 0.000000e+00
	@xmm3 = global double 0.000000e+00

	declare i64 @print(i64, i64, double, double)

	declare void @0()

	define i64 @fnc() {
		store i64 1, i64* @rcx
		store i64 1, i64* @rdx
		store double 2.000000e+00, double* @xmm2
		store double 2.000000e+00, double* @xmm3
		%1 = load i64, i64* @rcx
		%2 = load i64, i64* @rdx
		%3 = load double, double* @xmm2
		%4 = load double, double* @xmm3
		%5 = call i64 @print(i64 %1, i64 %2, double %3, double %4)
		store i64 %5, i64* @rax
		%6 = load i64, i64* @rax
		ret i64 %6
	}

	declare void @1()

	)";
	checkModuleAgainstExpectedIr(exp);
}

//
//TEST_F(ParamReturnTests, x86PtrCallOnlyContinuousStackOffsetsAreUsed)
//{
//	parseInput(R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-16 = alloca i32
//			%stack_-20 = alloca i32
//			%stack_-24 = alloca i32
//			store i32 1, i32* %stack_-16
//			store i32 2, i32* %stack_-20
//			store i32 3, i32* %stack_-24
//			store i32 4, i32* %stack_-4
//			%a = bitcast i32* @r to void()*
//			call void %a()
//			ret void
//		}
//	)");
//	auto c = config::Config::fromJsonString(R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "little",
//			"name" : "x86"
//		},
//		"functions" : [
//			{
//				"name" : "fnc",
//				"startAddr" : "0x1234",
//				"locals" : [
//					{
//						"name" : "stack_-4",
//						"storage" : { "type" : "stack", "value" : -4 }
//					},
//					{
//						"name" : "stack_-16",
//						"storage" : { "type" : "stack", "value" : -16 }
//					},
//					{
//						"name" : "stack_-20",
//						"storage" : { "type" : "stack", "value" : -20 }
//					},
//					{
//						"name" : "stack_-24",
//						"storage" : { "type" : "stack", "value" : -24 }
//					}
//				]
//			}
//		]
//	})");
//	auto config = Config::fromConfig(module.get(), c);
//	auto abi = AbiProvider::addAbi(module.get(), &config);
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(PPC_REG_R3, getGlobalByName("r3"));
	abi->addRegister(PPC_REG_R4, getGlobalByName("r4"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r = global i32 0
		@r3 = global i32 0
		@r4 = global i32 0

		define i32 @fnc() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			%a = bitcast i32* @r to void ()*
			%1 = load i32, i32* @r3
			%2 = load i32, i32* @r4
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			%4 = load i32, i32* @r3
			ret i32 %4
		}

		declare void @0()
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(PPC_REG_R3, getGlobalByName("r3"));
	abi->addRegister(PPC_REG_R4, getGlobalByName("r4"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r3 = global i32 0
		@r4 = global i32 0

		declare i32 @print(i32, i32)
		declare void @0()

		define i32 @fnc() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			%1 = load i32, i32* @r3
			%2 = load i32, i32* @r4
			%3 = call i32 @print(i32 %1, i32 %2)
			store i32 %3, i32* @r3
			%4 = load i32, i32* @r3
			ret i32 %4
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppcExternalCallBasicFPFunctionality)
{
	parseInput(R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@f1 = global double 0.0
		@f2 = global double 0.0
		declare void @print()
		define void @fnc() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			store double 0.0, double* @f1
			store double 0.0, double* @f2
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(PPC_REG_R3, getGlobalByName("r3"));
	abi->addRegister(PPC_REG_R4, getGlobalByName("r4"));
	abi->addRegister(PPC_REG_F1, getGlobalByName("f1"));
	abi->addRegister(PPC_REG_F2, getGlobalByName("f2"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@f1 = global double 0.0
		@f2 = global double 0.0

		declare i32 @print(i32, i32, double, double)
		declare void @0()

		define i32 @fnc() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			store double 0.0, double* @f1
			store double 0.0, double* @f2
			%1 = load i32, i32* @r3
			%2 = load i32, i32* @r4
			%3 = load double, double* @f1
			%4 = load double, double* @f2
			%5 = call i32 @print(i32 %1, i32 %2, double %3, double %4)
			store i32 %5, i32* @r3
			%6 = load i32, i32* @r3
			ret i32 %6
		}

		declare void @1()
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
/*
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(PPC_REG_R3, getGlobalByName("r3"));
	abi->addRegister(PPC_REG_R4, getGlobalByName("r4"));
	abi->addRegister(PPC_REG_R5, getGlobalByName("r5"));

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@r5 = global i32 0

		declare i32 @print(i32)

		declare void @0()

		define i32 @fnc1() {
			store i32 123, i32* @r3
			store i32 456, i32* @r4
			%1 = load i32, i32* @r3
			%2 = call i32 @print(i32 %1)
			store i32 %2, i32* @r3
			%3 = load i32, i32* @r3
			ret i32 %3
		}

		declare void @1()

		define i32 @fnc2() {
			store i32 123, i32* @r3
			store i32 456, i32* @r5
			%1 = load i32, i32* @r3
			%2 = call i32 @print(i32 %1)
			store i32 %2, i32* @r3
			%3 = load i32, i32* @r3
			ret i32 %3
		}

		declare void @2()
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(PPC_REG_R1, getGlobalByName("r1"));
	abi->addRegister(PPC_REG_R2, getGlobalByName("r2"));
	abi->addRegister(PPC_REG_R3, getGlobalByName("r3"));

	pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
		@r1 = global i32 0
		@r2 = global i32 0
		@r3 = global i32 0

		declare i32 @print(i32)

		declare void @0()

		define i32 @fnc() {
			store i32 123, i32* @r1
			store i32 456, i32* @r3
			store i32 789, i32* @r2
			%1 = load i32, i32* @r3
			%2 = call i32 @print(i32 %1)
			store i32 %2, i32* @r3
			%3 = load i32, i32* @r3
			ret i32 %3
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}
*/

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(PPC_REG_R3, getGlobalByName("r3"));
	abi->addRegister(PPC_REG_R4, getGlobalByName("r4"));
	abi->addRegister(PPC_REG_R5, getGlobalByName("r5"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r3 = global i32 0
		@r4 = global i32 0
		@r5 = global i32 0

		declare i32 @print(i32, i32, i32)

		declare void @0()

		define i32 @fnc() {
			store i32 123, i32* @r5
			store i32 456, i32* @r3
			store i32 789, i32* @r4
			%1 = load i32, i32* @r3
			%2 = load i32, i32* @r4
			%3 = load i32, i32* @r5
			%4 = call i32 @print(i32 %1, i32 %2, i32 %3)
			store i32 %4, i32* @r3
			%5 = load i32, i32* @r3
			ret i32 %5
		}

		declare void @1()
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "big",
			"name" : "powerpc"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					}
				]
			}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(PPC_REG_R3, getGlobalByName("r3"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r3 = global i32 0

		declare i32 @print(i32)

		declare void @0()

		define i32 @fnc() {
			%stack_-4 = alloca i32
			store i32 123, i32* @r3
			store i32 456, i32* %stack_-4
			%1 = load i32, i32* @r3
			%2 = call i32 @print(i32 %1)
			store i32 %2, i32* @r3
			%3 = load i32, i32* @r3
			ret i32 %3
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, ppc64PtrCallBasicFunctionality)
{
	parseInput(R"(
		target datalayout = "E-m:e-p:64:64-i64:64-n32"
		@r = global i64 0
		@r3 = global i64 0
		@r4 = global i64 0
		define void @fnc() {
			store i64 123, i64* @r3
			store i64 456, i64* @r4
			%a = bitcast i64* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "big",
			"name" : "powerpc64"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	AbiPowerpc64 abi(module.get(), &config);

	abi.addRegister(PPC_REG_R3, getGlobalByName("r3"));
	abi.addRegister(PPC_REG_R4, getGlobalByName("r4"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, &abi, demangler);

	std::string exp = R"(
		target datalayout = "E-m:e-p:64:64-i64:64-n32"

		@r = global i64 0
		@r3 = global i64 0
		@r4 = global i64 0

		define i64 @fnc() {
			store i64 123, i64* @r3
			store i64 456, i64* @r4
			%a = bitcast i64* @r to void ()*
			%1 = load i64, i64* @r3
			%2 = load i64, i64* @r4
			%3 = bitcast void ()* %a to void (i64, i64)*
			call void %3(i64 %1, i64 %2)
			%4 = load i64, i64* @r3
			ret i64 %4
		}

		declare void @0()
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
//	std::string exp = R"(
//		@r = global i32 0
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-16 = alloca i32
//			%stack_-20 = alloca i32
//			%stack_-24 = alloca i32
//			store i32 1, i32* %stack_-16
//			store i32 2, i32* %stack_-20
//			store i32 3, i32* %stack_-24
//			store i32 4, i32* %stack_-4
//			%a = bitcast i32* @r to void()*
//			%1 = load i32, i32* %stack_-24
//			%2 = load i32, i32* %stack_-20
//			%3 = load i32, i32* %stack_-16
//			%4 = bitcast void ()* %a to void (i32, i32, i32)*
//			call void %4(i32 %1, i32 %2, i32 %3)
//			ret void
//		}
//	)";
//	checkModuleAgainstExpectedIr(exp);
//}
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "arm"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(ARM_REG_R0, getGlobalByName("r0"));
	abi->addRegister(ARM_REG_R1, getGlobalByName("r1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r = global i32 0
		@r0 = global i32 0
		@r1 = global i32 0

		define i32 @fnc() {
			store i32 123, i32* @r0
			store i32 456, i32* @r1
			%a = bitcast i32* @r to void ()*
			%1 = load i32, i32* @r0
			%2 = load i32, i32* @r1
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			%4 = load i32, i32* @r0
			ret i32 %4
		}

		declare void @0()
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "arm"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(ARM_REG_R0, getGlobalByName("r0"));
	abi->addRegister(ARM_REG_R1, getGlobalByName("r1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r0 = global i32 0
		@r1 = global i32 0

		declare i32 @print(i32, i32)

		declare void @0()

		define i32 @fnc() {
			store i32 123, i32* @r0
			store i32 456, i32* @r1
			%1 = load i32, i32* @r0
			%2 = load i32, i32* @r1
			%3 = call i32 @print(i32 %1, i32 %2)
			store i32 %3, i32* @r0
			%4 = load i32, i32* @r0
			ret i32 %4
		}

		declare void @1()

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "arm"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(ARM_REG_R0, getGlobalByName("r0"));
	abi->addRegister(ARM_REG_R1, getGlobalByName("r1"));
	abi->addRegister(ARM_REG_R2, getGlobalByName("r2"));
	abi->addRegister(ARM_REG_R3, getGlobalByName("r3"));
	abi->addRegister(ARM_REG_R4, getGlobalByName("r4"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r0 = global i32 0
		@r1 = global i32 0
		@r2 = global i32 0
		@r3 = global i32 0
		@r4 = global i32 0

		declare i32 @print(i32, i32, i32, i32, i32, i32)

		declare void @0()

		define i32 @fnc() {
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
			%7 = call i32 @print(i32 %1, i32 %2, i32 %3, i32 %4, i32 %5, i32 %6)
			store i32 %7, i32* @r0
			%8 = load i32, i32* @r0
			ret i32 %8
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, arm64PtrCallBasicFunctionality)
{
	parseInput(R"(
		target datalayout = "E-m:e-p:64:64-i64:64-n32"

		@r = global i64 0
		@x0 = global i64 0
		@x1 = global i64 0
		define void @fnc() {
			store i64 123, i64* @x0
			store i64 456, i64* @x1
			%a = bitcast i64* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "arm aarch64"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	AbiArm64 abi(module.get(), &config);

	abi.addRegister(ARM64_REG_X0, getGlobalByName("x0"));
	abi.addRegister(ARM64_REG_X1, getGlobalByName("x1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, &abi, demangler);

	std::string exp = R"(
		target datalayout = "E-m:e-p:64:64-i64:64-n32"

		@r = global i64 0
		@x0 = global i64 0
		@x1 = global i64 0

		define i64 @fnc() {
			store i64 123, i64* @x0
			store i64 456, i64* @x1
			%a = bitcast i64* @r to void ()*
			%1 = load i64, i64* @x0
			%2 = load i64, i64* @x1
			%3 = bitcast void ()* %a to void (i64, i64)*
			call void %3(i64 %1, i64 %2)
			%4 = load i64, i64* @x0
			ret i64 %4
		}

		declare void @0()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, arm64ExternalCallBasicFunctionality)
{
	parseInput(R"(
		@x0 = global i64 0
		@x1 = global i64 0
		declare void @print()
		define void @fnc() {
			store i64 123, i64* @x0
			store i64 456, i64* @x1
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "arm aarch64"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	AbiArm64 abi(module.get(), &config);

	abi.addRegister(ARM64_REG_X0, getGlobalByName("x0"));
	abi.addRegister(ARM64_REG_X1, getGlobalByName("x1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, &abi, demangler);

	std::string exp = R"(
		@x0 = global i64 0
		@x1 = global i64 0

		declare i64 @print(i64, i64)

		declare void @0()

		define i64 @fnc() {
			store i64 123, i64* @x0
			store i64 456, i64* @x1
			%1 = load i64, i64* @x0
			%2 = load i64, i64* @x1
			%3 = call i64 @print(i64 %1, i64 %2)
			store i64 %3, i64* @x0
			%4 = load i64, i64* @x0
			ret i64 %4
		}

		declare void @1()

	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, arm64ExternalCallUseStacksIf8RegistersUsed)
{
	parseInput(R"(
		@x0 = global i64 0
		@x1 = global i64 0
		@x2 = global i64 0
		@x3 = global i64 0
		@x4 = global i64 0
		@x5 = global i64 0
		@x6 = global i64 0
		@x7 = global i64 0
		@x8 = global i64 0
		declare void @print()
		define void @fnc() {
			%stack_-4 = alloca i64
			%stack_-12 = alloca i64
			store i64 1, i64* @x2
			store i64 1, i64* @x1
			store i64 1, i64* @x5
			store i64 1, i64* @x6
			store i64 1, i64* @x8
			store i64 1, i64* @x7
			store i64 2, i64* %stack_-4
			store i64 1, i64* @x4
			store i64 1, i64* @x0
			store i64 2, i64* %stack_-12
			store i64 1, i64* @x3
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "arm aarch64"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-12",
						"storage" : { "type" : "stack", "value" : -12 }
					}
				]
			}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	AbiArm64 abi(module.get(), &config);

	abi.addRegister(ARM64_REG_X0, getGlobalByName("x0"));
	abi.addRegister(ARM64_REG_X1, getGlobalByName("x1"));
	abi.addRegister(ARM64_REG_X2, getGlobalByName("x2"));
	abi.addRegister(ARM64_REG_X3, getGlobalByName("x3"));
	abi.addRegister(ARM64_REG_X4, getGlobalByName("x4"));
	abi.addRegister(ARM64_REG_X5, getGlobalByName("x5"));
	abi.addRegister(ARM64_REG_X6, getGlobalByName("x6"));
	abi.addRegister(ARM64_REG_X7, getGlobalByName("x7"));
	abi.addRegister(ARM64_REG_X8, getGlobalByName("x8"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, &abi, demangler);

	std::string exp = R"(
		@x0 = global i64 0
		@x1 = global i64 0
		@x2 = global i64 0
		@x3 = global i64 0
		@x4 = global i64 0
		@x5 = global i64 0
		@x6 = global i64 0
		@x7 = global i64 0
		@x8 = global i64 0

		declare i64 @print(i64, i64, i64, i64, i64, i64, i64, i64, i64, i64)

		declare void @0()

		define i64 @fnc() {
			%stack_-4 = alloca i64
			%stack_-12 = alloca i64
			store i64 1, i64* @x2
			store i64 1, i64* @x1
			store i64 1, i64* @x5
			store i64 1, i64* @x6
			store i64 1, i64* @x8
			store i64 1, i64* @x7
			store i64 2, i64* %stack_-4
			store i64 1, i64* @x4
			store i64 1, i64* @x0
			store i64 2, i64* %stack_-12
			store i64 1, i64* @x3

			%1 = load i64, i64* @x0
			%2 = load i64, i64* @x1
			%3 = load i64, i64* @x2
			%4 = load i64, i64* @x3
			%5 = load i64, i64* @x4
			%6 = load i64, i64* @x5
			%7 = load i64, i64* @x6
			%8 = load i64, i64* @x7
			%9 = load i64, i64* %stack_-12
			%10 = load i64, i64* %stack_-4
			%11 = call i64 @print(i64 %1, i64 %2, i64 %3, i64 %4, i64 %5, i64 %6, i64 %7, i64 %8, i64 %9, i64 %10)
			store i64 %11, i64* @x0
			%12 = load i64, i64* @x0
			ret i64 %12
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, arm64ExternalCallHasDouleParameter)
{
	parseInput(R"(
		@x0 = global i64 0
		@x1 = global i64 0
		@x2 = global i64 0
		@x3 = global i64 0
		@x4 = global i64 0
		@v0 = global double 0.0
		declare void @foo()
		define void @fnc() {
			store double 0.0, double* @v0
			call void @foo()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "arm aarch64"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	AbiArm64 abi(module.get(), &config);

	abi.addRegister(ARM64_REG_X0, getGlobalByName("x0"));
	abi.addRegister(ARM64_REG_X1, getGlobalByName("x1"));
	abi.addRegister(ARM64_REG_X2, getGlobalByName("x2"));
	abi.addRegister(ARM64_REG_X3, getGlobalByName("x3"));
	abi.addRegister(ARM64_REG_X4, getGlobalByName("x4"));
	abi.addRegister(ARM64_REG_V0, getGlobalByName("v0"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, &abi, demangler);

	std::string exp = R"(
		@x0 = global i64 0
		@x1 = global i64 0
		@x2 = global i64 0
		@x3 = global i64 0
		@x4 = global i64 0
		@v0 = global double 0.0

		declare i64 @foo(double)

		declare void @0()

		define i64 @fnc() {
			store double 0.0, double* @v0
			%1 = load double, double* @v0
			%2 = call i64 @foo(double %1)
			store i64 %2, i64* @x0
			%3 = load i64, i64* @x0
			ret i64 %3
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
//TEST_F(ParamReturnTests, ppcExternalCallUseStacksIf7RegistersUsed)
//{
//	parseInput(R"(
//		@r3 = global i32 0
//		@r4 = global i32 0
//		@r5 = global i32 0
//		@r6 = global i32 0
//		@r7 = global i32 0
//		@r8 = global i32 0
//		@r9 = global i32 0
//		@r10 = global i32 0
//		declare void @print()
//		define void @fnc() {
//			%stack_-4 = alloca i32
//			%stack_-8 = alloca i32
//			store i32 1, i32* @r3
//			store i32 1, i32* @r4
//			store i32 1, i32* @r5
//			store i32 2, i32* %stack_-4
//			store i32 1, i32* @r6
//			store i32 1, i32* @r7
//			store i32 1, i32* @r8
//			store i32 2, i32* %stack_-8
//			store i32 1, i32* @r9
//			store i32 1, i32* @r10
//			call void @print()
//			ret void
//		}
//	)");
//	auto c = config::Config::fromJsonString(R"({
//		"architecture" : {
//			"bitSize" : 32,
//			"endian" : "big",
//			"name" : "powerpc"
//		},
//		"functions" : [
//			{
//				"name" : "fnc",
//				"startAddr" : "0x1234",
//				"locals" : [
//					{
//						"name" : "stack_-4",
//						"storage" : { "type" : "stack", "value" : -4 }
//					},
//					{
//						"name" : "stack_-8",
//						"storage" : { "type" : "stack", "value" : -8 }
//					}
//				]
//			}
//		],
//		"registers" : [
//			{
//				"name" : "r3",
//				"storage" : { "type" : "register", "value" : "r3",
//							"registerClass" : "gpregs", "registerNumber" : 3 }
//			},
//			{
//				"name" : "r4",
//				"storage" : { "type" : "register", "value" : "r4",
//							"registerClass" : "gpregs", "registerNumber" : 4 }
//			},
//			{
//				"name" : "r5",
//				"storage" : { "type" : "register", "value" : "r5",
//							"registerClass" : "gpregs", "registerNumber" : 5 }
//			},
//			{
//				"name" : "r6",
//				"storage" : { "type" : "register", "value" : "r6",
//							"registerClass" : "gpregs", "registerNumber" : 6 }
//			},
//			{
//				"name" : "r7",
//				"storage" : { "type" : "register", "value" : "r7",
//							"registerClass" : "gpregs", "registerNumber" : 7 }
//			},
//			{
//				"name" : "r8",
//				"storage" : { "type" : "register", "value" : "r8",
//							"registerClass" : "gpregs", "registerNumber" : 8 }
//			},
//			{
//				"name" : "r9",
//				"storage" : { "type" : "register", "value" : "r9",
//							"registerClass" : "gpregs", "registerNumber" : 9 }
//			},
//			{
//				"name" : "r10",
//				"storage" : { "type" : "register", "value" : "r10",
//							"registerClass" : "gpregs", "registerNumber" : 10 }
//			}
//		]
//	})");
//	auto config = Config::fromConfig(module.get(), c);
//	auto abi = AbiProvider::addAbi(module.get(), &config);
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "mips"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(MIPS_REG_A0, getGlobalByName("a0"));
	abi->addRegister(MIPS_REG_A1, getGlobalByName("a1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "mips"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(MIPS_REG_A0, getGlobalByName("a0"));
	abi->addRegister(MIPS_REG_A1, getGlobalByName("a1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "mips"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	abi->addRegister(MIPS_REG_A0, getGlobalByName("a0"));
	abi->addRegister(MIPS_REG_A1, getGlobalByName("a1"));
	abi->addRegister(MIPS_REG_A2, getGlobalByName("a2"));
	abi->addRegister(MIPS_REG_A3, getGlobalByName("a3"));
	abi->addRegister(MIPS_REG_T0, getGlobalByName("t0"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

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

TEST_F(ParamReturnTests, mips64PtrCallBasicFunctionality)
{
	parseInput(R"(
		target datalayout = "E-m:e-p:64:64-i64:64-f64:64"

		@r = global i64 0
		@a0 = global i64 0
		@a1 = global i64 0
		define void @fnc() {
			store i64 123, i64* @a0
			store i64 456, i64* @a1
			%a = bitcast i64* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "mips64"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	AbiMips64 abi(module.get(), &config);

	abi.addRegister(MIPS_REG_A0, getGlobalByName("a0"));
	abi.addRegister(MIPS_REG_A1, getGlobalByName("a1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, &abi, demangler);

	std::string exp = R"(
		target datalayout = "E-m:e-p:64:64-i64:64-f64:64"

		@r = global i64 0
		@a0 = global i64 0
		@a1 = global i64 0
		define void @fnc() {
			store i64 123, i64* @a0
			store i64 456, i64* @a1
			%a = bitcast i64* @r to void()*
			%1 = load i64, i64* @a0
			%2 = load i64, i64* @a1
			%3 = bitcast void ()* %a to void (i64, i64)*
			call void %3(i64 %1, i64 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, mips64ExternalCallBasicFunctionality)
{
	parseInput(R"(
		target datalayout = "E-m:e-p:64:64-i64:64-f64:64"

		@a0 = global i64 0
		@a1 = global i64 0
		declare void @print()
		define void @fnc() {
			store i64 123, i64* @a0
			store i64 456, i64* @a1
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "mips64"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);
	AbiMips64 abi(module.get(), &config);

	abi.addRegister(MIPS_REG_A0, getGlobalByName("a0"));
	abi.addRegister(MIPS_REG_A1, getGlobalByName("a1"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, &abi, demangler);

	std::string exp = R"(
		target datalayout = "E-m:e-p:64:64-i64:64-f64:64"

		@a0 = global i64 0
		@a1 = global i64 0
		declare void @print(i64, i64)
		declare void @0()
		define void @fnc() {
			store i64 123, i64* @a0
			store i64 456, i64* @a1
			%1 = load i64, i64* @a0
			%2 = load i64, i64* @a1
			call void @print(i64 %1, i64 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, mips64ExternalCallUseStacksIf8RegistersUsed)
{
	parseInput(R"(
		target datalayout = "E-m:e-p:64:64-i64:64-f64:64"

		@a0 = global i64 0
		@a1 = global i64 0
		@a2 = global i64 0
		@a3 = global i64 0
		@a4 = global i64 0
		@a5 = global i64 0
		@a6 = global i64 0
		@a7 = global i64 0
		@t4 = global i64 0
		declare void @print()
		define void @fnc() {
			%stack_-4 = alloca i64
			%stack_-12 = alloca i64
			store i64 1, i64* @a2
			store i64 1, i64* @a1
			store i64 1, i64* @a7
			store i64 1, i64* @a4
			store i64 2, i64* %stack_-4
			store i64 1, i64* @t4
			store i64 1, i64* @a0
			store i64 2, i64* %stack_-12
			store i64 1, i64* @a6
			store i64 1, i64* @a5
			store i64 1, i64* @a3
			call void @print()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "mips64"
		},
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-12",
						"storage" : { "type" : "stack", "value" : -12 }
					}
				]
			}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	AbiMips64 abi(module.get(), &config);

	abi.addRegister(MIPS_REG_A0, getGlobalByName("a0"));
	abi.addRegister(MIPS_REG_A1, getGlobalByName("a1"));
	abi.addRegister(MIPS_REG_A2, getGlobalByName("a2"));
	abi.addRegister(MIPS_REG_A3, getGlobalByName("a3"));
	abi.addRegister(MIPS_REG_T0, getGlobalByName("a4"));
	abi.addRegister(MIPS_REG_T1, getGlobalByName("a5"));
	abi.addRegister(MIPS_REG_T2, getGlobalByName("a6"));
	abi.addRegister(MIPS_REG_T3, getGlobalByName("a7"));
	abi.addRegister(MIPS_REG_T4, getGlobalByName("t4"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, &abi, demangler);

	std::string exp = R"(
		target datalayout = "E-m:e-p:64:64-i64:64-f64:64"

		@a0 = global i64 0
		@a1 = global i64 0
		@a2 = global i64 0
		@a3 = global i64 0
		@a4 = global i64 0
		@a5 = global i64 0
		@a6 = global i64 0
		@a7 = global i64 0
		@t4 = global i64 0

		declare void @print(i64, i64, i64, i64, i64, i64, i64, i64, i64, i64)
		declare void @0()

		define void @fnc() {
			%stack_-4 = alloca i64
			%stack_-12 = alloca i64
			store i64 1, i64* @a2
			store i64 1, i64* @a1
			store i64 1, i64* @a7
			store i64 1, i64* @a4
			store i64 2, i64* %stack_-4
			store i64 1, i64* @t4
			store i64 1, i64* @a0
			store i64 2, i64* %stack_-12
			store i64 1, i64* @a6
			store i64 1, i64* @a5
			store i64 1, i64* @a3

			%1 = load i64, i64* @a0
			%2 = load i64, i64* @a1
			%3 = load i64, i64* @a2
			%4 = load i64, i64* @a3
			%5 = load i64, i64* @a4
			%6 = load i64, i64* @a5
			%7 = load i64, i64* @a6
			%8 = load i64, i64* @a7
			%9 = load i64, i64* %stack_-12
			%10 = load i64, i64* %stack_-4
			call void @print(i64 %1, i64 %2, i64 %3, i64 %4, i64 %5, i64 %6, i64 %7, i64 %8, i64 %9, i64 %10)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86FastcallBasic)
{
	parseInput(R"(
		@eax = global i32 0
		@edx = global i32 0
		@ecx = global i32 0
		@r = global i32 0
		declare void @a()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @ecx
			store i32 1, i32* @edx
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			call void @a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"tools" :
		[
			{ "name" : "gcc" }
		],
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
				"name" : "a",
				"startAddr" : "0x5678",
				"callingConvention" : "fastcall"
			}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X86_REG_EAX, getGlobalByName("eax"));
	abi->addRegister(X86_REG_ECX, getGlobalByName("ecx"));
	abi->addRegister(X86_REG_EDX, getGlobalByName("edx"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@eax = global i32 0
		@edx = global i32 0
		@ecx = global i32 0
		@r = global i32 0

		declare i32 @a(i32, i32, i32, i32)

		declare void @0()

		define i32 @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @ecx
			store i32 1, i32* @edx
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%1 = load i32, i32* @ecx
			%2 = load i32, i32* @edx
			%3 = load i32, i32* %stack_-8
			%4 = load i32, i32* %stack_-4
			%5 = call i32 @a(i32 %1, i32 %2, i32 %3, i32 %4)
			store i32 %5, i32* @eax
			%6 = load i32, i32* @eax
			ret i32 %6
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86FastcallLargeTypeCatch)
{
	parseInput(R"(
		@r = global i32 0
		@ecx = global i32 0
		@edx = global i32 0
		@eax = global i32 0
		declare void @a()
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* @ecx
			store i32 456, i32* %stack_-4
			store i32 789, i32* %stack_-8
			call void @a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"tools" :
		[
			{ "name" : "gcc" }
		],
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				],
				"calingConvention" : "fastcall"
			},
			{
				"name" : "a",
				"startAddr" : "0x1235",
				"callingConvention" : "fastcall"
			}
		]

	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X86_REG_ECX, getGlobalByName("ecx"));
	abi->addRegister(X86_REG_EAX, getGlobalByName("eax"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r = global i32 0
		@ecx = global i32 0
		@edx = global i32 0
		@eax = global i32 0

		declare i32 @a(i32, i32, i32)

		declare void @0()

		define i32 @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* @ecx
			store i32 456, i32* %stack_-4
			store i32 789, i32* %stack_-8
			%1 = load i32, i32* @ecx
			%2 = load i32, i32* %stack_-8
			%3 = load i32, i32* %stack_-4
			%4 = call i32 @a(i32 %1, i32 %2, i32 %3)
			store i32 %4, i32* @eax
			%5 = load i32, i32* @eax
			ret i32 %5
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86PascalBasic)
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
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"tools" :
		[
			{ "name" : "borland" }
		],
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* %stack_-4
			%2 = load i32, i32* %stack_-8
			%3 = bitcast void ()* %a to void (i32, i32)*
			call void %3(i32 %1, i32 %2)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86PascalFastcallBasic)
{
	parseInput(R"(
		@eax = global i32 0
		@edx = global i32 0
		@ecx = global i32 0
		@r = global i32 0

		declare void @a()

		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @eax
			store i32 1, i32* @ecx
			store i32 1, i32* @edx
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			call void @a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"tools" :
		[
			{ "name" : "borland" }
		],
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				],
				"callingConvention" : "fastcall"
			},
			{
				"name" : "a",
				"callingConvention" : "fastcall"
			}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X86_REG_EAX, getGlobalByName("eax"));
	abi->addRegister(X86_REG_EDX, getGlobalByName("edx"));
	abi->addRegister(X86_REG_ECX, getGlobalByName("ecx"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@eax = global i32 0
		@edx = global i32 0
		@ecx = global i32 0
		@r = global i32 0

		declare i32 @a(i32, i32, i32, i32, i32)

		declare void @0()

		define i32 @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @eax
			store i32 1, i32* @ecx
			store i32 1, i32* @edx
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%1 = load i32, i32* @eax
			%2 = load i32, i32* @edx
			%3 = load i32, i32* @ecx
			%4 = load i32, i32* %stack_-4
			%5 = load i32, i32* %stack_-8
			%6 = call i32 @a(i32 %1, i32 %2, i32 %3, i32 %4, i32 %5)
			store i32 %6, i32* @eax
			%7 = load i32, i32* @eax
			ret i32 %7
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86PascalFastcallLargeType)
{
	parseInput(R"(
		@eax = global i32 0
		@edx = global i32 0
		@r = global i32 0

		declare void @a()

		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @eax
			store i32 456, i32* %stack_-8
			store i32 123, i32* %stack_-4
			store i32 1, i32* @edx
			call void @a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"tools" :
		[
			{ "name" : "borland" }
		],
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
				"locals" : [
					{
						"name" : "stack_-4",
						"storage" : { "type" : "stack", "value" : -4 }
					},
					{
						"name" : "stack_-8",
						"storage" : { "type" : "stack", "value" : -8 }
					}
				],
				"callingConvention" : "fastcall"
			},
			{
				"name" : "a",
				"callingConvention" : "fastcall"
			}
		]
	})");
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X86_REG_EAX, getGlobalByName("eax"));
	abi->addRegister(X86_REG_EDX, getGlobalByName("edx"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@eax = global i32 0
		@edx = global i32 0
		@r = global i32 0

		declare i32 @a(i32, i32, i32, i32)

		declare void @0()

		define i32 @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @eax
			store i32 456, i32* %stack_-8
			store i32 123, i32* %stack_-4
			store i32 1, i32* @edx
			%1 = load i32, i32* @eax
			%2 = load i32, i32* @edx
			%3 = load i32, i32* %stack_-4
			%4 = load i32, i32* %stack_-8
			%5 = call i32 @a(i32 %1, i32 %2, i32 %3, i32 %4)
			store i32 %5, i32* @eax
			%6 = load i32, i32* @eax
			ret i32 %6
		}

		declare void @1()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86WatcomBasic)
{
	parseInput(R"(
		@eax = global i32 0
		@ebx = global i32 0
		@edx = global i32 0
		@ecx = global i32 0
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @eax
			store i32 1, i32* @ebx
			store i32 1, i32* @ecx
			store i32 1, i32* @edx
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"tools" :
		[
			{ "name" : "open_watcom" }
		],
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X86_REG_EAX, getGlobalByName("eax"));
	abi->addRegister(X86_REG_EBX, getGlobalByName("ebx"));
	abi->addRegister(X86_REG_ECX, getGlobalByName("ecx"));
	abi->addRegister(X86_REG_EDX, getGlobalByName("edx"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@eax = global i32 0
		@ebx = global i32 0
		@edx = global i32 0
		@ecx = global i32 0
		@r = global i32 0

		define i32 @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @eax
			store i32 1, i32* @ebx
			store i32 1, i32* @ecx
			store i32 1, i32* @edx
			store i32 123, i32* %stack_-4
			store i32 456, i32* %stack_-8
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* @eax
			%2 = load i32, i32* @edx
			%3 = load i32, i32* @ebx
			%4 = load i32, i32* @ecx
			%5 = load i32, i32* %stack_-8
			%6 = load i32, i32* %stack_-4
			%7 = bitcast void ()* %a to void (i32, i32, i32, i32, i32, i32)*
			call void %7(i32 %1, i32 %2, i32 %3, i32 %4, i32 %5, i32 %6)
			%8 = load i32, i32* @eax
			ret i32 %8
		}

		declare void @0()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(ParamReturnTests, x86WatcomPassDouble)
{
	parseInput(R"(
		@eax = global i32 0
		@edx = global i32 0
		@r = global i32 0
		define void @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @eax
			store i32 1, i32* @edx
			store i32 456, i32* %stack_-8
			store i32 123, i32* %stack_-4
			%a = bitcast i32* @r to void()*
			call void %a()
			ret void
		}
	)");
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		},
		"tools" :
		[
			{ "name" : "open_watcom" }
		],
		"functions" : [
			{
				"name" : "fnc",
				"startAddr" : "0x1234",
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
	auto config = Config::fromConfig(module.get(), c);
	auto abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X86_REG_EAX, getGlobalByName("eax"));
	abi->addRegister(X86_REG_EDX, getGlobalByName("edx"));

	auto typeConfig = std::make_unique<ctypesparser::TypeConfig>();
	auto demangler = DemanglerProvider::addDemangler(
		module.get(),
		&config,
		std::move(typeConfig));

	pass.runOnModuleCustom(*module, &config, abi, demangler);

	std::string exp = R"(
		@eax = global i32 0
		@edx = global i32 0
		@r = global i32 0

		define i32 @fnc() {
			%stack_-4 = alloca i32
			%stack_-8 = alloca i32
			store i32 1, i32* @eax
			store i32 1, i32* @edx
			store i32 456, i32* %stack_-8
			store i32 123, i32* %stack_-4
			%a = bitcast i32* @r to void()*
			%1 = load i32, i32* @eax
			%2 = load i32, i32* @edx
			%3 = load i32, i32* %stack_-8
			%4 = load i32, i32* %stack_-4
			%5 = bitcast void ()* %a to void (i32, i32, i32, i32)*
			call void %5(i32 %1, i32 %2, i32 %3, i32 %4)
			%6 = load i32, i32* @eax
			ret i32 %6
		}

		declare void @0()
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
