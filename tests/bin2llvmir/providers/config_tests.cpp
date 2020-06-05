/**
* @file tests/bin2llvmir/providers/tests/config_tests.cpp
* @brief Tests for the @c Config and @c ConfigProvider.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/providers/config.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

//
//=============================================================================
//  ConfigTests
//=============================================================================
//

/**
 * @brief Tests for the @c Config.
 */
class ConfigTests: public LlvmIrTests
{

};

//
// getConfigFunction()
//

TEST_F(ConfigTests, getConfigFunctionGetsExistingFunction)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	Function* llvmFnc = getFunctionByName("fnc");
	auto config = Config::empty(module.get());
	auto p = config.getConfig().functions.insert(retdec::common::Function("fnc"));
	auto* configFnc1 = config.getConfigFunction(llvmFnc);

	EXPECT_NE(nullptr, configFnc1);
	EXPECT_EQ(&(*p.first), configFnc1);
}

TEST_F(ConfigTests, getConfigFunctionReturnsNullptrIfFunctionNotFound)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	Function* llvmFnc = getFunctionByName("fnc");
	auto config = Config::empty(module.get());
	auto p = config.getConfig().functions.insert(retdec::common::Function("f"));
	auto* configFnc1 = config.getConfigFunction(llvmFnc);

	EXPECT_EQ(nullptr, configFnc1);
	EXPECT_NE(&(*p.first), configFnc1);
}

//
// getLlvmFunction
//

TEST_F(ConfigTests, getLlvmFunctionGetsExistingFunction)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	Function* llvmFnc1 = getFunctionByName("fnc");
	auto config = Config::empty(module.get());
	auto configFnc = retdec::common::Function("fnc");
	configFnc.setStart(0x1234);
	config.getConfig().functions.insert(configFnc);
	Function* llvmFnc2 = config.getLlvmFunction(0x1234);

	EXPECT_EQ(llvmFnc1, llvmFnc2);
}

TEST_F(ConfigTests, getLlvmFunctionReturnsNullptrIfFunctionNotFound)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	Function* llvmFnc1 = getFunctionByName("fnc");
	auto config = Config::empty(module.get());
	auto configFnc = retdec::common::Function("fnc");
	configFnc.setStart(0x1234);
	config.getConfig().functions.insert(configFnc);
	Function* llvmFnc2 = config.getLlvmFunction(0x5678);

	EXPECT_EQ(nullptr, llvmFnc2);
	EXPECT_NE(llvmFnc1, llvmFnc2);
}

//
// getFunctionAddress()
//

TEST_F(ConfigTests, getFunctionAddressReturnsDefinedAddressIfFunctionFound)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	Function* llvmFnc = getFunctionByName("fnc");
	auto config = Config::empty(module.get());
	auto configFnc = retdec::common::Function("fnc");
	configFnc.setStart(0x1234);
	config.getConfig().functions.insert(configFnc);
	auto addr = config.getFunctionAddress(llvmFnc);

	EXPECT_EQ(0x1234, addr);
}

TEST_F(ConfigTests, getFunctionAddressReturnsUndefinedAddressIfFunctionNotFound)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	Function* llvmFnc = getFunctionByName("fnc");
	auto config = Config::empty(module.get());
	auto configFnc = retdec::common::Function("f");
	configFnc.setStart(0x1234);
	config.getConfig().functions.insert(configFnc);
	auto addr = config.getFunctionAddress(llvmFnc);

	EXPECT_TRUE(addr.isUndefined());
}

//
// getConfigRegister()
//

TEST_F(ConfigTests, getConfigRegisterReturnsConfigRegisterIfItExists)
{
	parseInput(R"(
		@r = global i1 0
	)");
	auto* llvmReg = getGlobalByName("r");
	auto s = retdec::common::Storage::inRegister("r");
	auto r = retdec::common::Object("r", s);
	auto config = Config::empty(module.get());
	auto p = config.getConfig().registers.insert(r);
	auto* configReg = config.getConfigRegister(llvmReg);

	EXPECT_NE(nullptr, configReg);
	EXPECT_EQ(&(*p.first), configReg);
}

TEST_F(ConfigTests, getConfigRegisterReturnsNullptrIfItRegisterNotFound)
{
	parseInput(R"(
		@r = global i1 0
	)");
	auto* llvmReg = getGlobalByName("r");
	auto s = retdec::common::Storage::inRegister("reg");
	auto r = retdec::common::Object("reg", s);
	auto config = Config::empty(module.get());
	config.getConfig().registers.insert(r);
	auto* configReg = config.getConfigRegister(llvmReg);

	EXPECT_EQ(nullptr, configReg);
}

//
// getConfigRegisterNumber()
//

TEST_F(ConfigTests, getConfigRegisterNumberReturnDefinedValueIfItExists)
{
	parseInput(R"(
		@r = global i1 0
	)");
	auto* llvmReg = getGlobalByName("r");
	auto s = retdec::common::Storage::inRegister("r", 123);
	auto r = retdec::common::Object("r", s);
	auto config = Config::empty(module.get());
	config.getConfig().registers.insert(r);
	auto regNum = config.getConfigRegisterNumber(llvmReg);

	EXPECT_TRUE(regNum.has_value());
	EXPECT_EQ(123, regNum);
}

TEST_F(ConfigTests, getConfigRegisterNumberReturnUndefinedValueIfItDoesNotExist)
{
	parseInput(R"(
		@r = global i1 0
	)");
	auto* llvmReg = getGlobalByName("r");
	auto s = retdec::common::Storage::inRegister("r");
	auto r = retdec::common::Object("r", s);
	auto config = Config::empty(module.get());
	config.getConfig().registers.insert(r);
	auto regNum = config.getConfigRegisterNumber(llvmReg);

	EXPECT_FALSE(regNum.has_value());
}

//
// getConfigGlobalVariable()
//

TEST_F(ConfigTests, getConfigGlobalVariableGetsExistingGlobalVariable)
{
	parseInput(R"(
		@gv = global i32 0
	)");
	GlobalVariable* llvmGv = getGlobalByName("gv");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::inMemory(0x1234);
	auto cgv = retdec::common::Object("gv", s);
	auto p = config.getConfig().globals.insert(cgv);
	auto* configGv1 = config.getConfigGlobalVariable(llvmGv);

	EXPECT_NE(nullptr, configGv1);
	EXPECT_EQ(&(*p.first), configGv1);
}

TEST_F(ConfigTests, getConfigGlobalVariableReturnsNullptrIfGlobalVariableNotFound)
{
	parseInput(R"(
		@gv = global i32 0
	)");
	GlobalVariable* llvmGv = getGlobalByName("gv");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::inMemory(0x1234);
	auto cgv = retdec::common::Object("global", s);
	auto p = config.getConfig().globals.insert(cgv);
	auto* configGv1 = config.getConfigGlobalVariable(llvmGv);

	EXPECT_EQ(nullptr, configGv1);
	EXPECT_NE(&(*p.first), configGv1);
}

//
// getLlvmGlobalVariable()
//

TEST_F(ConfigTests, getLlvmGlobalVariableGetsExistingGlobalVariable)
{
	parseInput(R"(
		@gv = global i32 0
	)");
	GlobalVariable* llvmGv = getGlobalByName("gv");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::inMemory(0x1234);
	auto cgv = retdec::common::Object("gv", s);
	config.getConfig().globals.insert(cgv);
	GlobalVariable* gv1 = config.getLlvmGlobalVariable(0x1234);
	GlobalVariable* gv2 = config.getLlvmGlobalVariable("bad name", 0x1234);
	GlobalVariable* gv3 = config.getLlvmGlobalVariable("gv", 0x5678);
	GlobalVariable* gv4 = config.getLlvmGlobalVariable("gv", 0x1234);

	EXPECT_NE(nullptr, gv1);
	EXPECT_EQ(llvmGv, gv1);
	EXPECT_EQ(gv1, gv2);
	EXPECT_EQ(gv1, gv3);
	EXPECT_EQ(gv1, gv4);
}

TEST_F(ConfigTests, getLlvmGlobalVariableReturnNullptrIfGlobalVariableNotFound)
{
	parseInput(R"(
		@gv = global i32 0
	)");
	GlobalVariable* llvmGv = getGlobalByName("gv");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::inMemory(0x5678);
	auto cgv = retdec::common::Object("global", s);
	config.getConfig().globals.insert(cgv);
	GlobalVariable* gv1 = config.getLlvmGlobalVariable(0x1234);
	GlobalVariable* gv2 = config.getLlvmGlobalVariable("bad name", 0x1234);

	EXPECT_NE(llvmGv, gv1);
	EXPECT_EQ(nullptr, gv1);
	EXPECT_EQ(gv1, gv2);
}

//
// getGlobalAddress()
//

TEST_F(ConfigTests, getGlobalAddressReturnsDefinedAddressForKnownGlobals)
{
	parseInput(R"(
		@gv = global i32 0
	)");
	GlobalVariable* llvmGv = getGlobalByName("gv");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::inMemory(0x1234);
	auto cgv = retdec::common::Object("gv", s);
	config.getConfig().globals.insert(cgv);
	auto addr = config.getGlobalAddress(llvmGv);

	EXPECT_EQ(0x1234, addr);
}

TEST_F(ConfigTests, getGlobalAddressReturnsUndefinedAddressForUnknownGlobals)
{
	parseInput(R"(
		@gv = global i32 0
	)");
	GlobalVariable* llvmGv = getGlobalByName("gv");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::inMemory(0x1234);
	auto cgv = retdec::common::Object("global", s);
	config.getConfig().globals.insert(cgv);
	auto addr = config.getGlobalAddress(llvmGv);

	EXPECT_TRUE(addr.isUndefined());
}

//
// getConfigLocalVariable()
//

TEST_F(ConfigTests, getConfigLocalVariableFindsLocalVariables)
{
	parseInput(R"(
		define void @fnc() {
			%local = alloca i32
			ret void
		}
	)");
	auto* llvmLv = getValueByName("local");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::undefined();
	auto clv = retdec::common::Object("local", s);
	auto cf = retdec::common::Function("fnc");
	cf.locals.insert(clv);
	config.getConfig().functions.insert(cf);
	auto* cclv = config.getConfigLocalVariable(llvmLv);

	ASSERT_NE(nullptr, cclv);
	EXPECT_EQ("local", cclv->getName());
}

TEST_F(ConfigTests, getConfigLocalVariableDoesNotFindNonLocalVariables)
{
	parseInput(R"(
		@gv = global i32 0
		define void @fnc() {
			%stack = alloca i32
			%local = alloca i32
			ret void
		}
	)");
	auto* llvmFnc = getFunctionByName("fnc");
	auto* llvmGv = getValueByName("gv");
	auto* llvmLv = getValueByName("local");
	auto* llvmSv = getValueByName("stack");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::onStack(4);
	auto cSv = retdec::common::Object("stack", s);
	auto cf = retdec::common::Function("fnc");
	cf.locals.insert(cSv);
	config.getConfig().functions.insert(cf);

	EXPECT_EQ(nullptr, config.getConfigLocalVariable(llvmFnc));
	EXPECT_EQ(nullptr, config.getConfigLocalVariable(llvmGv));
	EXPECT_EQ(nullptr, config.getConfigLocalVariable(llvmLv));
	EXPECT_EQ(nullptr, config.getConfigLocalVariable(llvmSv));
}

//
// getConfigStackVariable()
// isStackVariable()
//

TEST_F(ConfigTests, getConfigStackVariableFindsStackVariables)
{
	parseInput(R"(
		define void @fnc() {
			%stack = alloca i32
			ret void
		}
	)");
	auto* llvmSv = getValueByName("stack");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::onStack(4);
	auto cSv = retdec::common::Object("stack", s);
	auto cf = retdec::common::Function("fnc");
	cf.locals.insert(cSv);
	config.getConfig().functions.insert(cf);
	auto* ccSv = config.getConfigStackVariable(llvmSv);

	ASSERT_NE(nullptr, ccSv);
	EXPECT_EQ("stack", ccSv->getName());
	EXPECT_TRUE(ccSv->getStorage().isStack());
	EXPECT_EQ(4, ccSv->getStorage().getStackOffset());
	EXPECT_TRUE(config.isStackVariable(llvmSv));
}

TEST_F(ConfigTests, getConfigStackVariableDoesNotFindNonStackVariables)
{
	parseInput(R"(
		@gv = global i32 0
		define void @fnc() {
			%stack = alloca i32
			%local = alloca i32
			ret void
		}
	)");
	auto* llvmFnc = getFunctionByName("fnc");
	auto* llvmGv = getValueByName("gv");
	auto* llvmLv = getValueByName("local");
	auto* llvmSv = getValueByName("stack");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::undefined();
	auto cLv = retdec::common::Object("local", s);
	auto cf = retdec::common::Function("fnc");
	cf.locals.insert(cLv);
	config.getConfig().functions.insert(cf);

	EXPECT_EQ(nullptr, config.getConfigStackVariable(llvmFnc));
	EXPECT_EQ(nullptr, config.getConfigStackVariable(llvmGv));
	EXPECT_EQ(nullptr, config.getConfigStackVariable(llvmLv));
	EXPECT_EQ(nullptr, config.getConfigStackVariable(llvmSv));
	EXPECT_FALSE(config.isStackVariable(llvmFnc));
	EXPECT_FALSE(config.isStackVariable(llvmGv));
	EXPECT_FALSE(config.isStackVariable(llvmLv));
	EXPECT_FALSE(config.isStackVariable(llvmSv));
}

//
// getLlvmStackVariable()
//

TEST_F(ConfigTests, getLlvmStackVariableFindsStackVariable)
{
	parseInput(R"(
		define void @fnc() {
			%stack = alloca i32
			ret void
		}
	)");
	auto* llvmFnc = getFunctionByName("fnc");
	auto* llvmSv = getValueByName("stack");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::onStack(8);
	auto cSv = retdec::common::Object("stack", s);
	auto cf = retdec::common::Function("fnc");
	cf.locals.insert(cSv);
	config.getConfig().functions.insert(cf);
	auto* sv = config.getLlvmStackVariable(llvmFnc, 8);

	ASSERT_NE(nullptr, sv);
	EXPECT_EQ(llvmSv, sv);
}

TEST_F(ConfigTests, getLlvmStackVariableReturnsNullptrWhenStackVariableNotFound)
{
	parseInput(R"(
		define void @fnc() {
			%stack = alloca i32
			ret void
		}
	)");
	auto* llvmFnc = getFunctionByName("fnc");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::onStack(8);
	auto cSv = retdec::common::Object("stack", s);
	auto cf = retdec::common::Function("fnc");
	cf.locals.insert(cSv);
	config.getConfig().functions.insert(cf);

	auto* sv1 = config.getLlvmStackVariable(nullptr, 8);
	auto* sv2 = config.getLlvmStackVariable(llvmFnc, 4);

	EXPECT_EQ(nullptr, sv1);
	EXPECT_EQ(nullptr, sv2);
}

//
// getStackVariableOffset()
//

TEST_F(ConfigTests, getStackVariableOffsetReturnsDefinedValueForStacks)
{
	parseInput(R"(
		define void @fnc() {
			%stack = alloca i32
			ret void
		}
	)");
	auto* llvmSv = getValueByName("stack");
	auto config = Config::empty(module.get());
	auto s = retdec::common::Storage::onStack(4);
	auto cSv = retdec::common::Object("stack", s);
	auto cf = retdec::common::Function("fnc");
	cf.locals.insert(cSv);
	config.getConfig().functions.insert(cf);
	auto off = config.getStackVariableOffset(llvmSv);

	ASSERT_TRUE(off.has_value());
	EXPECT_EQ(4, off.value());
}

TEST_F(ConfigTests, getStackVariableOffsetReturnsUndefinedValueForNonStacks)
{
	parseInput(R"(
		define void @fnc() {
			ret void
		}
	)");
	auto* llvmFnc = getValueByName("fnc");
	auto config = Config::empty(module.get());
	auto off = config.getStackVariableOffset(llvmFnc);

	ASSERT_FALSE(off.has_value());
}

//
// getGlobalDummy()
//

TEST_F(ConfigTests, getGlobalDummyReturnsValidGlobal)
{
	auto config = Config::empty(module.get());
	auto* gv1 = config.getGlobalDummy();
	EXPECT_NE(nullptr, gv1);

	auto* gv2 = config.getGlobalDummy();
	EXPECT_EQ(gv1, gv2);
}

//
// insertStackVariable()
//

TEST_F(ConfigTests, insertStackVariableNew)
{
	parseInput(R"(
		define void @fnc() {
			%sv_4 = alloca i32
			ret void
		}
	)");
	auto* fnc = getFunctionByName("fnc");
	auto* sv1 = cast<AllocaInst>(getValueByName("sv_4"));

	auto c = Config::empty(module.get());
	auto* cf = c.insertFunction(fnc, 0x10, 0x20);
	auto* csv = c.insertStackVariable(sv1, 4, true);

	ASSERT_NE(nullptr, cf);
	ASSERT_NE(nullptr, csv);
	EXPECT_EQ(1, cf->locals.size());
	EXPECT_EQ(cf->locals.getObjectByName("sv_4"), csv);
	EXPECT_EQ("sv_4", csv->getName());
	EXPECT_TRUE(csv->getStorage().isStack());
	EXPECT_EQ(4, csv->getStorage().getStackOffset());
	EXPECT_TRUE(csv->isFromDebug());
	EXPECT_EQ("i32*", csv->type.getLlvmIr());
}

//
//=============================================================================
//  ConfigProviderTests
//=============================================================================
//

/**
 * @brief Tests for the @c ConfigProvider.
 */
class ConfigProviderTests: public LlvmIrTests
{

};

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
