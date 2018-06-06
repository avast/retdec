/**
* @file tests/bin2llvmir/analyses/tests/uses_analysis_tests.cpp
* @brief Tests for the uses analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/analyses/uses_analysis.h"
#include "retdec/bin2llvmir/utils/debug.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
* @brief Tests for the uses analysis.
*/
class UsesAnalysisTests: public Test {
protected:
	/**
	* @brief Constructs a uses analysis test.
	*/
	UsesAnalysisTests() {
		module = new Module("test", context);
		Constant *funcConstant(module->getOrInsertFunction("func1",
			Type::getVoidTy(context), AttributeSet(), nullptr));
		Constant *globConstant(module->getOrInsertGlobal("glob0",
			Type::getInt32Ty(context)));
		glob = cast<GlobalVariable>(globConstant);
		bbInFunc1 = BasicBlock::Create(context, "bb",
			cast<Function>(funcConstant));
		func1 = nullptr;
	}

	/**
	* @brief Destructs a uses analysis test.
	*/
	~UsesAnalysisTests() {
		delete module;
	}

protected:
	/// Context for our testing module.
	LLVMContext context;

	/// We can use this module for testing.
	Module *module;

	/// Global variable for testing..
	GlobalVariable *glob;

	/// Function for testing.
	Function *func1;

	/// Basic block in function 1 to testing.
	BasicBlock *bbInFunc1;

	/// Uses analysis.
	UsesAnalysis usesAnalysis;
};

TEST_F(UsesAnalysisTests,
AnalysisHasNonEmptyID) {
	EXPECT_TRUE(!usesAnalysis.getName().empty()) <<
		"the analyzer should have a non-empty ID";
}

TEST_F(UsesAnalysisTests,
GetUseInfoLeftUseTest) {
	// Testing if analysis returns correct info for instruction.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbInFunc1:
	//   store i32 1, i32* @glob0
	// }
	//

	// Creating input of test is in constructor of this test class.
	StoreInst *storeInst(new StoreInst(ConstantInt::get(
		Type::getInt32Ty(context), 1, true), glob, bbInFunc1));
	std::set<llvm::GlobalVariable*> globs{glob};
	usesAnalysis.doUsesAnalysis(globs);

	const UsesAnalysis::UseInfo *info(usesAnalysis.getUseInfo(*bbInFunc1,
		*storeInst));

	ASSERT_TRUE(info) <<
		"expected not the null pointer. \n";

	EXPECT_TRUE(info->isLUse) <<
		"expected that contained info is left use. \n";
}

TEST_F(UsesAnalysisTests,
GetUseInfoRightUseTest) {
	// Testing if analysis returns correct info for instruction.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbInFunc1:
	//   %x = load i32, i32* @glob0
	// }
	//

	// Creating input of test is in constructor of this test class.
	LoadInst *loadInst(new LoadInst(glob, "x", bbInFunc1));
	std::set<llvm::GlobalVariable*> globs{glob};
	usesAnalysis.doUsesAnalysis(globs);

	const UsesAnalysis::UseInfo *info(usesAnalysis.getUseInfo(*bbInFunc1,
		*loadInst));

	ASSERT_TRUE(info) <<
		"expected not the null pointer. \n";

	EXPECT_FALSE(info->isLUse) <<
		"expected that contained info is right use. \n";
}

TEST_F(UsesAnalysisTests,
HasNoUseTest) {
	// Testing if analysis make a correct decision about uses of global
	// variable.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbInFunc1:
	// }
	//

	// Creating input of test is in constructor of this test class.

	EXPECT_TRUE(UsesAnalysis::hasNoUse(*glob)) <<
		"expected that global variable doesn't have use. \n";
}

TEST_F(UsesAnalysisTests,
HasUseTest) {
	// Testing if analysis make a correct decision about uses of global
	// variable.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbInFunc1:
	//   %x = load i32, i32* @glob0
	// }
	//

	// Creating the main part of test is in constructor of this test class.
	new LoadInst(glob, "x", bbInFunc1);

	EXPECT_FALSE(UsesAnalysis::hasNoUse(*glob)) <<
		"expected that global variable has some use. \n";
}

TEST_F(UsesAnalysisTests,
hasValueUsesExceptTest) {
	// Testing if analysis recognizes uses except given uses.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbInFunc1:
	//   %x = load i32, i32* @glob0
	//   %z = load i32, i32* @glob0
	// }
	//

	// Creating the main part of test is in constructor of this test class.
	new LoadInst(glob, "x", bbInFunc1);
	std::set<llvm::Instruction*> exceptSet{new LoadInst(glob, "x", bbInFunc1)};

	EXPECT_TRUE(UsesAnalysis::hasValueUsesExcept(*glob, exceptSet)) <<
		"expected that global variable has some another uses except that"
		" are in given set. \n";
}

TEST_F(UsesAnalysisTests,
hasNotValueUsesExceptTest) {
	// Testing if analysis recognizes uses except given uses.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbInFunc1:
	//   %x = load i32, i32* @glob0
	// }
	//

	// Creating the main part of test is in constructor of this test class.
	std::set<llvm::Instruction*> exceptSet{new LoadInst(glob, "x", bbInFunc1)};

	EXPECT_FALSE(UsesAnalysis::hasValueUsesExcept(*glob, exceptSet)) <<
		"expected that global variable has only uses that are in given set. \n";
}

TEST_F(UsesAnalysisTests,
hasUseOnlyInOneFuncTest) {
	// Testing if analysis recognizes only one use in function.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbInFunc1:
	//   %x = load i32, i32* @glob0
	// }
	// define void @func2() {
	// }
	//

	// Creating the main part of test is in constructor of this test class.
	module->getOrInsertFunction("func2", Type::getVoidTy(context),
		AttributeSet(), nullptr);
	new LoadInst(glob, "x", bbInFunc1);

	EXPECT_TRUE(UsesAnalysis::hasUsesOnlyInOneFunc(*glob)) <<
		"expected that global variable has use only in one function. \n";
}

TEST_F(UsesAnalysisTests,
hasNoUseOnlyInOneFuncTest) {
	// Testing if analysis recognizes uses of global variables in more than one
	// function.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbFunc1:
	//   %x = load i32, i32* @glob0
	// }
	// define void @func2() {
	// bbFunc2:
	//   %z = load i32, i32* @glob0
	// }
	//

	// Creating the main part of test is in constructor of this test class.
	Constant *func2Constant(module->getOrInsertFunction(
		"func2", Type::getVoidTy(context), AttributeSet(), nullptr));
	BasicBlock *bbInFunc2(BasicBlock::Create(context, "bbFunc2",
		cast<Function>(func2Constant)));
	new LoadInst(glob, "x", bbInFunc1);
	new LoadInst(glob, "z", bbInFunc2);

	EXPECT_FALSE(UsesAnalysis::hasUsesOnlyInOneFunc(*glob)) <<
		"expected that global variable doesn't have use only in one"
		" function. \n";
}

TEST_F(UsesAnalysisTests,
hasVolatileLoadTest) {
	// Testing if analysis recognizes volatile load instruction as uses of a
	// global variable.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbFunc1:
	//   %x = load volatile i32, i32* @glob0
	// }
	//

	// Creating the main part of test is in constructor of this test class.
	new LoadInst(glob, "x", true, bbInFunc1);

	EXPECT_TRUE(UsesAnalysis::hasSomeUseVolatileLoadOrStore(*glob)) <<
		"expected that global variable has volatile load. \n";
}

TEST_F(UsesAnalysisTests,
hasNoVolatileLoadTest) {
	// Testing if analysis recognizes volatile load instruction as uses of a
	// global variable.
	//
	// @glob0 = global i32 0
	// define void @func1() {
	// bbFunc1:
	//   %x = load volatile i32, i32* @glob0
	// }
	//

	// Creating the main part of test is in constructor of this test class.
	new LoadInst(glob, "x", bbInFunc1);

	EXPECT_FALSE(UsesAnalysis::hasSomeUseVolatileLoadOrStore(*glob)) <<
		"expected that global variable doesn't have volatile load. \n";
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
