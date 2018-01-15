/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/variables_manager_tests.cpp
* @brief Tests for the @c variables_manager module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>
#include <llvm/ADT/Twine.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>

#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/assertions.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/variables_manager.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c variables_manager module.
*/
class VariablesManagerTests: public TestsWithModule {
public:
	VariablesManagerTests();

protected:
	/// Context for the LLVM module.
	llvm::LLVMContext context;

	/// Variables manager.
	UPtr<VariablesManager> variablesManager;
};

VariablesManagerTests::VariablesManagerTests():
	variablesManager(std::make_unique<VariablesManager>(module)) {}

//
// Tests for getVarByValue()
//

TEST_F(VariablesManagerTests,
VariableWithCorrectNameIsReturnedForLLVMValue) {
	auto type = llvm::Type::getInt32Ty(context);
	auto llvmVal = std::make_unique<llvm::Argument>(type, "var");

	auto var = variablesManager->getVarByValue(llvmVal.get());

	ASSERT_TRUE(var);
	ASSERT_EQ("var"s, var->getName());
}

TEST_F(VariablesManagerTests,
IdenticalVariableIsReturnedForIdenticalLLVMValue) {
	auto type = llvm::Type::getInt32Ty(context);
	auto llvmVal = std::make_unique<llvm::Argument>(type, "var");

	auto var1 = variablesManager->getVarByValue(llvmVal.get());
	auto var2 = variablesManager->getVarByValue(llvmVal.get());

	ASSERT_TRUE(var1);
	ASSERT_TRUE(var2);
	ASSERT_BIR_EQ(var1, var2);
}

TEST_F(VariablesManagerTests,
VariableWithNameIsReturnedForLLVMValueWithoutName) {
	auto type = llvm::Type::getInt32Ty(context);
	auto llvmVal = std::make_unique<llvm::Argument>(type);

	auto var = variablesManager->getVarByValue(llvmVal.get());

	ASSERT_TRUE(var);
	ASSERT_TRUE(var->hasName());
}

TEST_F(VariablesManagerTests,
IdenticalVariableIsReturnedForIdenticalLLVMValueWithoutName) {
	auto type = llvm::Type::getInt32Ty(context);
	auto llvmVal = std::make_unique<llvm::Argument>(type);

	auto var1 = variablesManager->getVarByValue(llvmVal.get());
	auto var2 = variablesManager->getVarByValue(llvmVal.get());

	ASSERT_TRUE(var1);
	ASSERT_TRUE(var2);
	ASSERT_BIR_EQ(var1, var2);
}

TEST_F(VariablesManagerTests,
FunctionAsVariableIsReturnedForExistingFunctionInModule) {
	auto funcRetType = llvm::Type::getVoidTy(context);
	auto funcType = llvm::FunctionType::get(funcRetType, false);
	auto func = UPtr<llvm::Function>(llvm::Function::Create(funcType,
		llvm::Function::ExternalLinkage, "exampleFunction"));
	addFuncDecl(func->getName());

	auto var = variablesManager->getVarByValue(func.get());

	ASSERT_TRUE(var);
	ASSERT_EQ("exampleFunction"s, var->getName());
	ASSERT_TRUE(isa<VoidType>(var->getType()));
}

TEST_F(VariablesManagerTests,
GlobalVariableIsReturnedForExistingGlobalVariableInModule) {
	auto llvmIntType = llvm::Type::getInt32Ty(context);
	auto llvmGlobVar = std::make_unique<llvm::GlobalVariable>(llvmIntType,
		false, llvm::GlobalVariable::ExternalLinkage, nullptr, "g");
	auto globVar = Variable::create(llvmGlobVar->getName(), IntType::create(32));
	module->addGlobalVar(globVar);

	auto var = variablesManager->getVarByValue(llvmGlobVar.get());

	ASSERT_TRUE(var);
	ASSERT_BIR_EQ(globVar, var);
}

//
// Tests for getLocalVars()
//

TEST_F(VariablesManagerTests,
EmptyVarSetIsReturnedForEmptyVars) {
	ASSERT_TRUE(variablesManager->getLocalVars().empty());
}

TEST_F(VariablesManagerTests,
CorrectVarSetIsReturnedForNonEmptyVars) {
	auto type = llvm::Type::getInt32Ty(context);
	auto llvmVal1 = std::make_unique<llvm::Argument>(type, "var1");
	auto llvmVal2 = std::make_unique<llvm::Argument>(type, "var2");
	auto llvmVal3 = std::make_unique<llvm::Argument>(type, "var3");

	auto var1 = variablesManager->getVarByValue(llvmVal1.get());
	auto var2 = variablesManager->getVarByValue(llvmVal2.get());
	auto var3 = variablesManager->getVarByValue(llvmVal3.get());

	ASSERT_EQ(VarSet({var1, var2, var3}), variablesManager->getLocalVars());
}

//
// Tests for reset()
//

TEST_F(VariablesManagerTests,
DifferentVariablesAreReturnedForIdenticalLLVMValueAfterReset) {
	auto type = llvm::Type::getInt32Ty(context);
	auto llvmVal = std::make_unique<llvm::Argument>(type, "var");

	auto var1 = variablesManager->getVarByValue(llvmVal.get());
	variablesManager->reset();
	auto var2 = variablesManager->getVarByValue(llvmVal.get());

	ASSERT_TRUE(var1);
	ASSERT_TRUE(var2);
	ASSERT_NE(var1, var2);
}

TEST_F(VariablesManagerTests,
DifferentVariablesAreReturnedForIdenticalLLVMValueWithoutNameAfterReset) {
	auto type = llvm::Type::getInt32Ty(context);
	auto llvmVal = std::make_unique<llvm::Argument>(type);

	auto var1 = variablesManager->getVarByValue(llvmVal.get());
	variablesManager->reset();
	auto var2 = variablesManager->getVarByValue(llvmVal.get());

	ASSERT_TRUE(var1);
	ASSERT_TRUE(var2);
	ASSERT_NE(var1, var2);
}

TEST_F(VariablesManagerTests,
EmptyVarSetIsReturnedForNonEmptyVarsAfterReset) {
	auto type = llvm::Type::getInt32Ty(context);
	auto llvmVal1 = std::make_unique<llvm::Argument>(type, "var1");
	auto llvmVal2 = std::make_unique<llvm::Argument>(type, "var2");
	auto llvmVal3 = std::make_unique<llvm::Argument>(type, "var3");

	variablesManager->getVarByValue(llvmVal1.get());
	variablesManager->getVarByValue(llvmVal2.get());
	variablesManager->getVarByValue(llvmVal3.get());
	variablesManager->reset();

	ASSERT_TRUE(variablesManager->getLocalVars().empty());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
