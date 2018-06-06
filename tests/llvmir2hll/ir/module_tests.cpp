/**
* @file tests/llvmir2hll/ir/module_tests.cpp
* @brief Tests for the @c module class.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <vector>

#include <gtest/gtest.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "llvmir2hll/config/config_mock.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "llvmir2hll/semantics/semantics_mock.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c module class.
*/
class ModuleTests: public Test {
protected:
	ModuleTests();

	ShPtr<Function> addFuncDecl(const std::string &name);
	ShPtr<Function> addFuncDef(const std::string &name);
	ShPtr<Variable> addGlobalVar(const std::string &name);

protected:
	/// Context for the LLVM module.
	// Implementation note: Do NOT use llvm::getGlobalContext() because that
	//                      would make the context same for all tests (we want
	//                      to run all tests in isolation).
	llvm::LLVMContext llvmContext;

	/// LLVM module.
	llvm::Module llvmModule;

	/// A mock for the used semantics.
	ShPtr<::testing::NiceMock<SemanticsMock>> semanticsMock;

	/// A mock for the used config.
	ShPtr<::testing::NiceMock<ConfigMock>> configMock;

	/// Module in our IR.
	ShPtr<Module> module;
};

/**
* @brief Constructs a new test fixture.
*/
ModuleTests::ModuleTests():
	llvmModule("testing module", llvmContext),
	semanticsMock(std::make_shared<NiceMock<SemanticsMock>>()),
	configMock(std::make_shared<NiceMock<ConfigMock>>()),
	module(std::make_shared<Module>(&llvmModule, llvmModule.getModuleIdentifier(),
		semanticsMock, configMock)) {}

/**
* @brief Adds a declaration of a function with the given name to the module.
*/
ShPtr<Function> ModuleTests::addFuncDecl(const std::string &name) {
	auto func = FunctionBuilder(name).build();
	module->addFunc(func);
	return func;
}

/**
* @brief Adds an empty definition of a function with the given name to the module.
*/
ShPtr<Function> ModuleTests::addFuncDef(const std::string &name) {
	auto func = FunctionBuilder(name)
		.definitionWithEmptyBody()
		.build();
	module->addFunc(func);
	return func;
}

/**
* @brief Adds a global variable with the given name to the module.
*/
ShPtr<Variable> ModuleTests::addGlobalVar(const std::string &name) {
	auto var = Variable::create(name, IntType::create(32));
	module->addGlobalVar(var);
	return var;
}

//
// func_begin(), func_end()
//

TEST_F(ModuleTests,
IterationOverFunctionsIteratesOverBothDeclarationsAndDefinitions) {
	addFuncDecl("decl1");
	addFuncDef("def");
	addFuncDecl("decl2");

	std::vector<ShPtr<Function>> funcs(
		module->func_begin(),
		module->func_end()
	);

	ASSERT_EQ(3, funcs.size());
}

//
// func_definition_begin(), func_definition_end()
//

TEST_F(ModuleTests,
IterationOverFunctionDefinitionsIteratesOnlyOverDefinitions) {
	addFuncDecl("decl1");
	addFuncDef("def");
	addFuncDecl("decl2");

	std::vector<ShPtr<Function>> funcs(
		module->func_definition_begin(),
		module->func_definition_end()
	);

	ASSERT_EQ(1, funcs.size());
}

//
// func_declaration_begin(), func_declaration_end()
//

TEST_F(ModuleTests,
IterationOverFunctionDeclarationsIteratesOnlyOverDeclarations) {
	addFuncDecl("decl1");
	addFuncDef("def");
	addFuncDecl("decl2");

	std::vector<ShPtr<Function>> funcs(
		module->func_declaration_begin(),
		module->func_declaration_end()
	);

	ASSERT_EQ(2, funcs.size());
}

//
// isGlobalVarStoringStringLiteral()
//

TEST_F(ModuleTests,
IsGlobalVarStoringStringLiteralReturnsCorrectResult) {
	EXPECT_CALL(*configMock, isGlobalVarStoringWideString("g"))
		.WillOnce(Return(true));

	ASSERT_TRUE(module->isGlobalVarStoringStringLiteral("g"));
}

//
// getExternalGlobalVars()
//

TEST_F(ModuleTests,
GetExternalGlobalVarsReturnsExternalGlobalVars) {
	// var1: external
	auto var1 = Variable::create("a", IntType::create(32));
	var1->markAsExternal();
	module->addGlobalVar(var1);
	// var2: internal
	auto var2 = Variable::create("b", IntType::create(32));
	var2->markAsInternal();
	module->addGlobalVar(var2);

	const auto &externalGlobalVars = module->getExternalGlobalVars();

	// The only external variable is var1.
	EXPECT_EQ(externalGlobalVars.size(), 1);
	EXPECT_EQ(*externalGlobalVars.begin(), var1) <<
		"expected `" << var1 << "`, " <<
		"got `" << *externalGlobalVars.begin() << "`";
}

//
// getRegisterForGlobalVar()
//

TEST_F(ModuleTests,
GetRegisterForGlobalVarReturnsCorrectValue) {
	auto var = addGlobalVar("g");
	EXPECT_CALL(*configMock, getRegisterForGlobalVar("g"))
		.WillOnce(Return("ebx"));

	ASSERT_EQ("ebx", module->getRegisterForGlobalVar(var));
}

//
// getDetectedCryptoPatternForGlobalVar()
//

TEST_F(ModuleTests,
GetDetectedCryptoPatternForGlobalVarReturnsCorrectValue) {
	auto var = addGlobalVar("g");
	EXPECT_CALL(*configMock, getDetectedCryptoPatternForGlobalVar("g"))
		.WillOnce(Return("CRC32"));

	ASSERT_EQ("CRC32", module->getDetectedCryptoPatternForGlobalVar(var));
}

//
// hasGlobalVar()
//

TEST_F(ModuleTests,
HasGlobalVarReturnsTrueWhenGlobalVarExists) {
	module->addGlobalVar(Variable::create("g", IntType::create(32)));

	ASSERT_TRUE(module->hasGlobalVar("g"));
}

TEST_F(ModuleTests,
HasGlobalVarReturnsFalseWhenGlobalVarDoesNotExist) {
	module->addGlobalVar(Variable::create("g", IntType::create(32)));

	ASSERT_FALSE(module->hasGlobalVar("nonexisting"));
}

//
// correspondsToFunc()
//

TEST_F(ModuleTests,
CorrespondsToFuncReturnsFalseWhenThereIsNoFuncWithVarName) {
	auto var = Variable::create("my_func", IntType::create(32));

	ASSERT_FALSE(module->correspondsToFunc(var));
}

TEST_F(ModuleTests,
CorrespondsToFuncReturnsFalseWhenVarHasOnlySameNameAsFuncButDoesNotComeFromFunc) {
	auto myFunc = addFuncDecl("my_func");
	auto var = Variable::create("my_func", IntType::create(32));

	ASSERT_FALSE(module->correspondsToFunc(var));
}

TEST_F(ModuleTests,
CorrespondsToFuncReturnsTrueWhenVarHasSameNameAsFuncAndComesFromIt) {
	auto myFunc = addFuncDecl("my_func");

	ASSERT_TRUE(module->correspondsToFunc(myFunc->getAsVar()));
}

//
// hasUserDefinedFuncs()
//

TEST_F(ModuleTests,
HasUserDefinedFuncsReturnsFalseWhenThereAreNoFuncs) {
	ASSERT_FALSE(module->hasUserDefinedFuncs());
}

TEST_F(ModuleTests,
HasUserDefinedFuncsReturnsTrueWhenThereIsDeclarationOfUserDefinedFunc) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, isUserDefinedFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_TRUE(module->hasUserDefinedFuncs());
}

TEST_F(ModuleTests,
HasUserDefinedFuncsReturnsTrueWhenThereIsDefinitionOfUserDefinedFunc) {
	auto myFunc = addFuncDef("my_func");
	EXPECT_CALL(*configMock, isUserDefinedFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_TRUE(module->hasUserDefinedFuncs());
}

//
// getUserDefinedFuncs()
//

TEST_F(ModuleTests,
GetUserDefinedFuncsReturnsEmptySetWhenThereAreNoFuncs) {
	ASSERT_EQ(FuncSet(), module->getUserDefinedFuncs());
}

TEST_F(ModuleTests,
GetUserDefinedFuncsReturnsCorrectValueWhenThereAreUserDefinedFunc) {
	// Check that both declarations and definitions are checked.
	auto myFunc1 = addFuncDecl("my_func1");
	EXPECT_CALL(*configMock, isUserDefinedFunc(myFunc1->getName()))
		.WillOnce(Return(true));
	auto myFunc2 = addFuncDef("my_func2");
	EXPECT_CALL(*configMock, isUserDefinedFunc(myFunc2->getName()))
		.WillOnce(Return(true));

	ASSERT_EQ(FuncSet({myFunc1, myFunc2}), module->getUserDefinedFuncs());
}

//
// hasStaticallyLinkedFuncs()
//

TEST_F(ModuleTests,
HasStaticallyLinkedFuncsReturnsFalseWhenThereAreNoFuncs) {
	ASSERT_FALSE(module->hasStaticallyLinkedFuncs());
}

TEST_F(ModuleTests,
HasStaticallyLinkedFuncsReturnsTrueWhenThereIsStaticallyLinkedFunc) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, isStaticallyLinkedFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_TRUE(module->hasStaticallyLinkedFuncs());
}

//
// markFuncAsStaticallyLinked()
//

TEST_F(ModuleTests,
MarkFuncAsStaticallyLinkedMarksFunctionAsStaticallyLinked) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, markFuncAsStaticallyLinked(myFunc->getName()));

	module->markFuncAsStaticallyLinked(myFunc);
}

//
// getStaticallyLinkedFuncs()
//

TEST_F(ModuleTests,
GetStaticallyLinkedFuncsReturnsEmptySetWhenThereAreNoFuncs) {
	ASSERT_EQ(FuncSet(), module->getStaticallyLinkedFuncs());
}

TEST_F(ModuleTests,
GetStaticallyLinkedFuncsReturnsCorrectValueWhenThereIsStaticallyLinkedFunc) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, isStaticallyLinkedFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_EQ(FuncSet({myFunc}), module->getStaticallyLinkedFuncs());
}

//
// hasDynamicallyLinkedFuncs()
//

TEST_F(ModuleTests,
HasDynamicallyLinkedFuncsReturnsFalseWhenThereAreNoFuncs) {
	ASSERT_FALSE(module->hasDynamicallyLinkedFuncs());
}

TEST_F(ModuleTests,
HasDynamicallyLinkedFuncsReturnsTrueWhenThereIsDynamicallyLinkedFunc) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, isDynamicallyLinkedFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_TRUE(module->hasDynamicallyLinkedFuncs());
}

//
// hasSyscallFuncs()
//

TEST_F(ModuleTests,
HasSyscallFuncsReturnsFalseWhenThereAreNoFuncs) {
	ASSERT_FALSE(module->hasSyscallFuncs());
}

TEST_F(ModuleTests,
HasSyscallFuncsReturnsTrueWhenThereIsSyscallFunc) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, isSyscallFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_TRUE(module->hasSyscallFuncs());
}

//
// hasInstructionIdiomFuncs()
//

TEST_F(ModuleTests,
HasInstructionIdiomFuncsReturnsFalseWhenThereAreNoFuncs) {
	ASSERT_FALSE(module->hasInstructionIdiomFuncs());
}

TEST_F(ModuleTests,
HasInstructionIdiomFuncsReturnsTrueWhenThereIsInstructionIdiomFunc) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, isInstructionIdiomFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_TRUE(module->hasInstructionIdiomFuncs());
}

//
// isExportedFunc()
//

TEST_F(ModuleTests,
IsExportedFuncReturnsCorrectValue) {
	auto myFunc = addFuncDef("my_func");
	EXPECT_CALL(*configMock, isExportedFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_TRUE(module->isExportedFunc(myFunc));
}

//
// getDynamicallyLinkedFuncs()
//

TEST_F(ModuleTests,
GetDynamicallyLinkedFuncsReturnsEmptySetWhenThereAreNoFuncs) {
	ASSERT_EQ(FuncSet(), module->getDynamicallyLinkedFuncs());
}

TEST_F(ModuleTests,
GetDynamicallyLinkedFuncsReturnsCorrectValueWhenThereIsDynamicallyLinkedFunc) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, isDynamicallyLinkedFunc(myFunc->getName()))
		.WillOnce(Return(true));

	ASSERT_EQ(FuncSet({myFunc}), module->getDynamicallyLinkedFuncs());
}

//
// getRealNameForFunc()
//

TEST_F(ModuleTests,
GetRealNameForFuncReturnsCorrectValue) {
	auto REAL_NAME = "myFunc"s;
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getRealNameForFunc("my_func"))
		.WillOnce(Return(REAL_NAME));

	ASSERT_EQ(REAL_NAME, module->getRealNameForFunc(myFunc));
}

//
// getDeclarationStringForFunc()
//

TEST_F(ModuleTests,
GetDeclarationStringForFuncReturnsCorrectValue) {
	auto MY_FUNC_DECLARATION_STRING = "int my_func();"s;
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getDeclarationStringForFunc("my_func"))
		.WillOnce(Return(MY_FUNC_DECLARATION_STRING));

	ASSERT_EQ(
		MY_FUNC_DECLARATION_STRING,
		module->getDeclarationStringForFunc(myFunc)
	);
}

//
// getCommentForFunc()
//

TEST_F(ModuleTests,
GetCommentForFuncReturnsCorrectValue) {
	auto COMMENT = "comment"s;
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getCommentForFunc("my_func"))
		.WillOnce(Return(COMMENT));

	ASSERT_EQ(COMMENT, module->getCommentForFunc(myFunc));
}

//
// getDetectedCryptoPatternsForFunc()
//

TEST_F(ModuleTests,
GetDetectedCryptoPatternsForFuncReturnsCorrectValue) {
	StringSet PATTERNS{"CRC32"};
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getDetectedCryptoPatternsForFunc("my_func"))
		.WillOnce(Return(PATTERNS));

	ASSERT_EQ(PATTERNS, module->getDetectedCryptoPatternsForFunc(myFunc));
}

//
// getWrappedFuncName()
//

TEST_F(ModuleTests,
GetWrappedFuncNameReturnsCorrectValue) {
	auto WRAPPED_FUNC_NAME = "another_func"s;
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getWrappedFunc("my_func"))
		.WillOnce(Return(WRAPPED_FUNC_NAME));

	ASSERT_EQ(WRAPPED_FUNC_NAME, module->getWrappedFuncName(myFunc));
}

//
// getDemangledNameOfFunc()
//

TEST_F(ModuleTests,
GetDemangledNameOfFuncReturnsCorrectValue) {
	auto DEMANGLED_NAME = "demangled_my_func"s;
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getDemangledNameOfFunc("my_func"))
		.WillOnce(Return(DEMANGLED_NAME));

	ASSERT_EQ(DEMANGLED_NAME, module->getDemangledNameOfFunc(myFunc));
}

//
// getNamesOfFuncsFixedWithLLVMIRFixer()
//

TEST_F(ModuleTests,
GetNamesOfFuncsFixedWithLLVMIRFixerReturnsCorrectValue) {
	auto FIXED_FUNCS = StringSet({"func1", "func2"});
	EXPECT_CALL(*configMock, getFuncsFixedWithLLVMIRFixer())
		.WillOnce(Return(FIXED_FUNCS));

	ASSERT_EQ(FIXED_FUNCS, module->getNamesOfFuncsFixedWithLLVMIRFixer());
}

//
// getAddressRangeForFunc()
//

TEST_F(ModuleTests,
GetAddressRangeForFuncReturnsCorrectValue) {
	auto myFunc = addFuncDecl("my_func");
	auto ADDRESS_RANGE = AddressRange(0, 20);
	EXPECT_CALL(*configMock, getAddressRangeForFunc(myFunc->getName()))
		.WillOnce(Return(ADDRESS_RANGE));

	ASSERT_EQ(ADDRESS_RANGE, module->getAddressRangeForFunc(myFunc));
}

//
// hasAddressRange()
//

TEST_F(ModuleTests,
HasAddressRangeReturnsFalseWhenFuncHasNoAddressRange) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getAddressRangeForFunc(myFunc->getName()))
		.WillOnce(Return(NO_ADDRESS_RANGE));

	ASSERT_FALSE(module->hasAddressRange(myFunc));
}

TEST_F(ModuleTests,
HasAddressRangeReturnsTrueWhenFuncHasAddressRange) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getAddressRangeForFunc(myFunc->getName()))
		.WillOnce(Return(AddressRange(0, 20)));

	ASSERT_TRUE(module->hasAddressRange(myFunc));
}

//
// allFuncDefinitionsHaveAddressRange()
//

TEST_F(ModuleTests,
AllFuncDefinitionsHaveAddressRangeReturnsFalseWhenNotAllFuncDefinitionsHaveAddressRange) {
	auto myFunc = addFuncDef("my_func");
	EXPECT_CALL(*configMock, getAddressRangeForFunc(myFunc->getName()))
		.WillOnce(Return(NO_ADDRESS_RANGE));

	ASSERT_FALSE(module->allFuncDefinitionsHaveAddressRange());
}

TEST_F(ModuleTests,
AllFuncDefinitionsHaveAddressRangeReturnsTrueWhenAllFuncDefinitionsHaveAddressRange) {
	auto myFunc = addFuncDef("my_func");
	EXPECT_CALL(*configMock, getAddressRangeForFunc(myFunc->getName()))
		.WillOnce(Return(AddressRange(0, 20)));

	ASSERT_TRUE(module->allFuncDefinitionsHaveAddressRange());
}

//
// getLineRangeForFunc()
//

TEST_F(ModuleTests,
GetLineRangeForFuncReturnsCorrectValue) {
	auto myFunc = addFuncDecl("my_func");
	auto LINE_RANGE = LineRange(0, 20);
	EXPECT_CALL(*configMock, getLineRangeForFunc(myFunc->getName()))
		.WillOnce(Return(LINE_RANGE));

	ASSERT_EQ(LINE_RANGE, module->getLineRangeForFunc(myFunc));
}

//
// hasLineRange()
//

TEST_F(ModuleTests,
HasLineRangeReturnsFalseWhenFuncHasNoLineRange) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getLineRangeForFunc(myFunc->getName()))
		.WillOnce(Return(NO_LINE_RANGE));

	ASSERT_FALSE(module->hasLineRange(myFunc));
}

TEST_F(ModuleTests,
HasLineRangeReturnsTrueWhenFuncHasLineRange) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, getLineRangeForFunc(myFunc->getName()))
		.WillOnce(Return(LineRange(0, 20)));

	ASSERT_TRUE(module->hasLineRange(myFunc));
}

//
// allFuncDefinitionsHaveLineRange()
//

TEST_F(ModuleTests,
AllFuncDefinitionsHaveLineRangeReturnsFalseWhenNotAllFuncDefinitionsHaveLineRange) {
	auto myFunc = addFuncDef("my_func");
	EXPECT_CALL(*configMock, getLineRangeForFunc(myFunc->getName()))
		.WillOnce(Return(NO_LINE_RANGE));

	ASSERT_FALSE(module->allFuncDefinitionsHaveLineRange());
}

TEST_F(ModuleTests,
AllFuncDefinitionsHaveLineRangeReturnsTrueWhenAllFuncDefinitionsHaveLineRange) {
	auto myFunc = addFuncDef("my_func");
	EXPECT_CALL(*configMock, getLineRangeForFunc(myFunc->getName()))
		.WillOnce(Return(LineRange(0, 20)));

	ASSERT_TRUE(module->allFuncDefinitionsHaveLineRange());
}

//
// comesFromGlobalVar()
//

TEST_F(ModuleTests,
ComesFromGlobalVarReturnsCorrectValue) {
	auto myFunc = addFuncDef("my_func");
	auto varG = Variable::create("g_global_to_local", IntType::create(32));
	myFunc->addLocalVar(varG);
	std::string GLOBAL_VAR_NAME("g");
	EXPECT_CALL(*configMock, comesFromGlobalVar(myFunc->getName(), varG->getName()))
		.WillOnce(Return(GLOBAL_VAR_NAME));

	ASSERT_EQ(GLOBAL_VAR_NAME, module->comesFromGlobalVar(myFunc, varG));
}

//
// hasClasses()
//

TEST_F(ModuleTests,
HasClassesReturnsFalseWhenThereAreNoClasses) {
	EXPECT_CALL(*configMock, getClassNames())
		.WillOnce(Return(StringSet()));

	ASSERT_FALSE(module->hasClasses());
}

TEST_F(ModuleTests,
HasClassesReturnsTrueWhenAtLeastOneClassWasFound) {
	EXPECT_CALL(*configMock, getClassNames())
		.WillOnce(Return(StringSet{"A"}));

	ASSERT_TRUE(module->hasClasses());
}

//
// getClassNames()
//

TEST_F(ModuleTests,
GetClassNamesReturnsCorrectValue) {
	StringSet CLASS_NAMES{"A", "B"};
	EXPECT_CALL(*configMock, getClassNames())
		.WillOnce(Return(CLASS_NAMES));

	ASSERT_EQ(CLASS_NAMES, module->getClassNames());
}

//
// getClassForFunc()
//

TEST_F(ModuleTests,
GetClassForFuncReturnsCorrectValue) {
	auto myFunc = addFuncDef("my_func");
	std::string CLASS("A");
	EXPECT_CALL(*configMock, getClassForFunc(myFunc->getName()))
		.WillOnce(Return(CLASS));

	ASSERT_EQ(CLASS, module->getClassForFunc(myFunc));
}

//
// getTypeOfFuncInClass()
//

TEST_F(ModuleTests,
GetTypeOfFuncInClassReturnsCorrectValue) {
	auto myFunc = addFuncDef("my_func");
	std::string TYPE("constructor");
	EXPECT_CALL(*configMock, getTypeOfFuncInClass(myFunc->getName(), "A"))
		.WillOnce(Return(TYPE));

	ASSERT_EQ(TYPE, module->getTypeOfFuncInClass(myFunc, "A"));
}

//
// getBaseClassNames()
//

TEST_F(ModuleTests,
GetBaseClassNamesReturnsCorrectValue) {
	StringVector BASE_CLASS_NAMES{"A", "B"};
	EXPECT_CALL(*configMock, getBaseClassNames("C"))
		.WillOnce(Return(BASE_CLASS_NAMES));

	ASSERT_EQ(BASE_CLASS_NAMES, module->getBaseClassNames("C"));
}

//
// getDemangledNameOfClass()
//

TEST_F(ModuleTests,
GetDemangledNameOfClassReturnsCorrectValue) {
	std::string DEMANGLED_NAME("DemangledA");
	EXPECT_CALL(*configMock, getDemangledNameOfClass("A"))
		.WillOnce(Return(DEMANGLED_NAME));

	ASSERT_EQ(DEMANGLED_NAME, module->getDemangledNameOfClass("A"));
}

//
// isDebugInfoAvailable()
//

TEST_F(ModuleTests,
IsDebugInfoAvailableReturnsCorrectValue) {
	auto myFunc = addFuncDecl("my_func");
	EXPECT_CALL(*configMock, isDebugInfoAvailable())
		.WillOnce(Return(true));

	ASSERT_TRUE(module->isDebugInfoAvailable());
}

//
// getDebugModuleNameForFunc()
//

TEST_F(ModuleTests,
GetDebugModuleNameForFuncReturnsCorrectValue) {
	auto myFunc = addFuncDecl("my_func");
	auto MODULE_NAME = "module.c"s;
	EXPECT_CALL(*configMock, getDebugModuleNameForFunc(myFunc->getName()))
		.WillOnce(Return(MODULE_NAME));

	ASSERT_EQ(MODULE_NAME, module->getDebugModuleNameForFunc(myFunc));
}

//
// getDebugModuleNames()
//

TEST_F(ModuleTests,
GetDebugModuleNamesReturnsCorrectValue) {
	auto MODULE_NAMES = StringSet({"module1.c", "module2.c"});
	EXPECT_CALL(*configMock, getDebugModuleNames())
		.WillOnce(Return(MODULE_NAMES));

	ASSERT_EQ(MODULE_NAMES, module->getDebugModuleNames());
}

//
// getDebugNameForGlobalVar()
//

TEST_F(ModuleTests,
GetDebugNameForGlobalVarReturnsCorrectValue) {
	auto varG = Variable::create("orig_g", IntType::create(32));
	auto DEBUG_NAME = "g";
	EXPECT_CALL(*configMock, getDebugNameForGlobalVar("orig_g"))
		.WillOnce(Return(DEBUG_NAME));

	ASSERT_EQ(DEBUG_NAME, module->getDebugNameForGlobalVar(varG));
}

//
// getDebugNameForLocalVar()
//

TEST_F(ModuleTests,
GetDebugNameForLocalVarReturnsCorrectValue) {
	auto varV = Variable::create("orig_v", IntType::create(32));
	auto myFunc = addFuncDef("my_func");
	myFunc->addLocalVar(varV);
	auto DEBUG_NAME = "v";
	EXPECT_CALL(*configMock, getDebugNameForLocalVar("my_func", "orig_v"))
		.WillOnce(Return(DEBUG_NAME));

	ASSERT_EQ(DEBUG_NAME, module->getDebugNameForLocalVar(myFunc, varV));
}

//
// getFrontendRelease()
//

TEST_F(ModuleTests,
GetFrontendReleaseReturnsCorrectValue) {
	auto FRONTEND_RELEASE = "v1.0"s;
	EXPECT_CALL(*configMock, getFrontendRelease())
		.WillOnce(Return(FRONTEND_RELEASE));

	ASSERT_EQ(FRONTEND_RELEASE, module->getFrontendRelease());
}

//
// getNumberOfFuncsDetectedInFrontend()
//

TEST_F(ModuleTests,
GetNumberOfFuncsDetectedInFrontendReturnsCorrectValue) {
	auto FRONTEND_FUNC_COUNT = 123;
	EXPECT_CALL(*configMock, getNumberOfFuncsDetectedInFrontend())
		.WillOnce(Return(FRONTEND_FUNC_COUNT));

	ASSERT_EQ(FRONTEND_FUNC_COUNT, module->getNumberOfFuncsDetectedInFrontend());
}

//
// getDetectedCompilerOrPacker()
//

TEST_F(ModuleTests,
GetDetectedCompilerOrPackerReturnsCorrectValue) {
	auto DETECTED_COMPILER = "gcc"s;
	EXPECT_CALL(*configMock, getDetectedCompilerOrPacker())
		.WillOnce(Return(DETECTED_COMPILER));

	ASSERT_EQ(DETECTED_COMPILER, module->getDetectedCompilerOrPacker());
}

//
// getDetectedLanguage()
//

TEST_F(ModuleTests,
GetDetectedLanguageReturnsCorrectValue) {
	auto DETECTED_LANGUAGE = "C"s;
	EXPECT_CALL(*configMock, getDetectedLanguage())
		.WillOnce(Return(DETECTED_LANGUAGE));

	ASSERT_EQ(DETECTED_LANGUAGE, module->getDetectedLanguage());
}

//
// getSelectedButNotFoundFuncs()
//

TEST_F(ModuleTests,
GetSelectedButNotFoundFuncsReturnsCorrectValue) {
	auto SELECTED_BUT_NOT_FOUND_FUNCS = StringSet({"func1", "func2"});
	EXPECT_CALL(*configMock, getSelectedButNotFoundFuncs())
		.WillOnce(Return(SELECTED_BUT_NOT_FOUND_FUNCS));

	ASSERT_EQ(SELECTED_BUT_NOT_FOUND_FUNCS, module->getSelectedButNotFoundFuncs());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
