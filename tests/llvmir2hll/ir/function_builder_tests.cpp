/**
* @file tests/llvmir2hll/ir/function_builder_tests.cpp
* @brief Tests for the @c function_builder module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c function_builder module.
*/
class FunctionBuilderTests: public Test {};

TEST_F(FunctionBuilderTests,
BuilderWithoutAdditionalSpecifiersBuildsDefaultFunctionDeclaration) {
	const std::string FUNC_NAME("test");
	ShPtr<Function> func(
		FunctionBuilder(FUNC_NAME)
			.build()
	);

	EXPECT_TRUE(func->isDeclaration()) <<
		"expected a declaration, " <<
		"but got a definition";
	EXPECT_TRUE(isa<VoidType>(func->getRetType())) <<
		"expected a void return type, " <<
		"but got `" << func->getRetType() << "`";
	EXPECT_EQ(FUNC_NAME, func->getName()) <<
		"expected an empty name, " <<
		"but got \"" << func->getName() << "\"";
	EXPECT_EQ(0, func->getNumOfParams());
}

TEST_F(FunctionBuilderTests,
BuilderWithoutFunctionNameBuildsFunctionWithEmptyName) {
	ShPtr<Function> func(
		FunctionBuilder()
			.build()
	);

	EXPECT_TRUE(func->getName().empty()) <<
		"expected an empty name, " <<
		"but got \"" << func->getName() << "\"";
}

TEST_F(FunctionBuilderTests,
BuilderWithNonEmptyFuncNameCreatesFunctionWithThatName) {
	const std::string FUNC_NAME("test");
	ShPtr<Function> func(
		FunctionBuilder(FUNC_NAME)
			.build()
	);

	EXPECT_EQ(FUNC_NAME, func->getName());
}

TEST_F(FunctionBuilderTests,
DefinitionWithEmptyBodySpecifierMakesFunctionDefinitionWithEmptyBody) {
	ShPtr<Function> func(
		FunctionBuilder()
			.definitionWithEmptyBody()
			.build()
	);

	EXPECT_TRUE(func->isDefinition()) <<
		"expected a definition, " <<
		"but got a declaration";
	EXPECT_TRUE(isa<EmptyStmt>(func->getBody())) <<
		"expected an empty body, " <<
		"but got `" << func->getBody() << "`";
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
DefinitionWithEmptyBodySpecifierChecksThatBuildHasNotBeenAlreadyCalled) {
	FunctionBuilder builder;
	builder.build();

	ASSERT_DEATH(builder.definitionWithEmptyBody(), ".*build.*already.*");
}
#endif

TEST_F(FunctionBuilderTests,
DefinitionWithBodySpecifierMakesFunctionDefinitionWithGivenBody) {
	ShPtr<ReturnStmt> FUNC_BODY(ReturnStmt::create());
	ShPtr<Function> func(
		FunctionBuilder()
			.definitionWithBody(FUNC_BODY)
			.build()
	);

	EXPECT_EQ(FUNC_BODY, func->getBody()) <<
		"expected `" << FUNC_BODY << "`, "<<
		"but got `" << func->getBody() << "`";
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
DefinitionWithBodySpecifierChecksThatBuildHasNotBeenAlreadyCalled) {
	FunctionBuilder builder;
	builder.build();

	ASSERT_DEATH(builder.definitionWithBody(ReturnStmt::create()),
		".*build.*already.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
DefinitionWithBodySpecifierWithNullBodyResultsIntoViolatedPrecondition) {
	FunctionBuilder builder;

	ASSERT_DEATH(builder.definitionWithBody(ShPtr<Statement>()),
		".*Precondition.*body.*");
}
#endif

TEST_F(FunctionBuilderTests,
WithRetTypeSpecifierMakesFunctionWithGivenReturnType) {
	ShPtr<IntType> FUNC_RET_TYPE(IntType::create(32));
	ShPtr<Function> func(
		FunctionBuilder()
			.withRetType(FUNC_RET_TYPE)
			.build()
	);

	EXPECT_EQ(FUNC_RET_TYPE, func->getRetType()) <<
		"expected `" << FUNC_RET_TYPE << "`, "<<
		"but got `" << func->getRetType() << "`";
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
WithRetTypeSpecifierChecksThatBuildHasNotBeenAlreadyCalled) {
	FunctionBuilder builder;
	builder.build();

	ASSERT_DEATH(builder.withRetType(IntType::create(32)),
		".*build.*already.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
WithRetTypeSpecifierWithNullRetTypeResultsIntoViolatedPrecondition) {
	FunctionBuilder builder;

	ASSERT_DEATH(builder.withRetType(ShPtr<Type>()),
		".*Precondition.*retType.*");
}
#endif

TEST_F(FunctionBuilderTests,
WithParamSpecifierMakesFunctionWithoutParametersToHaveGivenParameter) {
	ShPtr<Variable> FUNC_PARAM(Variable::create("p", IntType::create(32)));
	ShPtr<Function> func(
		FunctionBuilder()
			.withParam(FUNC_PARAM)
			.build()
	);

	ASSERT_EQ(1, func->getNumOfParams());
	EXPECT_EQ(FUNC_PARAM, func->getParam(1)) <<
		"expected `" << FUNC_PARAM << "`, "<<
		"but got `" << func->getParam(1) << "`";
}

TEST_F(FunctionBuilderTests,
WithParamSpecifierCalledForSecondTimeAppendsSecondParameter) {
	ShPtr<Variable> FUNC_PARAM1(Variable::create("p1", IntType::create(32)));
	ShPtr<Variable> FUNC_PARAM2(Variable::create("p2", IntType::create(32)));
	ShPtr<Function> func(
		FunctionBuilder()
			.withParam(FUNC_PARAM1)
			.withParam(FUNC_PARAM2)
			.build()
	);

	ASSERT_EQ(2, func->getNumOfParams());
	EXPECT_EQ(FUNC_PARAM1, func->getParam(1)) <<
		"expected `" << FUNC_PARAM1 << "`, "<<
		"but got `" << func->getParam(1) << "`";
	EXPECT_EQ(FUNC_PARAM2, func->getParam(2)) <<
		"expected `" << FUNC_PARAM2 << "`, "<<
		"but got `" << func->getParam(2) << "`";
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
WithParamSpecifierChecksThatBuildHasNotBeenAlreadyCalled) {
	FunctionBuilder builder;
	builder.build();

	ASSERT_DEATH(builder.withParam(Variable::create("p", IntType::create(32))),
		".*build.*already.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
WithParamSpecifierWithNullParamResultsIntoViolatedPrecondition) {
	FunctionBuilder builder;

	ASSERT_DEATH(builder.withParam(ShPtr<Variable>()),
		".*Precondition.*param.*");
}
#endif

TEST_F(FunctionBuilderTests,
WithLocalVarSpecifierMakesFunctionWithoutLocalVariablesHavingSingleLocalVariable) {
	ShPtr<Variable> FUNC_LOCAL_VAR(Variable::create("v", IntType::create(32)));
	ShPtr<Function> func(
		FunctionBuilder()
			.withLocalVar(FUNC_LOCAL_VAR)
			.build()
	);

	ASSERT_EQ(1, func->getNumOfLocalVars());
	VarSet expectedLocalVars;
	expectedLocalVars.insert(FUNC_LOCAL_VAR);
	EXPECT_EQ(expectedLocalVars, func->getLocalVars());
}

TEST_F(FunctionBuilderTests,
WithLocalVarSpecifierWhenCalledMultipleTimesAddsLocalVars) {
	ShPtr<Variable> FUNC_LOCAL_VAR1(Variable::create("v1", IntType::create(32)));
	ShPtr<Variable> FUNC_LOCAL_VAR2(Variable::create("v2", IntType::create(32)));
	ShPtr<Function> func(
		FunctionBuilder()
			.withLocalVar(FUNC_LOCAL_VAR1)
			.withLocalVar(FUNC_LOCAL_VAR2)
			.build()
	);

	ASSERT_EQ(2, func->getNumOfLocalVars());
	VarSet expectedLocalVars;
	expectedLocalVars.insert(FUNC_LOCAL_VAR1);
	expectedLocalVars.insert(FUNC_LOCAL_VAR2);
	EXPECT_EQ(expectedLocalVars, func->getLocalVars());
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
WithLocalVarSpecifierChecksThatBuildHasNotBeenAlreadyCalled) {
	FunctionBuilder builder;
	builder.build();

	ASSERT_DEATH(builder.withLocalVar(Variable::create("v", IntType::create(32))),
		".*build.*already.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
WithLocalVarSpecifierWithNullLocalVarResultsIntoViolatedPrecondition) {
	FunctionBuilder builder;

	ASSERT_DEATH(builder.withLocalVar(ShPtr<Variable>()),
		".*Precondition.*var.*");
}
#endif

TEST_F(FunctionBuilderTests,
WithVarArgSpecifierMakesFunctionWithVariableNumberOfArguments) {
	ShPtr<Function> func(
		FunctionBuilder()
			.withVarArg()
			.build()
	);

	EXPECT_TRUE(func->isVarArg()) <<
		"expected the function to take a variable number of arguments";
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
WithVarArgSpecifierChecksThatBuildHasNotBeenAlreadyCalled) {
	FunctionBuilder builder;
	builder.build();

	ASSERT_DEATH(builder.withVarArg(), ".*build.*already.*");
}
#endif

TEST_F(FunctionBuilderTests,
FuncReturnedFromBuildIsUnique) {
	FunctionBuilder builder;
	ShPtr<Function> func(builder.build());

	EXPECT_EQ(1, func.use_count());
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionBuilderTests,
BuilderIsInvalidatedAfterBuild) {
	FunctionBuilder builder;
	builder.build();

	ASSERT_DEATH(builder.build(), ".*build.*already.*");
}
#endif

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
