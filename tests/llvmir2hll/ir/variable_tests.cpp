/**
* @file tests/llvmir2hll/ir/variable_tests.cpp
* @brief Tests for the @c variable module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c variable module.
*/
class VariableTests: public Test {};

//
// create()
//

TEST_F(VariableTests,
CreateCreatedVariableIsNonNull) {
	ShPtr<Variable> var(Variable::create("a", IntType::create(32)));

	EXPECT_TRUE(var);
}

TEST_F(VariableTests,
CreateCreatedVariableIsInternalByDefault) {
	ShPtr<Variable> var(Variable::create("a", IntType::create(32)));

	EXPECT_TRUE(var->isInternal());
}

//
// copy()
//

TEST_F(VariableTests,
CopyCreatesExactCopyOfVariable) {
	ShPtr<Variable> var(Variable::create("a", IntType::create(32)));
	var->setName("b");
	var->markAsExternal();

	ShPtr<Variable> varCopy(var->copy());

	ASSERT_TRUE(varCopy);
	EXPECT_NE(var, varCopy);
	EXPECT_EQ(var->getInitialName(), varCopy->getInitialName());
	EXPECT_EQ(var->getName(), varCopy->getName());
	EXPECT_EQ(var->getType(), varCopy->getType());
	EXPECT_EQ(var->isInternal(), varCopy->isInternal());
	EXPECT_EQ(var->isExternal(), varCopy->isExternal());
}

//
// markAsInternal(), isInternal()
//

TEST_F(VariableTests,
IsInternalReturnsTrueIfVariableIsInternal) {
	ShPtr<Variable> var(Variable::create("a", IntType::create(32)));

	var->markAsInternal();

	EXPECT_TRUE(var->isInternal());
}

TEST_F(VariableTests,
IsInternalReturnsFalseIfVariableIsExternal) {
	ShPtr<Variable> var(Variable::create("a", IntType::create(32)));

	var->markAsExternal();

	EXPECT_FALSE(var->isInternal());
}

//
// markAsExternal(), isExternal()
//

TEST_F(VariableTests,
IsExternalReturnsTrueIfVariableIsExternal) {
	ShPtr<Variable> var(Variable::create("a", IntType::create(32)));

	var->markAsExternal();

	EXPECT_TRUE(var->isExternal());
}

TEST_F(VariableTests,
IsExternalReturnsFalseIfVariableIsInternal) {
	ShPtr<Variable> var(Variable::create("a", IntType::create(32)));

	var->markAsInternal();

	EXPECT_FALSE(var->isExternal());
}

//
// getInitialName()
//

TEST_F(VariableTests,
GetOrigNameOriginalNameBeforeRenameIsCorrectlyReturned) {
	ShPtr<Variable> var(Variable::create("original", IntType::create(32)));

	EXPECT_EQ("original", var->getName());
	EXPECT_EQ("original", var->getInitialName());
}

TEST_F(VariableTests,
GetOrigNameOriginalNameAfterRenameIsCorrectlyReturned) {
	ShPtr<Variable> var(Variable::create("original", IntType::create(32)));
	var->setName("new");

	EXPECT_EQ("new", var->getName());
	EXPECT_EQ("original", var->getInitialName());
}

//
// hasName()
//

TEST_F(VariableTests,
HasNameReturnsTrueIfVariableHasNonEmptyName) {
	auto var = Variable::create("a", IntType::create(32));

	ASSERT_TRUE(var->hasName());
}

TEST_F(VariableTests,
HasNameReturnsFalseIfVariableHasEmptyName) {
	auto var = Variable::create("", IntType::create(32));

	ASSERT_FALSE(var->hasName());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
