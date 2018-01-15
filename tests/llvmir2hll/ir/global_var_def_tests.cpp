/**
* @file tests/llvmir2hll/ir/global_var_def_tests.cpp
* @brief Tests for the @c global_var_def module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c global_var_def module.
*/
class GlobalVarDefTests: public Test {};

//
// definesExternalVar()
//

TEST_F(GlobalVarDefTests,
DefinesExternalVarReturnsTrueIfGlobalVarIsExternal) {
	auto var = Variable::create("a", IntType::create(32));
	var->markAsExternal();
	auto varDef = GlobalVarDef::create(var);

	EXPECT_TRUE(varDef->definesExternalVar());
}

TEST_F(GlobalVarDefTests,
DefinesExternalVarReturnsFalseIfGlobalVarIsInternal) {
	auto var = Variable::create("a", IntType::create(32));
	var->markAsInternal();
	auto varDef = GlobalVarDef::create(var);

	EXPECT_FALSE(varDef->definesExternalVar());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
