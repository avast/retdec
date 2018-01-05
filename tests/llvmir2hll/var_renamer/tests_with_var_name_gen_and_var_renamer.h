/**
* @file tests/llvmir2hll/var_renamer/tests_with_var_name_gen_and_var_renamer.h
* @brief Support for tests using VarNameGen and VarRenamer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_VAR_RENAMER_TESTS_TESTS_WITH_VAR_NAME_GEN_AND_VAR_RENAMER_H
#define BACKEND_BIR_VAR_RENAMER_TESTS_TESTS_WITH_VAR_NAME_GEN_AND_VAR_RENAMER_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/var_name_gen/var_name_gen_mock.h"

/**
* @brief Instantiates VarNameGenMock, VarNameGen, and @c VarRenamerType by
*        using the mock and @c useDebugNames.
*
* This macro does the following:
*  (1) Instantiates VarNameGenMock (variable @c varNameGenMock) and VarNameGen
*      (variable @c varNameGen).
*  (2) Sets-up default actions for @c varNameGenMock (only @c getId() is set).
*  (3) Instantiates the given VarRenamer (variable @c varRenamer).
*
* Example of usage:
* @code
* TEST(TestExample, Test1) {
*     // Set-up the module.
*     // ...
*
*     INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(CustomVarRenamer, true);
*     // Set required default actions for the variable name generator.
*     // ...
*
*     // Rename the variables.
*     varRenamer->renameVars(module);
*
*     // Check the resulting module.
*     // ...
* }
* @endcode
*/
#define INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(VarRenamerType, useDebugNames) \
	/* (1) */ \
	::testing::NiceMock<VarNameGenMock> *varNameGenMock = \
		new ::testing::NiceMock<VarNameGenMock>(); \
	ShPtr<VarNameGen> varNameGen(varNameGenMock); \
	/* (2) */ \
	ON_CALL(*varNameGenMock, getId()) \
		.WillByDefault(::testing::Return(std::string("mock"))); \
	/* (3) */ \
	ShPtr<VarRenamer> varRenamer(VarRenamerType::create(varNameGen, useDebugNames))

#endif
