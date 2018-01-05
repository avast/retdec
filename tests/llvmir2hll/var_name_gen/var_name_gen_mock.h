/**
* @file tests/llvmir2hll/var_name_gen/var_name_gen_mock.h
* @brief A mock for the VarNameGen module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_VAR_NAME_GEN_TESTS_VAR_NAME_GEN_MOCK_H
#define BACKEND_BIR_VAR_NAME_GEN_TESTS_VAR_NAME_GEN_MOCK_H

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/var_name_gen/var_name_gen.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for the VarNameGen module.
*/
class VarNameGenMock: public VarNameGen {
public:
	MOCK_CONST_METHOD0(getId, std::string ());
	MOCK_METHOD0(restart, void ());
	MOCK_METHOD0(getNextVarName, std::string ());
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
