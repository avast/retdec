/**
* @file tests/llvmir2hll/pattern/pattern_mock.h
* @brief A mock for the Pattern class.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_PATTERN_TESTS_PATTERN_MOCK_H
#define BACKEND_BIR_PATTERN_TESTS_PATTERN_MOCK_H

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/pattern/pattern.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for the Pattern class.
*/
class PatternMock: public Pattern {
public:
	MOCK_CONST_METHOD2(print, void (llvm::raw_ostream &os, const std::string &));
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
