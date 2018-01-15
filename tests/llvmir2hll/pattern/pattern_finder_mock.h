/**
* @file tests/llvmir2hll/pattern/pattern_finder_mock.h
* @brief A mock for the PatternFinder class.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_PATTERN_TESTS_PATTERN_FINDER_MOCK_H
#define BACKEND_BIR_PATTERN_TESTS_PATTERN_FINDER_MOCK_H

#include <string>

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/pattern/pattern_finder.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for the PatternFinder class.
*/
class PatternFinderMock: public PatternFinder {
public:
	PatternFinderMock(ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
		PatternFinder(va, cio) {}

	MOCK_CONST_METHOD0(getId, const std::string ());
	MOCK_METHOD1(findPatterns, PatternFinder::Patterns (ShPtr<Module>));
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
