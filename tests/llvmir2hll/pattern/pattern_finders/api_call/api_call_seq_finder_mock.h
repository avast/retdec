/**
* @file tests/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finder_mock.h
* @brief A mock for the APICallSeqFinder class.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_PATTERN_PATTERN_FINDERS_API_CALL_TESTS_API_CALL_SEQ_FINDER_MOCK_H
#define BACKEND_BIR_PATTERN_PATTERN_FINDERS_API_CALL_TESTS_API_CALL_SEQ_FINDER_MOCK_H

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finder.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for the APICallSeqFinder class.
*/
class APICallSeqFinderMock: public APICallSeqFinder {
public:
	APICallSeqFinderMock(ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
		PatternFinder(va, cio) {}

	MOCK_METHOD3(findPatterns, Patterns (const APICallInfoSeq &,
		ShPtr<CallExpr>, ShPtr<Statement>, ShPtr<Function>, ShPtr<Module>);
);

};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
