/**
* @file tests/llvmir2hll/llvm/llvm_support_tests.cpp
* @brief Tests for the @c llvm_support module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/llvm/llvm_support.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c llvm_support module.
*/
class LLVMSupportTests: public Test {};

//
// isBasicBlockLabel()
//

TEST_F(LLVMSupportTests,
IsLLVMBasicBlockLabelIsLabel) {
	EXPECT_TRUE(LLVMSupport::isBasicBlockLabel(
		LLVMSupport::getBasicBlockLabelPrefix() + "8903087"));
	EXPECT_TRUE(LLVMSupport::isBasicBlockLabel(
		LLVMSupport::getBasicBlockLabelPrefix() + "8900368"));
	EXPECT_TRUE(LLVMSupport::isBasicBlockLabel(
		LLVMSupport::getBasicBlockLabelPrefix() + "4534"));
	EXPECT_TRUE(LLVMSupport::isBasicBlockLabel(
		LLVMSupport::getBasicBlockLabelPrefix() + "1"));
}

TEST_F(LLVMSupportTests,
IsLLVMBasicBlockLabelIsNotLabel) {
	EXPECT_FALSE(LLVMSupport::isBasicBlockLabel(
		""));
	EXPECT_FALSE(LLVMSupport::isBasicBlockLabel(
		LLVMSupport::getBasicBlockLabelPrefix()));
	EXPECT_FALSE(LLVMSupport::isBasicBlockLabel(
		"pc_8900368"));
	EXPECT_FALSE(LLVMSupport::isBasicBlockLabel(
		"dream away"));
	EXPECT_FALSE(LLVMSupport::isBasicBlockLabel(
		LLVMSupport::getBasicBlockLabelPrefix() + "fgxxx"));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
