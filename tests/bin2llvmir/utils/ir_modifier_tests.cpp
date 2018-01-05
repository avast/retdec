/**
* @file tests/bin2llvmir/utils/tests/ir_modifier_tests.cpp
* @brief Tests for the @c IrModifier utils module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c IrModifier module.
 */
class IrModifierTests: public LlvmIrTests
{

};

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
