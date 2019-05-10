/**
* @file tests/bin2llvmir/providers/tests/lti_tests.cpp
* @brief Tests for the @c LtiProvider.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/void_type.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/utils/ctypes2llvm.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

//
//=============================================================================
//  LtiTests
//=============================================================================
//

/**
 * @brief Tests for the @c Lti.
 */
class LtiTests: public LlvmIrTests
{

};

//
//=============================================================================
//  LtiProviderTests
//=============================================================================
//

/**
 * @brief Tests for the @c LtiProviderTests.
 */
class LtiProviderTests: public LlvmIrTests
{

};

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
