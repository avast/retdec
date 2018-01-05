/**
* @file tests/bin2llvmir/optimizations/idioms_libgcc/tests/idioms_libgcc_tests.cpp
* @brief Tests for the @c IdiomsLibgcc pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/idioms_libgcc/idioms_libgcc.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

/**
 * Dummy function used to fill @c IdiomsLibgcc::Fnc2Action used in tests.
 */
void dummyFunction(llvm::CallInst* inst)
{

}

/**
 * This is *NOT* the same macro as in
 * @c frontend/bin2llvmirl/optimizations/idioms_libgcc/idioms_libgcc.cpp
 */
#define ID_FNC_PAIR(ID, FNC) \
		{ID, [] (llvm::CallInst* c) { return FNC(c); }}

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c Volatilize pass.
 */
class IdiomsLibgccTests: public LlvmIrTests
{

};

TEST_F(IdiomsLibgccTests, checkFunctionToActionMapEmptyContainerIsNotMisordered)
{
	IdiomsLibgcc::Fnc2Action f2a;

	EXPECT_FALSE(IdiomsLibgcc::checkFunctionToActionMap(f2a));
}

TEST_F(IdiomsLibgccTests, checkFunctionToActionMapDetectsMisorderedElements)
{
	IdiomsLibgcc::Fnc2Action f2a =
	{
			ID_FNC_PAIR("ab", dummyFunction),
			ID_FNC_PAIR("abcd", dummyFunction),
	};

	EXPECT_TRUE(IdiomsLibgcc::checkFunctionToActionMap(f2a));
}

TEST_F(IdiomsLibgccTests, checkFunctionToActionMapNotMisorderedElementPassTheTest)
{
	IdiomsLibgcc::Fnc2Action f2a =
	{
			ID_FNC_PAIR("abcd", dummyFunction),
			ID_FNC_PAIR("ab", dummyFunction),
	};

	EXPECT_FALSE(IdiomsLibgcc::checkFunctionToActionMap(f2a));
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
