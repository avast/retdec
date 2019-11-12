/**
 * @file tests/common/functions_tests.cpp
 * @brief Tests for the function module.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/function.h"

using namespace ::testing;

namespace retdec {
namespace common {
namespace tests {

//
//=============================================================================
//  FunctionContainerTests
//=============================================================================
//

class FunctionContainerTests : public Test
{
	public:
		FunctionContainerTests() :
			fnc1("fnc1"),
			fnc2("fnc2"),
			fnc3("fnc3"),
			fnc4("fnc4")
		{
			fnc1.setStart(0x1000);
			funcs.insert(fnc1);

			fnc2.setStart(0x2000);
			funcs.insert(fnc2);

			fnc3.setStart(0x3000);
			funcs.insert(fnc3);

			fnc4.setStart(0x4000);
			funcs.insert(fnc4);
		}

	protected:
		Function fnc1;
		Function fnc2;
		Function fnc3;
		Function fnc4;
		FunctionContainer funcs;
};

TEST_F(FunctionContainerTests, TestGetFunctionByName)
{
	// found
	auto* f = funcs.getFunctionByName(fnc3.getName());
	ASSERT_TRUE(f != nullptr);
	EXPECT_EQ( fnc3.getStart(), f->getStart() );

	// not found
	auto* n = funcs.getFunctionByName("non-existing-name");
	ASSERT_TRUE(n == nullptr);
}

TEST_F(FunctionContainerTests, TestGetFunctionByStartAddress)
{
	// found
	auto* f = funcs.getFunctionByStartAddress(fnc4.getStart());
	ASSERT_TRUE(f != nullptr);
	EXPECT_EQ( fnc4.getName(), f->getName() );

	// not found
	auto* n = funcs.getFunctionByStartAddress(0x1234);
	ASSERT_TRUE(n == nullptr);
}

} // namespace tests
} // namespace common
} // namespace retdec
