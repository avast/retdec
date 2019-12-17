/**
 * @file tests/common/tool_info_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/tool_info.h"

using namespace ::testing;

namespace retdec {
namespace common {
namespace tests {

//
//=============================================================================
//  ToolInfoTests
//=============================================================================
//

class ToolInfoTests : public Test
{
	protected:
		ToolInfo tool;
};

//
// isMsvc()
//

TEST_F(ToolInfoTests, Test_isMsvc_WithNoParameter)
{
	tool.setName("msvc");
	EXPECT_EQ( true, tool.isMsvc() );

	tool.setName("not_microsoft");
	EXPECT_EQ( false, tool.isMsvc() );
}

TEST_F(ToolInfoTests, Test_isMsvc_WithParameter)
{
	tool.setName("MSVC");
	tool.setVersion("12.0");
	EXPECT_EQ( true, tool.isMsvc("12.0") );
	EXPECT_EQ( false, tool.isMsvc("13.0") );
}

//
//=============================================================================
//  ToolInfoContainerTests
//=============================================================================
//

class ToolInfoContainerTests : public Test
{
	public:
		ToolInfoContainerTests()
		{
			t1.setName("toool1");
			t1.setPercentage(25.0);
			tools.push_back(t1);

			t2.setName("toool2");
			tools.push_back(t2);

			t3.setName("toool3");
			t3.setPercentage(50.0);
			tools.push_back(t3);
		}

	protected:
		ToolInfo t1;
		ToolInfo t2;
		ToolInfo t3;
		ToolInfoContainer tools;
};

TEST_F(ToolInfoContainerTests, TestGetToolMostSignificant)
{
	// found
	auto* t = tools.getToolMostSignificant();
	ASSERT_TRUE(t != nullptr);
	EXPECT_EQ( t1, *t );

	// not found
	tools.clear();
	t = tools.getToolMostSignificant();
	ASSERT_TRUE(t == nullptr);
}

TEST_F(ToolInfoContainerTests, TestGetToolByName)
{
	// found
	auto* t = tools.getToolByName(t2.getName());
	ASSERT_TRUE(t != nullptr);
	EXPECT_EQ( t2, *t );

	// not found
	t = tools.getToolByName("non-existing-name");
	ASSERT_TRUE(t == nullptr);
}

TEST_F(ToolInfoContainerTests, TestGetToolWithMaxPercentage)
{
	// found
	auto* t = tools.getToolWithMaxPercentage();
	ASSERT_TRUE(t != nullptr);
	EXPECT_EQ( t3, *t );

	// if two equal, return first
	ToolInfo t4;
	t4.setName("tool4");
	t4.setPercentage(50.0);
	tools.push_back(t4);
	t = tools.getToolWithMaxPercentage();
	ASSERT_TRUE(t != nullptr);
	EXPECT_EQ( t3, *t );

	// not found
	tools.clear();
	t = tools.getToolWithMaxPercentage();
	ASSERT_TRUE(t == nullptr);
}

TEST_F(ToolInfoContainerTests, TestIsTool)
{
	EXPECT_EQ( true, tools.isTool("toool1") );
	EXPECT_EQ( false, tools.isTool("non_existing") );
}

TEST_F(ToolInfoContainerTests, TestisMsvc)
{
	EXPECT_EQ( false, tools.isMsvc() );

	ToolInfo t;
	t.setName("msvc");
	tools.push_back(t);
	EXPECT_EQ( true, t.isMsvc() );

	EXPECT_EQ( true, tools.isMsvc() );
}

} // namespace tests
} // namespace common
} // namespace retdec
