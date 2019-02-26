/**
 * @file tests/demangler/borland_ast_tests.cpp
 * @brief Tests for the borland ast representation.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <memory>
#include <gtest/gtest.h>

#include "llvm/Demangle/borland_ast_parser.h"
#include "llvm/Demangle/borland_ast_types.h"
#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/context.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace borland {
namespace tests {

class BorlandContextTests: public Test
{
public:
	BorlandContextTests() = default;

protected:
	Context context;
};

TEST_F(BorlandContextTests, IntegralTest)
{
	auto i1 = IntegralTypeNode::create(context, "int", false, {false, false});
	auto i2 = IntegralTypeNode::create(context, "int", false, {false, false});
	auto i3 = IntegralTypeNode::create(context, "int", true, {false, false});
	auto i4 = IntegralTypeNode::create(context, "int", false, {true, false});
	auto i5 = IntegralTypeNode::create(context, "int", false, {true, true});

	EXPECT_EQ(i1, i2);
	EXPECT_NE(i1, i3);
	EXPECT_NE(i1, i4);
	EXPECT_NE(i4, i5);
}

TEST_F(BorlandContextTests, PointerTests)
{
	auto i1 = IntegralTypeNode::create(context, "int", false, {false, false});
	auto i2 = IntegralTypeNode::create(context, "int", false, {false, false});

	auto p1 = PointerTypeNode::create(context, i1, {false, false});
	auto p2 = PointerTypeNode::create(context, i1, {false, false});
	auto p3 = PointerTypeNode::create(context, i2, {false, false});

	EXPECT_EQ(p1, p2);
	EXPECT_NE(p1, p3);

}

} // tests
} // borland
} // demangler
} // retdec/