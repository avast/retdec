/**
 * @file tests/demangler/borland_ast_tests.cpp
 * @brief Tests for the borland ast representation.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <memory>
#include <gtest/gtest.h>

#include "retdec/demangler/borland_ast_parser.h"
#include "retdec/demangler/context.h"
#include "retdec/demangler/borland_ast/borland_ast.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace borland {
namespace tests {

class BorlandContextTests : public Test
{
public:
	BorlandContextTests(): context(), parser(context) {};

protected:
	Context context;
	borland::BorlandASTParser parser;
};

TEST_F(BorlandContextTests, BuiltInTest)
{
	auto b1 = BuiltInTypeNode::create(context, "void", {false, false});
	auto b2 = BuiltInTypeNode::create(context, "void", {false, false});
	auto b3 = BuiltInTypeNode::create(context, "void", {true, false});
	auto b4 = BuiltInTypeNode::create(context, "notVoid", {false, false});

	EXPECT_EQ(b1, b2);
	EXPECT_NE(b1, b3);
	EXPECT_NE(b1, b4);
	EXPECT_NE(b3, b4);
}

TEST_F(BorlandContextTests, CharTypeTests)
{
	auto c0 = CharTypeNode::create(context, ThreeStateSignedness::signed_char, {false, false});
	auto c1 = CharTypeNode::create(context, ThreeStateSignedness::signed_char, {false, false});
	auto c2 = CharTypeNode::create(context, ThreeStateSignedness::unsigned_char, {false, false});
	auto c3 = CharTypeNode::create(context, ThreeStateSignedness::no_prefix, {false, false});
	auto c4 = CharTypeNode::create(context, ThreeStateSignedness::signed_char, {true, false});
	auto c5 = CharTypeNode::create(context, ThreeStateSignedness::signed_char, {false, true});

	EXPECT_EQ(c0, c1);
	EXPECT_NE(c0, c2);
	EXPECT_NE(c0, c3);
	EXPECT_NE(c0, c4);
	EXPECT_NE(c0, c5);
}

TEST_F(BorlandContextTests, FloatTypeTets)
{
	auto f1 = FloatTypeNode::create(context, "float", {false, false});
	auto f2 = FloatTypeNode::create(context, "float", {false, false});
	auto f3 = FloatTypeNode::create(context, "double", {false, false});
	auto f4 = FloatTypeNode::create(context, "float", {true, false});
	auto f5 = FloatTypeNode::create(context, "float", {false, true});

	EXPECT_EQ(f1, f2);
	EXPECT_NE(f1, f3);
	EXPECT_NE(f1, f4);
	EXPECT_NE(f1, f5);
}

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
	auto i2 = IntegralTypeNode::create(context, "long", false, {false, false});

	auto p1 = PointerTypeNode::create(context, i1, {false, false});
	auto p2 = PointerTypeNode::create(context, i1, {false, false});
	auto p3 = PointerTypeNode::create(context, i2, {false, false});
	auto p4 = PointerTypeNode::create(context, i1, {true, false});
	auto p5 = PointerTypeNode::create(context, i1, {false, true});

	EXPECT_EQ(p1, p2);
	EXPECT_NE(p1, p3);
	EXPECT_NE(p1, p4);
	EXPECT_NE(p4, p5);
}

TEST_F(BorlandContextTests, ReferenceTests)
{
	auto i1 = IntegralTypeNode::create(context, "int", false, {false, false});
	auto i2 = IntegralTypeNode::create(context, "int", false, {false, true});

	auto r1 = ReferenceTypeNode::create(context, i1);
	auto r2 = ReferenceTypeNode::create(context, i1);
	auto r3 = ReferenceTypeNode::create(context, i2);

	EXPECT_EQ(r1, r2);
	EXPECT_NE(r1, r3);
}

TEST_F(BorlandContextTests, NameNodesTests)
{
	auto n1 = NameNode::create(context, "foo");
	auto n2 = NameNode::create(context, "foo");
	auto n3 = NameNode::create(context, "fo");

	EXPECT_EQ(n1, n2);
	EXPECT_NE(n1, n3);
}

TEST_F(BorlandContextTests, NestedNameNodesTests)
{
	auto name = NameNode::create(context, "foo");
	auto name2 = NameNode::create(context, "bar");

	auto nn1 = NestedNameNode::create(context, name, name);
	auto nn2 = NestedNameNode::create(context, name, name);
	auto nn3 = NestedNameNode::create(context, name, name2);

	EXPECT_EQ(nn1, nn2);
	EXPECT_NE(nn1, nn3);
}

TEST_F(BorlandContextTests, ArrayTests)
{
	auto i1 = IntegralTypeNode::create(context, "int", false, {false, false});
	auto i2 = IntegralTypeNode::create(context, "long", false, {false, false});

	auto a1 = ArrayNode::create(context, i1, 10, {false, false});
	auto a2 = ArrayNode::create(context, i1, 10, {false, false});
	auto a3 = ArrayNode::create(context, i2, 10, {false, false});

	EXPECT_EQ(a1, a2);
	EXPECT_NE(a1, a3);
}

TEST_F(BorlandContextTests, RReferenceTests)
{
	auto i1 = IntegralTypeNode::create(context, "int", false, {false, false});
	auto i2 = IntegralTypeNode::create(context, "int", false, {false, true});

	auto r1 = RReferenceTypeNode::create(context, i1);
	auto r2 = RReferenceTypeNode::create(context, i1);
	auto r3 = RReferenceTypeNode::create(context, i2);

	EXPECT_EQ(r1, r2);
	EXPECT_NE(r1, r3);
}

} // tests
} // borland
} // demangler
} // retdec/