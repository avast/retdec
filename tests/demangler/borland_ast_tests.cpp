/**
 * @file tests/demangler/borland_ast_tests.cpp
 * @brief Tests for the borland ast representation.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <memory>
#include <gtest/gtest.h>

#include "llvm/Demangle/borland_ast_parser.h"
#include "llvm/Demangle/borland_ast_types.h"

#define AST_EQ(expected, ast) ast_eq(expected, ast.get())

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace borland {
namespace tests {

class BorlandAstTests: public Test
{
	public:
		BorlandAstTests() = default;

	protected:
		void ast_eq(const std::string &expected, Node *ast) {
			std::stringstream ss;
			ast->print(ss);
			EXPECT_EQ(expected, ss.str());
		}

		Context context;
};

TEST_F(BorlandAstTests,	NestedNameTest)
{
	auto foo = NameNode::create("foo");
	auto bar = NameNode::create("bar");
	auto foo_bar = NestedNameNode::create(
		std::move(foo),
		std::move(bar));
	AST_EQ("foo::bar", foo_bar);

	auto baz = NameNode::create("baz");
	auto foo_bar_baz = NestedNameNode::create(
		std::move(foo_bar),
		std::move(baz));
	AST_EQ("foo::bar::baz", foo_bar_baz);

	EXPECT_EQ(foo_bar_baz->kind(), Node::Kind::KNestedName);
}

TEST_F(BorlandAstTests, ParseNameTest)
{
	std::string mangled = "@Project1@mojaproc$q";
	std::string expected = "Project1::mojaproc()";

	BorlandASTParser parser = BorlandASTParser(context, mangled);
	auto ast = parser.ast();
	auto ast2 = parser.ast();
	std::string demangled = ast->str();
	ast2->str();

	EXPECT_EQ(demangled, expected);
}

TEST_F(BorlandAstTests, NodeArrayTest)
{
	auto i_arr = NodeArray::create();
	AST_EQ("", i_arr);
	i_arr->addNode(BuiltInTypeNode::create(context, "int", false, false));
	AST_EQ("int", i_arr);
	i_arr->addNode(BuiltInTypeNode::create(context, "bool", false, false));
	AST_EQ("int, bool", i_arr);
}

} // tests
} // borland
} // demangler
} // retdec/