/**
* @file tests/llvmir2hll/hll/output_managers/plain_manager_tests.cpp
* @brief Implementation of class for tests of Plain output manager.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "llvmir2hll/hll/output_managers/output_manager_tests.h"
#include "retdec/llvmir2hll/hll/output_managers/plain_manager.h"
#include "retdec/utils/string.h"

using namespace ::testing;

using retdec::utils::contains;

namespace retdec {
namespace llvmir2hll {
namespace tests {

class PlainOutputManagerTests: public OutputManagerTests
{
	protected:
		virtual void SetUp() override;
};

void PlainOutputManagerTests::SetUp()
{
	OutputManagerTests::SetUp();
	manager = UPtr<OutputManager>(new PlainOutputManager(codeStream));
	manager->setCommentPrefix("//");
}

//
// tokens
//

TEST_F(PlainOutputManagerTests, token_newline)
{
	manager->newLine();
	EXPECT_EQ("\n", emitCode());
}

TEST_F(PlainOutputManagerTests, token_space_default)
{
	manager->space();
	EXPECT_EQ(" ", emitCode());
}

TEST_F(PlainOutputManagerTests, token_space_space)
{
	manager->space("    ");
	EXPECT_EQ("    ", emitCode());
}

TEST_F(PlainOutputManagerTests, token_space_tab)
{
	manager->space("\t");
	EXPECT_EQ("\t", emitCode());
}

TEST_F(PlainOutputManagerTests, token_punctuation)
{
	manager->punctuation(';');
	EXPECT_EQ(";", emitCode());
}

TEST_F(PlainOutputManagerTests, token_operatorX)
{
	manager->operatorX("++");
	EXPECT_EQ("++", emitCode());
}

TEST_F(PlainOutputManagerTests, token_globalVariableId)
{
	manager->globalVariableId("var");
	EXPECT_EQ("var", emitCode());
}

TEST_F(PlainOutputManagerTests, token_localVariableId)
{
	manager->localVariableId("var");
	EXPECT_EQ("var", emitCode());
}

TEST_F(PlainOutputManagerTests, token_memberId)
{
	manager->memberId("mem");
	EXPECT_EQ("mem", emitCode());
}

TEST_F(PlainOutputManagerTests, token_labelId)
{
	manager->labelId("label");
	EXPECT_EQ("label", emitCode());
}

TEST_F(PlainOutputManagerTests, token_functionId)
{
	manager->functionId("func");
	EXPECT_EQ("func", emitCode());
}

TEST_F(PlainOutputManagerTests, token_parameterId)
{
	manager->parameterId("arg");
	EXPECT_EQ("arg", emitCode());
}

TEST_F(PlainOutputManagerTests, token_keyword)
{
	manager->keyword("while");
	EXPECT_EQ("while", emitCode());
}

TEST_F(PlainOutputManagerTests, token_dataType)
{
	manager->dataType("unsigned");
	EXPECT_EQ("unsigned", emitCode());
}

TEST_F(PlainOutputManagerTests, token_preprocessor)
{
	manager->preprocessor("#define");
	EXPECT_EQ("#define", emitCode());
}

TEST_F(PlainOutputManagerTests, token_include)
{
	manager->include("stdlib.h");
	EXPECT_EQ("<stdlib.h>", emitCode());
}

TEST_F(PlainOutputManagerTests, token_constantBool)
{
	manager->constantBool("true");
	EXPECT_EQ("true", emitCode());
}

TEST_F(PlainOutputManagerTests, token_constantInt)
{
	manager->constantInt("1234");
	EXPECT_EQ("1234", emitCode());
}

TEST_F(PlainOutputManagerTests, token_constantFloat)
{
	manager->constantFloat("3.14");
	EXPECT_EQ("3.14", emitCode());
}

TEST_F(PlainOutputManagerTests, token_constantString)
{
	manager->constantString("\"hello world\"");
	EXPECT_EQ("\"hello world\"", emitCode());
}

TEST_F(PlainOutputManagerTests, token_constantSymbol)
{
	manager->constantSymbol("UNKNOWN");
	EXPECT_EQ("UNKNOWN", emitCode());
}

TEST_F(PlainOutputManagerTests, token_constantPointer)
{
	manager->constantPointer("NULL");
	EXPECT_EQ("NULL", emitCode());
}

TEST_F(PlainOutputManagerTests, token_comment)
{
	manager->comment("hello world");
	EXPECT_EQ("// hello world", emitCode());
}

//
// commentModifier()
//

TEST_F(PlainOutputManagerTests, commentModifier_creates_comment_until_end_of_line)
{
	manager->commentModifier();
	manager->localVariableId("hello");
	manager->space();
	manager->operatorX("=");
	manager->space();
	manager->constantInt("1234");
	manager->punctuation(';');
	manager->newLine();
	manager->functionId("ackermann");

	EXPECT_EQ("// hello = 1234;\nackermann", emitCode());
}

//
// addressPush()
// addressPop()
//

TEST_F(PlainOutputManagerTests, address_push_and_pop_do_nothing)
{
	manager->addressPush(0x1000);
	manager->localVariableId("hello");
	manager->addressPush(0x1234);
	manager->space();
	manager->operatorX("=");
	manager->space();
	manager->addressPop();
	manager->constantInt("1234");
	manager->punctuation(';');
	manager->addressPop();

	EXPECT_EQ("hello = 1234;", emitCode());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec