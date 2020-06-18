/**
* @file tests/llvmir2hll/hll/output_managers/json_manager_tests.cpp
* @brief Implementation of class for tests of JSON output manager.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "llvmir2hll/hll/output_managers/output_manager_tests.h"
#include "retdec/llvmir2hll/hll/output_managers/json_manager.h"
#include "retdec/utils/string.h"

using namespace ::testing;

using retdec::utils::contains;

namespace retdec {
namespace llvmir2hll {
namespace tests {

class JsonOutputManagerTests: public OutputManagerTests
{
	protected:
		virtual void SetUp() override;

		std::string emitSingleToken();
};

void JsonOutputManagerTests::SetUp()
{
	OutputManagerTests::SetUp();
	manager = UPtr<OutputManager>(new JsonOutputManagerPlain(codeStream));
	manager->setCommentPrefix("//");
	manager->setOutputLanguage("C");
}

/**
 * When a single token is added to a manager, and then the code is emmited,
 * it contains an entire JSON contents.
 * This method strips the expected prefix and suffic and leaves only JSON
 * object representing a single token.
 * It makes token tests more readable.
 * If prefix/suffix removal fails, it returns an empty string.
 */
std::string JsonOutputManagerTests::emitSingleToken()
{
	std::string all = emitCode();

	std::string prefix = R"({"tokens":[{"addr":""},)";
	std::string suffix = R"(],"language":"C"})";

	if (!retdec::utils::startsWith(all, prefix))
	{
		return std::string();
	}

	if (!retdec::utils::endsWith(all, suffix))
	{
		return std::string();
	}

	auto tmp = all.erase(0, prefix.length());
	return tmp.erase(tmp.length() - suffix.length());
}

//
// tokens
//

TEST_F(JsonOutputManagerTests, token_newline)
{
	manager->newLine();
	EXPECT_EQ(R"({"kind":"nl","val":"\n"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_space_default)
{
	manager->space();
	EXPECT_EQ(R"({"kind":"ws","val":" "})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_space_space)
{
	manager->space("    ");
	EXPECT_EQ(R"({"kind":"ws","val":"    "})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_space_tab)
{
	manager->space("\t");
	EXPECT_EQ(R"({"kind":"ws","val":"\t"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_punctuation)
{
	manager->punctuation(';');
	EXPECT_EQ(R"({"kind":"punc","val":";"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_operatorX)
{
	manager->operatorX("++");
	EXPECT_EQ(R"({"kind":"op","val":"++"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_globalVariableId)
{
	manager->globalVariableId("var");
	EXPECT_EQ(R"({"kind":"i_gvar","val":"var"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_lovalVariableId)
{
	manager->localVariableId("var");
	EXPECT_EQ(R"({"kind":"i_lvar","val":"var"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_memberId)
{
	manager->memberId("mem");
	EXPECT_EQ(R"({"kind":"i_mem","val":"mem"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_labelId)
{
	manager->labelId("label");
	EXPECT_EQ(R"({"kind":"i_lab","val":"label"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_functionId)
{
	manager->functionId("func");
	EXPECT_EQ(R"({"kind":"i_fnc","val":"func"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_parameterId)
{
	manager->parameterId("arg");
	EXPECT_EQ(R"({"kind":"i_arg","val":"arg"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_keyword)
{
	manager->keyword("while");
	EXPECT_EQ(R"({"kind":"keyw","val":"while"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_dataType)
{
	manager->dataType("unsigned");
	EXPECT_EQ(R"({"kind":"type","val":"unsigned"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_preprocessor)
{
	manager->preprocessor("#define");
	EXPECT_EQ(R"({"kind":"preproc","val":"#define"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_include)
{
	manager->include("stdlib.h");
	EXPECT_EQ(R"({"kind":"inc","val":"<stdlib.h>"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_constantBool)
{
	manager->constantBool("true");
	EXPECT_EQ(R"({"kind":"l_bool","val":"true"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_constantInt)
{
	manager->constantInt("1234");
	EXPECT_EQ(R"({"kind":"l_int","val":"1234"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_constantFloat)
{
	manager->constantFloat("3.14");
	EXPECT_EQ(R"({"kind":"l_fp","val":"3.14"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_constantString)
{
	manager->constantString("\"hello world\"");
	EXPECT_EQ(
			"{\"kind\":\"l_str\",\"val\":\"\\\"hello world\\\"\"}",
			emitSingleToken()
	);
}

TEST_F(JsonOutputManagerTests, token_constantSymbol)
{
	manager->constantSymbol("UNKNOWN");
	EXPECT_EQ(R"({"kind":"l_sym","val":"UNKNOWN"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_constantPointer)
{
	manager->constantPointer("NULL");
	EXPECT_EQ(R"({"kind":"l_ptr","val":"NULL"})", emitSingleToken());
}

TEST_F(JsonOutputManagerTests, token_comment)
{
	manager->comment("hello world");
	EXPECT_EQ(R"({"kind":"cmnt","val":"// hello world"})", emitSingleToken());
}

//
// commentModifier()
//

TEST_F(JsonOutputManagerTests, commentModifier_creates_comment_until_end_of_line)
{
	manager->commentModifier();
	manager->localVariableId("hello");
	manager->space();
	manager->operatorX("=");
	manager->space();
	manager->constantInt("1234");
	manager->punctuation(';');
	manager->newLine();
	manager->functionId("f");

	EXPECT_EQ(
		R"({"kind":"cmnt","val":"// hello = 1234;"},{"kind":"nl","val":"\n"},{"kind":"i_fnc","val":"f"})",
		emitSingleToken());
}

//
// addressPush()
// addressPop()
//

TEST_F(JsonOutputManagerTests, address_push_and_pop_do_nothing)
{
	manager->addressPush(0x1000);
	manager->localVariableId("v1"); // addr "0x1000"
	manager->addressPush(Address::Undefined);
	manager->functionId("f"); // addr ""
	manager->addressPop();
	manager->localVariableId("v2"); // addr "0x1000"
	manager->addressPop();

	EXPECT_EQ(
		R"({"addr":"0x1000"},{"kind":"i_lvar","val":"v1"},{"addr":""},{"kind":"i_fnc","val":"f"},{"addr":"0x1000"},{"kind":"i_lvar","val":"v2"})",
		emitSingleToken());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec