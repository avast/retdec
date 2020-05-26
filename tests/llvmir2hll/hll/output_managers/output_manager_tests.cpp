/**
* @file tests/llvmir2hll/hll/output_managers/output_manager_tests.cpp
* @brief Implementation of the base class for tests of output managers.
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

OutputManagerTests::OutputManagerTests() :
		codeStream(code)
{

}

void OutputManagerTests::SetUp()
{
	// By default, use PlainOutputManager to test functionality that is shared
	// between output managers.
	manager = UPtr<OutputManager>(new PlainOutputManager(codeStream));
}

std::string OutputManagerTests::emitCode()
{
	manager->finalize();
	return codeStream.str();
}

//
// comment prefix
//

TEST_F(OutputManagerTests, uninited_comment_prefix_is_empty)
{
	EXPECT_EQ("", manager->getCommentPrefix());
}

TEST_F(OutputManagerTests, init_comment_prefix)
{
	std::string prefix = "//";

	manager->setCommentPrefix(prefix);

	EXPECT_EQ(prefix, manager->getCommentPrefix());
}

//
// output language
//

TEST_F(OutputManagerTests, uninited_language_is_empty)
{
	EXPECT_EQ("", manager->getOutputLanguage());
}

TEST_F(OutputManagerTests, init_language)
{
	std::string lang = "c";

	manager->setOutputLanguage(lang);

	EXPECT_EQ(lang, manager->getOutputLanguage());
}

//
// operatorX()
//

TEST_F(OutputManagerTests, operatorX_no_spaces)
{
	manager->operatorX("++", false, false);

	EXPECT_EQ("++", emitCode());
}

TEST_F(OutputManagerTests, operatorX_space_before)
{
	manager->operatorX("++", true, false);

	EXPECT_EQ(" ++", emitCode());
}

TEST_F(OutputManagerTests, operatorX_space_after)
{
	manager->operatorX("++", false, true);

	EXPECT_EQ("++ ", emitCode());
}

TEST_F(OutputManagerTests, operatorX_space_before_after)
{
	manager->operatorX("++", true, true);

	EXPECT_EQ(" ++ ", emitCode());
}

//
// comment()
//

TEST_F(OutputManagerTests, comment_without_indent)
{
	manager->setCommentPrefix("//");
	manager->comment("hello world", "");

	EXPECT_EQ("// hello world", emitCode());
}

TEST_F(OutputManagerTests, comment_with_indent)
{
	manager->setCommentPrefix("//");
	manager->comment("hello world", "    ");

	EXPECT_EQ("    // hello world", emitCode());
}

//
// commentLine()
//

TEST_F(OutputManagerTests, comment_line_without_indent)
{
	manager->setCommentPrefix("//");
	manager->commentLine("hello world");

	EXPECT_EQ("// hello world\n", emitCode());
}

TEST_F(OutputManagerTests, comment_line_with_indent)
{
	manager->setCommentPrefix("//");
	manager->commentLine("hello world", "    ");

	EXPECT_EQ("    // hello world\n", emitCode());
}

//
// includeLine()
//

TEST_F(OutputManagerTests, include_line_basic)
{
	manager->includeLine("stdlib.h");

	EXPECT_EQ("#include <stdlib.h>\n", emitCode());
}

TEST_F(OutputManagerTests, include_line_basic_indent)
{
	manager->includeLine("stdlib.h", "    ");

	EXPECT_EQ("    #include <stdlib.h>\n", emitCode());
}

TEST_F(OutputManagerTests, include_line_basic_indent_comment)
{
	manager->setCommentPrefix("//");
	manager->includeLine("stdlib.h", "    ", "hello");

	EXPECT_EQ("    #include <stdlib.h> // hello\n", emitCode());
}

//
// typedefLine()
//

TEST_F(OutputManagerTests, typedef_line)
{
	manager->typedefLine("    ", "int", "uint64_t");

	EXPECT_EQ("    typedef int uint64_t;\n", emitCode());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec