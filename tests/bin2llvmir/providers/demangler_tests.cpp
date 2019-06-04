/**
* @file tests/bin2llvmir/providers/tests/demangler_tests.cpp
* @brief Tests for the @c DemanglerProvider.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/config/tool_info.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c DemanglerProvider pass.
 */
class DemanglerProviderTests: public LlvmIrTests
{

};

TEST_F(DemanglerProviderTests, addDemanglerAddsDemanglerForModule)
{
	retdec::config::ToolInfo tool;
	tool.setIsGcc();
	retdec::config::ToolInfoContainer tools;
	tools.insert(tool);
	auto* r1 = DemanglerProvider::addDemangler(module.get(), tools);
	auto* r2 = DemanglerProvider::getDemangler(module.get());
	retdec::demangler::CDemangler* r3 = nullptr;
	bool b = DemanglerProvider::getDemangler(module.get(), r3);

	EXPECT_NE(nullptr, r1);
	EXPECT_EQ(r1, r2);
	EXPECT_EQ(r1, r3);
	EXPECT_TRUE(b);
}

TEST_F(DemanglerProviderTests, getDemanglerReturnsNullptrForUnknownModule)
{
	retdec::config::ToolInfo tool;
	tool.setIsGcc();
	retdec::config::ToolInfoContainer tools;
	tools.insert(tool);
	DemanglerProvider::addDemangler(module.get(), tools);
	parseInput(""); // creates a different module
	auto* r1 = DemanglerProvider::getDemangler(module.get());
	retdec::demangler::CDemangler* r2 = nullptr;
	bool b = DemanglerProvider::getDemangler(module.get(), r2);

	EXPECT_EQ(nullptr, r1);
	EXPECT_EQ(nullptr, r2);
	EXPECT_FALSE(b);
}

TEST_F(DemanglerProviderTests, addedDemanglerWorks)
{
	retdec::config::ToolInfo tool;
	tool.setIsGcc();
	retdec::config::ToolInfoContainer tools;
	tools.insert(tool);
	parseInput(R"(
		define void @_ZN9wikipedia7article8print_toERSo() {
			ret void
		}
	)");
	Value* f = getValueByName("_ZN9wikipedia7article8print_toERSo");
	auto* d = DemanglerProvider::addDemangler(module.get(), tools);
	std::string name = d->demangleToString(f->getName());

	EXPECT_EQ("wikipedia::article::print_to(std::ostream &)", name);
}

TEST_F(DemanglerProviderTests, clearRemovesAllData)
{
	retdec::config::ToolInfo tool;
	tool.setIsGcc();
	retdec::config::ToolInfoContainer tools;
	tools.insert(tool);
	DemanglerProvider::addDemangler(module.get(), tools);
	auto* r1 = DemanglerProvider::getDemangler(module.get());
	EXPECT_NE(nullptr, r1);

	DemanglerProvider::clear();
	auto* r2 = DemanglerProvider::getDemangler(module.get());
	EXPECT_EQ(nullptr, r2);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
