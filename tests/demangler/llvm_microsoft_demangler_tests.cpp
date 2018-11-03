/**
 * @file tests/demangler/llvm_microsoft_demangler_tests.cpp
 * @brief Tests for the llvm microsoft demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "llvm/Demangle/demangler_retdec.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

class LlvmMicrosoftDemanglerTests : public Test
{
	public:
		LlvmMicrosoftDemanglerTests():
			demangler(retdec::demangler::DemanglerFactory::getDemangler("microsoft")) {}

		void demangle_eq(const std::string &mangled, const std::string &demangled) {
			using status = retdec::demangler::Demangler::Status;

			auto result = demangler->demangleToString(mangled);
			EXPECT_EQ(demangler->status(), status::success);
			EXPECT_EQ(result, demangled);
		}
	protected:
		std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(LlvmMicrosoftDemanglerTests,
	   BasicTest)
{
	demangle_eq("??D@YAPAXI@Z", "void * __cdecl operator*(unsigned int)");
}

} // namespace tests
} // namespace demangler
} // namespace retdec
