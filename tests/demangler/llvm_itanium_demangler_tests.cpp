/**
 * @file tests/demangler/llvm_itanium_demangler_tests.cpp
 * @brief Tests for the llvm itanium demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "llvm/Demangle/demangler.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

class LlvmItaniumDemanglerTests : public Test
{
	public:
		LlvmItaniumDemanglerTests():
			demangler(retdec::demangler::DemanglerFactory::getDemangler("itanium")) {}

		void demangle_eq(const std::string &mangled, const std::string &demangled) {
			using status = retdec::demangler::Demangler::Status;

			auto result = demangler->demangleToString(mangled);
			EXPECT_EQ(demangler->status(), status::success);
			EXPECT_EQ(result, demangled);
		}
	protected:
		std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(LlvmItaniumDemanglerTests,
BasicTest)
{
	demangle_eq("_ZN3fooILi1EEC5Ev", "foo<1>::foo()");
}

} // namespace tests
} // namespace demangler
} // namespace retdec
