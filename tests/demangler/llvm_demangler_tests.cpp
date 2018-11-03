#include <gtest/gtest.h>

#include "llvm/Demangle/Demangle.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

class LlvmDemanglerTests : public Test
{
	public:
		LlvmDemanglerTests() = default;

		bool demangle_eq(std::string mangled, std::string demangled) {
			const char *man_c = mangled.c_str();
			const char *dem_c = demangled.c_str();
			int status{};
			char *result = llvm::itaniumDemangle(man_c, nullptr, nullptr, &status);
			return status == llvm::demangle_success && strcmp(result, dem_c) == 0;
		}
};

TEST_F(LlvmDemanglerTests,
BasicTest)
{
	EXPECT_TRUE(demangle_eq("_ZN3fooILi1EEC5Ev", "foo<1>::foo()"));
}

} // namespace tests
} // namespace demangler
} // namespace retdec

