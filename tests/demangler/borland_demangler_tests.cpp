/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "llvm/Demangle/demangler_retdec.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

#define DEM_EQ(mangled, demangled) \
			do {	\
				EXPECT_EQ(demangler->demangleToString(mangled), demangled); \
                EXPECT_EQ(demangler->status(), status::success); \
			} while(0)

class LlvmBorlandDemanglerTests : public Test
{
	public:
		using status = retdec::demangler::Demangler::Status;

		LlvmBorlandDemanglerTests():
			demangler(retdec::demangler::DemanglerFactory::getDemangler("borland")) {}

	protected:
		std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(LlvmBorlandDemanglerTests,
	   BasicTest)
{
	DEM_EQ("@myFunc_int_$qi", "myFunc(int)");
}

TEST_F(LlvmBorlandDemanglerTests,
		CallConvTest)
{
	DEM_EQ("@myFunc_fastcall_$qqrv", "__fastcall myFunc_fastcall_()");
	DEM_EQ("@myFunc_cdecl_$qv", "__cdecl myFunc_cdecl_()");
	DEM_EQ("@myFunc_pascal_$qv", "__pascal myFunc_pascal_()");
	DEM_EQ("@myFunc_stdcall_$qqsv", "__stdcall myFunc_stdcall_()");
}

} // namespace tests
} // namespace demangler
} // namespace retdec

