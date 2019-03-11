/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/demangler/demangler.h"
#include "retdec/ctypes/module.h"
#include "retdec/demangler/context.h"
#include "retdec/ctypes/context.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

class BorlandCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	BorlandCtypesTests() :
		demangler(retdec::demangler::DemanglerFactory::getDemangler("borland")) {}
protected:
	std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(BorlandCtypesTests, basic)
{
	auto context = std::make_shared<retdec::ctypes::Context>();
	auto module = std::make_unique<ctypes::Module>(context);
	demangler->demangleToModule("@myFunc_int_$qi", module);
}

}
}
}