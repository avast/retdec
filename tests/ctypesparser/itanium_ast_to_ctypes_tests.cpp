/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>
#include <retdec/ctypes/floating_point_type.h>

#include "retdec/demangler/demangler.h"
#include "retdec/demangler/context.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/named_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/reference_type.h"
#include "retdec/ctypes/unknown_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypesparser {
namespace tests {

class ItaniumCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	ItaniumCtypesTests() :
		demangler(retdec::demangler::DemanglerFactory::getDemangler("itanium")),
		context(std::make_shared<retdec::ctypes::Context>()),
		module(std::make_unique<ctypes::Module>(context)) {}
protected:
	void mangledToCtypes(
		const std::string &mangled)
	{
		demangler->demangleToModule(mangled, module);
	}

	std::unique_ptr<retdec::demangler::Demangler> demangler;
	std::shared_ptr<retdec::ctypes::Context> context;
	std::unique_ptr<retdec::ctypes::Module> module;
};

TEST_F(ItaniumCtypesTests, BasicTest)
{
	mangledToCtypes("_Z1fKP3Bar");
}

}	// namespace tests
}	// namespace ctypesparser
}	// namespace retdec