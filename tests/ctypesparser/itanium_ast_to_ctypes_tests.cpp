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
		demangler(std::make_unique<retdec::demangler::ItaniumDemangler>()),
		context(std::make_shared<retdec::ctypes::Context>()),
		module(std::make_shared<ctypes::Module>(context)) {}
protected:
	void mangledToCtypes(
		const std::string &mangled)
	{
		demangler->demangleToModule(mangled, module);
	}

	std::unique_ptr<retdec::demangler::Demangler> demangler;
	std::shared_ptr<retdec::ctypes::Context> context;
	std::shared_ptr<retdec::ctypes::Module> module;
};

TEST_F(ItaniumCtypesTests, PointerTest)
{
	mangledToCtypes("_Z1fKP3Bar");	// f(Bar* const);

	EXPECT_TRUE(module->hasFunctionWithName("f"));

	auto func = module->getFunctionWithName("f");
	EXPECT_TRUE(func->getReturnType()->isUnknown());
	EXPECT_EQ(func->getParameterCount(), 1);

	auto param = func->getParameter(1);
	auto pointer = param.getType();
	EXPECT_TRUE(pointer->isPointer());
	auto pointee = std::static_pointer_cast<ctypes::PointerType>(pointer)->getPointedType();
	EXPECT_TRUE(pointee->isNamed());
}

TEST_F(ItaniumCtypesTests, ReferenceTest)
{
	mangledToCtypes("_Z1fRi");	// f(int &);

	EXPECT_TRUE(module->hasFunctionWithName("f"));

	auto func = module->getFunctionWithName("f");
	EXPECT_TRUE(func->getReturnType()->isUnknown());
	EXPECT_EQ(func->getParameterCount(), 1);

	auto param = func->getParameter(1);
	auto reference = param.getType();
	EXPECT_TRUE(reference->isReference());
	auto pointee = std::static_pointer_cast<ctypes::ReferenceType>(reference)->getReferencedType();
	EXPECT_TRUE(pointee->isIntegral());
}

TEST_F(ItaniumCtypesTests, VarArgnessTest)
{
	mangledToCtypes("_Z3fooiz");

	EXPECT_TRUE(module->hasFunctionWithName("foo"));

	auto func = module->getFunctionWithName("foo");
	EXPECT_TRUE(func->getReturnType()->isUnknown());
	EXPECT_EQ(func->getParameterCount(), 1);
	auto param = func->getParameter(1);
	EXPECT_TRUE(param.getType()->isIntegral());

	EXPECT_TRUE(func->isVarArg());
}

TEST_F(ItaniumCtypesTests, ArrayTest)
{
	mangledToCtypes("_Z1fA37_A42_iPS_");

	EXPECT_TRUE(module->hasFunctionWithName("f"));

	auto func = module->getFunctionWithName("f");
	EXPECT_TRUE(func->getReturnType()->isUnknown());
	EXPECT_EQ(func->getParameterCount(), 2);

	auto param = func->getParameter(1);
	auto array1 = param.getType();
	EXPECT_TRUE(array1->isArray());
	auto type = std::static_pointer_cast<ctypes::ArrayType>(array1)->getElementType();

	auto dimensions = std::static_pointer_cast<ctypes::ArrayType>(array1)->getDimensions();
	ctypes::ArrayType::Dimensions expectedDimensions{37,42};
	EXPECT_EQ(dimensions, expectedDimensions);
}

TEST_F(ItaniumCtypesTests, FunctionPointers)
{
	mangledToCtypes("_Z4foo1PFivE");

	EXPECT_TRUE(module->hasFunctionWithName("foo1"));

	auto func = module->getFunctionWithName("foo1");
	EXPECT_TRUE(func->getReturnType()->isUnknown());
	EXPECT_EQ(func->getParameterCount(), 1);

	auto param = func->getParameter(1);
	auto pointer = param.getType();
	EXPECT_TRUE(pointer->isPointer());

	auto pointee = std::static_pointer_cast<ctypes::PointerType>(pointer)->getPointedType();
	EXPECT_TRUE(pointee->isFunction());

	auto pointed_func = std::static_pointer_cast<ctypes::FunctionType>(pointee);
	EXPECT_TRUE(pointed_func->getReturnType()->isIntegral());
	EXPECT_EQ(pointed_func->getParameterCount(), 0);
}

}	// namespace tests
}	// namespace ctypesparser
}	// namespace retdec