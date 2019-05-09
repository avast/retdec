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
		module(std::make_unique<ctypes::Module>(std::make_shared<retdec::ctypes::Context>())) {}
protected:
	std::shared_ptr<ctypes::Function> mangledToCtypes(
		const std::string &mangled)
	{
		ctypesparser::CTypesParser::TypeWidths typeWidths {
			{"void", 0},
			{"bool", 1},
			{"char", 8},
			{"signed char", 8},
			{"unsigned char", 8},
			{"wchar_t", 32},
			{"short", 16},
			{"unsigned short", 16},
			{"int", 32},
			{"unsigned int", 32},
			{"long", 64},
			{"unsigned long", 64},
			{"long long", 64},
			{"unsigned long long", 64},
			{"int64_t", 64},
			{"uint64_t", 64},
			{"float", 32},
			{"double", 64},
			{"long double", 96},
			{"pointer", 32}
		};

		ctypesparser::CTypesParser::TypeSignedness typeSignedness {
			{"wchar_t", ctypes::IntegralType::Signess::Unsigned},
			{"char", ctypes::IntegralType::Signess::Unsigned},
		};

		return demangler->demangleFunctionToCtypes(mangled, module, typeWidths, typeSignedness);
	}

	std::unique_ptr<retdec::demangler::Demangler> demangler;
	std::unique_ptr<retdec::ctypes::Module> module;
};

TEST_F(ItaniumCtypesTests, PointerTest)
{
	mangledToCtypes("_Z1fKP3Bar");	// f(Bar* const);

	EXPECT_TRUE(module->hasFunctionWithName("_Z1fKP3Bar"));

	auto func = module->getFunctionWithName("_Z1fKP3Bar");
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

	EXPECT_TRUE(module->hasFunctionWithName("_Z1fRi"));

	auto func = module->getFunctionWithName("_Z1fRi");
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

	EXPECT_TRUE(module->hasFunctionWithName("_Z3fooiz"));

	auto func = module->getFunctionWithName("_Z3fooiz");
	EXPECT_TRUE(func->getReturnType()->isUnknown());
	EXPECT_EQ(func->getParameterCount(), 1);
	auto param = func->getParameter(1);
	EXPECT_TRUE(param.getType()->isIntegral());

	EXPECT_TRUE(func->isVarArg());
}

TEST_F(ItaniumCtypesTests, ArrayTest)
{
	mangledToCtypes("_Z1fA37_A42_iPS_");

	EXPECT_TRUE(module->hasFunctionWithName("_Z1fA37_A42_iPS_"));

	auto func = module->getFunctionWithName("_Z1fA37_A42_iPS_");
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

	EXPECT_TRUE(module->hasFunctionWithName("_Z4foo1PFivE"));

	auto func = module->getFunctionWithName("_Z4foo1PFivE");
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