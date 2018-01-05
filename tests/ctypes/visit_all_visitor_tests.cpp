/**
* @file tests/ctypes/visit_all_visitor_tests.cpp
* @brief Tests for the @c visit_all_visitor module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/enum_type.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/visit_all_visitor.h"
#include "retdec/ctypes/void_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class VisitAll: public VisitAllVisitor
{
	public:
		VisitAll() = default;

	public:
		const AccessedTypes &getAccessedTypes() const
		{
			return accessedTypes;
		}
};

class VisitAllVisitorTests : public Test
{
	public:
		VisitAllVisitorTests():
			visitor(new VisitAll()),
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)),
			floatType(FloatingPointType::create(context, "float", 32)),
			ptrToInt(PointerType::create(context, intType)) {}

	public:
		VisitAll *visitor;
		std::shared_ptr<Context> context;
		std::shared_ptr<IntegralType> intType;
		std::shared_ptr<FloatingPointType> floatType;
		std::shared_ptr<PointerType> ptrToInt;
};

TEST_F(VisitAllVisitorTests,
VisitAllFunctionTypeParametersAndReturnType)
{
	auto funcType = FunctionType::create(context, intType, {floatType, ptrToInt});
	VisitAll::AccessedTypes expected{funcType, intType, floatType, ptrToInt};

	funcType->accept(visitor);

	EXPECT_EQ(expected, visitor->getAccessedTypes());
}

TEST_F(VisitAllVisitorTests,
VisitAllStructMembers)
{

	StructType::Members mem{Member("x", intType), Member("y", floatType)};
	auto structType = StructType::create(context, "s", mem);
	VisitAll::AccessedTypes expected{structType, intType, floatType};

	structType->accept(visitor);

	EXPECT_EQ(expected, visitor->getAccessedTypes());
}

TEST_F(VisitAllVisitorTests,
VisitAllUnionMembers)
{

	UnionType::Members mem{Member("x", intType), Member("y", floatType)};
	auto unionType = UnionType::create(context, "s", mem);
	VisitAll::AccessedTypes expected{unionType, intType, floatType};

	unionType->accept(visitor);

	EXPECT_EQ(expected, visitor->getAccessedTypes());
}

TEST_F(VisitAllVisitorTests,
VisitEnumTypeVisitsOnlyEnum)
{
	EnumType::Values values{{"a", 1}};
	auto enumType = EnumType::create(context, "s", values);
	VisitAll::AccessedTypes expected{enumType};

	enumType->accept(visitor);

	EXPECT_EQ(expected, visitor->getAccessedTypes());
}

TEST_F(VisitAllVisitorTests,
VisitElementTypeInArray)
{

	auto intType = IntegralType::create(context, "int", 32);
	auto arrayType = ArrayType::create(context, intType, {1});
	VisitAll::AccessedTypes expected{arrayType, intType};

	arrayType->accept(visitor);

	EXPECT_EQ(expected, visitor->getAccessedTypes());
}

TEST_F(VisitAllVisitorTests,
VisitTypedefedTypeVisitsAlisedType)
{

	auto intType = IntegralType::create(context, "int", 32);
	auto typedefedType = TypedefedType::create(context, "newInt", intType);
	VisitAll::AccessedTypes expected{typedefedType, intType};

	typedefedType->accept(visitor);

	EXPECT_EQ(expected, visitor->getAccessedTypes());
}

TEST_F(VisitAllVisitorTests,
VisitTypedefedTypeToUnknownTypeVisitsUnknwonType)
{
	auto unknown = UnknownType::create();
	auto typedefedType = TypedefedType::create(context, "noname", unknown);
	VisitAll::AccessedTypes expected{typedefedType, unknown};

	typedefedType->accept(visitor);

	EXPECT_EQ(expected, visitor->getAccessedTypes());
}

TEST_F(VisitAllVisitorTests,
VisitVoidType)
{
	auto voidType = VoidType::create();
	VisitAll::AccessedTypes expected{voidType};

	voidType->accept(visitor);

	EXPECT_EQ(expected, visitor->getAccessedTypes());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
