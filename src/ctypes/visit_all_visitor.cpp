/**
* @file src/ctypes/visit_all_visitor.cpp
* @brief Implementation of VisitAllVisitor.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/array_type.h"
#include "retdec/ctypes/enum_type.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/visit_all_visitor.h"
#include "retdec/ctypes/void_type.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new visitor.
*/
VisitAllVisitor::VisitAllVisitor() = default;

/**
* @brief Destructs the visitor.
*/
VisitAllVisitor::~VisitAllVisitor() = default;

void VisitAllVisitor::visit(const std::shared_ptr<ArrayType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}

	type->getElementType()->accept(this);
}

void VisitAllVisitor::visit(const std::shared_ptr<EnumType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}
}

void VisitAllVisitor::visit(const std::shared_ptr<FloatingPointType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}
}

void VisitAllVisitor::visit(const std::shared_ptr<FunctionType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}

	type->getReturnType()->accept(this);
	for (const auto &param: type->getParameters())
	{
		param->accept(this);
	}
}

void VisitAllVisitor::visit(const std::shared_ptr<IntegralType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}
}

void VisitAllVisitor::visit(const std::shared_ptr<PointerType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}

	type->getPointedType()->accept(this);
}

void VisitAllVisitor::visit(const std::shared_ptr<StructType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}

	for (auto i = type->member_begin(), e = type->member_end(); i != e; ++i)
	{
		i->getType()->accept(this);
	}
}

void VisitAllVisitor::visit(const std::shared_ptr<TypedefedType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}

	type->getAliasedType()->accept(this);
}

void VisitAllVisitor::visit(const std::shared_ptr<UnionType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}

	for (auto i = type->member_begin(), e = type->member_end(); i != e; ++i)
	{
		i->getType()->accept(this);
	}
}

void VisitAllVisitor::visit(const std::shared_ptr<UnknownType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}
}

void VisitAllVisitor::visit(const std::shared_ptr<VoidType> &type)
{
	if (makeAccessedAndCheckIfAccessed(type))
	{
		return;
	}
}

bool VisitAllVisitor::makeAccessedAndCheckIfAccessed(const std::shared_ptr<Type> &type)
{
	auto result = accessedTypes.insert(type);
	// result is a std::pair, where the second element denotes whether the
	// insertion took place.
	return !result.second;
}

} // namespace ctypes
} // namespace retdec
