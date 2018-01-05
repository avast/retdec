/**
* @file include/retdec/ctypes/visitor.h
* @brief A base class of all visitors.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_VISITOR_H
#define RETDEC_CTYPES_VISITOR_H

#include <memory>

namespace retdec {
namespace ctypes {

class ArrayType;
class EnumType;
class FloatingPointType;
class FunctionType;
class IntegralType;
class PointerType;
class StructType;
class TypedefedType;
class UnionType;
class UnknownType;
class VoidType;

/**
* @brief A base class of all C-types' visitors.
*/
class Visitor
{
	public:
		virtual ~Visitor() = 0;

		virtual void visit(const std::shared_ptr<ArrayType> &type) = 0;
		virtual void visit(const std::shared_ptr<EnumType> &type) = 0;
		virtual void visit(const std::shared_ptr<FloatingPointType> &type) = 0;
		virtual void visit(const std::shared_ptr<FunctionType> &type) = 0;
		virtual void visit(const std::shared_ptr<IntegralType> &type) = 0;
		virtual void visit(const std::shared_ptr<PointerType> &type) = 0;
		virtual void visit(const std::shared_ptr<StructType> &type) = 0;
		virtual void visit(const std::shared_ptr<TypedefedType> &type) = 0;
		virtual void visit(const std::shared_ptr<UnionType> &type) = 0;
		virtual void visit(const std::shared_ptr<UnknownType> &type) = 0;
		virtual void visit(const std::shared_ptr<VoidType> &type) = 0;

	protected:
		Visitor();
};

} // namespace ctypes
} // namespace retdec

#endif
