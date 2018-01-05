/**
* @file include/retdec/ctypes/visit_all_visitor.h
* @brief A visitor that visits all types inside some type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_VISIT_ALL_VISITOR_H
#define RETDEC_CTYPES_VISIT_ALL_VISITOR_H

#include <unordered_set>

#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

class Type;

/**
* @brief A visitor that visits all types inside some type.
*/
class VisitAllVisitor: public Visitor
{
	public:
		virtual ~VisitAllVisitor() override;

		/// @name Visitor interface.
		/// @{
		virtual void visit(const std::shared_ptr<ArrayType> &type) override;
		virtual void visit(const std::shared_ptr<EnumType> &type) override;
		virtual void visit(const std::shared_ptr<FloatingPointType> &type) override;
		virtual void visit(const std::shared_ptr<FunctionType> &type) override;
		virtual void visit(const std::shared_ptr<IntegralType> &type) override;
		virtual void visit(const std::shared_ptr<PointerType> &type) override;
		virtual void visit(const std::shared_ptr<StructType> &type) override;
		virtual void visit(const std::shared_ptr<TypedefedType> &type) override;
		virtual void visit(const std::shared_ptr<UnionType> &type) override;
		virtual void visit(const std::shared_ptr<UnknownType> &type) override;
		virtual void visit(const std::shared_ptr<VoidType> &type) override;
		/// @}

	public:
		using AccessedTypes = std::unordered_set<std::shared_ptr<Type>>;

	protected:
		VisitAllVisitor();

		bool makeAccessedAndCheckIfAccessed(const std::shared_ptr<Type> &type);

	protected:
		/// A set of all accessed types.
		AccessedTypes accessedTypes;

};

} // namespace ctypes
} // namespace retdec

#endif
