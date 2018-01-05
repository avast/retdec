/**
* @file include/retdec/llvmir2hll/analysis/used_types_visitor.h
* @brief A visitor for obtaining the used types in the IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_USED_TYPES_VISITOR_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_USED_TYPES_VISITOR_H

#include <cstddef>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Value;
class Type;

/**
* @brief Used types in a module.
*
* See UsedTypesVisitor for a way of creating instances of this class.
*
* Instances of this class have value object semantics.
*/
class UsedTypes {
	friend class UsedTypesVisitor;

public:
	/// Types iterator.
	using type_iterator = TypeSet::const_iterator;

	/// Struct types iterator.
	using struct_type_iterator = StructTypeSet::const_iterator;

public:
	UsedTypes(const UsedTypes &other);
	~UsedTypes();

	UsedTypes &operator=(const UsedTypes &other);
	bool operator==(const UsedTypes &other) const;
	bool operator!=(const UsedTypes &other) const;

	TypeSet getIntTypes() const;
	TypeSet getSignedIntTypes() const;
	TypeSet getUnsignedIntTypes() const;
	TypeSet getFloatTypes() const;
	StructTypeSet getStructTypes() const;
	TypeSet getOtherTypes() const;
	TypeSet getAllTypes() const;
	std::size_t getCount(bool intTy = true, bool floatTy = true,
		bool structTy = true, bool otherTy = true) const;
	bool isUsedBool() const;

	/// @name Used Types Accessors
	/// @{
	type_iterator int_begin() const;
	type_iterator int_end() const;

	type_iterator signed_int_begin() const;
	type_iterator signed_int_end() const;

	type_iterator unsigned_int_begin() const;
	type_iterator unsigned_int_end() const;

	type_iterator float_begin() const;
	type_iterator float_end() const;

	struct_type_iterator struct_begin() const;
	struct_type_iterator struct_end() const;

	type_iterator other_begin() const;
	type_iterator other_end() const;

	type_iterator all_begin() const;
	type_iterator all_end() const;
	/// @}

private:
	UsedTypes();

private:
	/// Set of all integer types.
	TypeSet intTypes;

	/// Set of signed integer types.
	TypeSet signedIntTypes;

	/// Set of unsigned integer types.
	TypeSet unsignedIntTypes;

	/// Set of float types.
	TypeSet floatTypes;

	/// Set of structure types.
	StructTypeSet structTypes;

	/// Set of other types (integer, float, structs are not included).
	TypeSet otherTypes;

	/// Set of all types (integer, float, structs and other).
	TypeSet allTypes;

	/// Is bool type used?
	bool usedBool;
};

/**
* @brief A visitor for obtaining the used types in the IR.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class UsedTypesVisitor: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~UsedTypesVisitor() override;

	static ShPtr<UsedTypes> getUsedTypes(ShPtr<Module> module);

private:
	explicit UsedTypesVisitor();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<Function> func) override;
	virtual void visit(ShPtr<Variable> var) override;
	virtual void visit(ShPtr<ConstBool> constant) override;
	// Casts
	virtual void visit(ShPtr<BitCastExpr> expr) override;
	virtual void visit(ShPtr<ExtCastExpr> expr) override;
	virtual void visit(ShPtr<FPToIntCastExpr> expr) override;
	virtual void visit(ShPtr<IntToFPCastExpr> expr) override;
	virtual void visit(ShPtr<IntToPtrCastExpr> expr) override;
	virtual void visit(ShPtr<PtrToIntCastExpr> expr) override;
	virtual void visit(ShPtr<TruncCastExpr> expr) override;
	// Types
	virtual void visit(ShPtr<FloatType> type) override;
	virtual void visit(ShPtr<IntType> type) override;
	virtual void visit(ShPtr<PointerType> type) override;
	virtual void visit(ShPtr<StringType> type) override;
	virtual void visit(ShPtr<ArrayType> type) override;
	virtual void visit(ShPtr<StructType> type) override;
	virtual void visit(ShPtr<FunctionType> type) override;
	virtual void visit(ShPtr<VoidType> type) override;
	virtual void visit(ShPtr<UnknownType> type) override;
	/// @}

private:
	/// Set of used types.
	ShPtr<UsedTypes> usedTypes;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
