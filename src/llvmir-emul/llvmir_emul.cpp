/**
 * @file src/llvmir-emul/llvmir_emul.cpp
 * @brief LLVM IR emulator library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/CallSite.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/TypeBuilder.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/MathExtras.h>
#include <llvm/Support/Memory.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/PluginLoader.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Process.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir-emul/llvmir_emul.h"

using namespace llvm;

namespace retdec {
namespace llvmir_emul {

namespace {

/**
 * Print any LLVM object which implements @c print(llvm::raw_string_ostream&)
 * method into std::string.
 * @param t LLVM object to print.
 * @return String with printed object.
 */
template<typename T>
std::string llvmObjToString(const T* t)
{
	std::string str;
	llvm::raw_string_ostream ss(str);
	if (t)
		t->print(ss);
	else
		ss << "nullptr";
	return ss.str();
}

//
//=============================================================================
// Binary Instruction Implementations
//=============================================================================
//

#define IMPLEMENT_BINARY_OPERATOR(OP, TY) \
	case Type::TY##TyID: \
		Dest.TY##Val = Src1.TY##Val OP Src2.TY##Val; \
		break

void executeFAddInst(
		GenericValue &Dest,
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	switch (Ty->getTypeID())
	{
		IMPLEMENT_BINARY_OPERATOR(+, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_BINARY_OPERATOR(+, Double);
		default:
			dbgs() << "Unhandled type for FAdd instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
}

void executeFSubInst(
		GenericValue &Dest,
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	switch (Ty->getTypeID())
	{
		IMPLEMENT_BINARY_OPERATOR(-, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_BINARY_OPERATOR(-, Double);
		default:
			dbgs() << "Unhandled type for FSub instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
}

void executeFMulInst(
		GenericValue &Dest,
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	switch (Ty->getTypeID())
	{
		IMPLEMENT_BINARY_OPERATOR(*, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_BINARY_OPERATOR(*, Double);
		default:
			dbgs() << "Unhandled type for FMul instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
}

void executeFDivInst(
		GenericValue &Dest,
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	switch (Ty->getTypeID())
	{
		IMPLEMENT_BINARY_OPERATOR(/, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_BINARY_OPERATOR(/, Double);
		default:
			dbgs() << "Unhandled type for FDiv instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
}

void executeFRemInst(
		GenericValue &Dest,
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	switch (Ty->getTypeID())
	{
		case Type::FloatTyID:
			Dest.FloatVal = fmod(Src1.FloatVal, Src2.FloatVal);
			break;
		case Type::X86_FP80TyID:
		case Type::DoubleTyID:
			Dest.DoubleVal = fmod(Src1.DoubleVal, Src2.DoubleVal);
			break;
		default:
			dbgs() << "Unhandled type for Rem instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
}

#define IMPLEMENT_INTEGER_ICMP(OP, TY) \
	case Type::IntegerTyID:  \
		Dest.IntVal = APInt(1,Src1.IntVal.OP(Src2.IntVal)); \
		break;

#define IMPLEMENT_VECTOR_INTEGER_ICMP(OP, TY)                              \
	case Type::VectorTyID:                                                 \
	{                                                                      \
		assert(Src1.AggregateVal.size() == Src2.AggregateVal.size());      \
		Dest.AggregateVal.resize( Src1.AggregateVal.size() );              \
		for(uint32_t _i=0;_i<Src1.AggregateVal.size();_i++)                \
			Dest.AggregateVal[_i].IntVal = APInt(1,                        \
			Src1.AggregateVal[_i].IntVal.OP(Src2.AggregateVal[_i].IntVal));\
	} break;

// Handle pointers specially because they must be compared with only as much
// width as the host has.  We _do not_ want to be comparing 64 bit values when
// running on a 32-bit target, otherwise the upper 32 bits might mess up
// comparisons if they contain garbage.
// Matula: This may not be the case for emulation, but it will probable be ok.
#define IMPLEMENT_POINTER_ICMP(OP) \
	case Type::PointerTyID: \
		Dest.IntVal = APInt(1, reinterpret_cast<void*>(reinterpret_cast<intptr_t>(Src1.PointerVal)) OP \
				reinterpret_cast<void*>(reinterpret_cast<intptr_t>(Src2.PointerVal))); \
		break;

GenericValue executeICMP_EQ(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(eq,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(eq,Ty);
		IMPLEMENT_POINTER_ICMP(==);
		default:
			dbgs() << "Unhandled type for ICMP_EQ predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_NE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(ne,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(ne,Ty);
		IMPLEMENT_POINTER_ICMP(!=);
		default:
			dbgs() << "Unhandled type for ICMP_NE predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_ULT(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(ult,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(ult,Ty);
		IMPLEMENT_POINTER_ICMP(<);
		default:
			dbgs() << "Unhandled type for ICMP_ULT predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_SLT(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(slt,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(slt,Ty);
		IMPLEMENT_POINTER_ICMP(<);
		default:
			dbgs() << "Unhandled type for ICMP_SLT predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_UGT(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(ugt,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(ugt,Ty);
		IMPLEMENT_POINTER_ICMP(>);
		default:
			dbgs() << "Unhandled type for ICMP_UGT predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_SGT(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(sgt,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(sgt,Ty);
		IMPLEMENT_POINTER_ICMP(>);
		default:
			dbgs() << "Unhandled type for ICMP_SGT predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_ULE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(ule,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(ule,Ty);
		IMPLEMENT_POINTER_ICMP(<=);
		default:
			dbgs() << "Unhandled type for ICMP_ULE predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_SLE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(sle,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(sle,Ty);
		IMPLEMENT_POINTER_ICMP(<=);
		default:
			dbgs() << "Unhandled type for ICMP_SLE predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_UGE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_INTEGER_ICMP(uge,Ty);
		IMPLEMENT_VECTOR_INTEGER_ICMP(uge,Ty);
		IMPLEMENT_POINTER_ICMP(>=);
		default:
			dbgs() << "Unhandled type for ICMP_UGE predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeICMP_SGE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
			IMPLEMENT_INTEGER_ICMP(sge,Ty);
			IMPLEMENT_VECTOR_INTEGER_ICMP(sge,Ty);
			IMPLEMENT_POINTER_ICMP(>=);
		default:
			dbgs() << "Unhandled type for ICMP_SGE predicate: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

#define IMPLEMENT_FCMP(OP, TY) \
	case Type::TY##TyID: \
		Dest.IntVal = APInt(1,Src1.TY##Val OP Src2.TY##Val); \
		break

#define IMPLEMENT_VECTOR_FCMP_T(OP, TY)                                 \
	assert(Src1.AggregateVal.size() == Src2.AggregateVal.size());       \
	Dest.AggregateVal.resize( Src1.AggregateVal.size() );               \
	for( uint32_t _i=0;_i<Src1.AggregateVal.size();_i++)                \
		Dest.AggregateVal[_i].IntVal = APInt(1,                         \
		Src1.AggregateVal[_i].TY##Val OP Src2.AggregateVal[_i].TY##Val);\
	break;

#define IMPLEMENT_VECTOR_FCMP(OP)                                   \
	case Type::VectorTyID:                                          \
	if (cast<VectorType>(Ty)->getElementType()->isFloatTy())        \
	{                                                               \
		IMPLEMENT_VECTOR_FCMP_T(OP, Float);                         \
	}                                                               \
	else                                                            \
	{                                                               \
		IMPLEMENT_VECTOR_FCMP_T(OP, Double);                        \
	}

GenericValue executeFCMP_OEQ(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_FCMP(==, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_FCMP(==, Double);
		IMPLEMENT_VECTOR_FCMP(==);
		default:
			dbgs() << "Unhandled type for FCmp EQ instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

#define IMPLEMENT_SCALAR_NANS(TY, X,Y)                                \
	if (TY->isFloatTy())                                              \
	{                                                                 \
		if (X.FloatVal != X.FloatVal || Y.FloatVal != Y.FloatVal)     \
		{                                                             \
			Dest.IntVal = APInt(1,false);                             \
			return Dest;                                              \
		}                                                             \
	}                                                                 \
	else                                                              \
	{                                                                 \
		if (X.DoubleVal != X.DoubleVal || Y.DoubleVal != Y.DoubleVal) \
		{                                                             \
			Dest.IntVal = APInt(1,false);                             \
			return Dest;                                              \
		}                                                             \
	}

#define MASK_VECTOR_NANS_T(X,Y, TZ, FLAG)                                 \
	assert(X.AggregateVal.size() == Y.AggregateVal.size());               \
	Dest.AggregateVal.resize( X.AggregateVal.size() );                    \
	for( uint32_t _i=0;_i<X.AggregateVal.size();_i++)                     \
	{                                                                     \
		if (X.AggregateVal[_i].TZ##Val != X.AggregateVal[_i].TZ##Val ||   \
				Y.AggregateVal[_i].TZ##Val != Y.AggregateVal[_i].TZ##Val) \
				Dest.AggregateVal[_i].IntVal = APInt(1,FLAG);             \
		else                                                              \
		{                                                                 \
			Dest.AggregateVal[_i].IntVal = APInt(1,!FLAG);                \
		}                                                                 \
	}

#define MASK_VECTOR_NANS(TY, X,Y, FLAG)                                \
	if (TY->isVectorTy())                                              \
	{                                                                  \
		if (cast<VectorType>(TY)->getElementType()->isFloatTy())       \
		{                                                              \
			MASK_VECTOR_NANS_T(X, Y, Float, FLAG)                      \
		}                                                              \
		else                                                           \
		{                                                              \
			MASK_VECTOR_NANS_T(X, Y, Double, FLAG)                     \
		}                                                              \
	}

static GenericValue executeFCMP_ONE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	// if input is scalar value and Src1 or Src2 is NaN return false
	IMPLEMENT_SCALAR_NANS(Ty, Src1, Src2)
	// if vector input detect NaNs and fill mask
	MASK_VECTOR_NANS(Ty, Src1, Src2, false)
	GenericValue DestMask = Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_FCMP(!=, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_FCMP(!=, Double);
		IMPLEMENT_VECTOR_FCMP(!=);
		default:
			dbgs() << "Unhandled type for FCmp NE instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	// in vector case mask out NaN elements
	if (Ty->isVectorTy())
		for( size_t _i=0; _i<Src1.AggregateVal.size(); _i++)
			if (DestMask.AggregateVal[_i].IntVal == false)
				Dest.AggregateVal[_i].IntVal = APInt(1,false);

	return Dest;
}

GenericValue executeFCMP_OLE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_FCMP(<=, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_FCMP(<=, Double);
		IMPLEMENT_VECTOR_FCMP(<=);
		default:
			dbgs() << "Unhandled type for FCmp LE instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeFCMP_OGE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_FCMP(>=, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_FCMP(>=, Double);
		IMPLEMENT_VECTOR_FCMP(>=);
	default:
		dbgs() << "Unhandled type for FCmp GE instruction: " << *Ty << "\n";
		llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeFCMP_OLT(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_FCMP(<, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_FCMP(<, Double);
		IMPLEMENT_VECTOR_FCMP(<);
		default:
			dbgs() << "Unhandled type for FCmp LT instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

GenericValue executeFCMP_OGT(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	switch (Ty->getTypeID())
	{
		IMPLEMENT_FCMP(>, Float);
		case Type::X86_FP80TyID:
		IMPLEMENT_FCMP(>, Double);
		IMPLEMENT_VECTOR_FCMP(>);
		default:
			dbgs() << "Unhandled type for FCmp GT instruction: " << *Ty << "\n";
			llvm_unreachable(nullptr);
	}
	return Dest;
}

#define IMPLEMENT_UNORDERED(TY, X,Y)                                         \
	if (TY->isFloatTy())                                                     \
	{                                                                        \
		if (X.FloatVal != X.FloatVal || Y.FloatVal != Y.FloatVal)            \
		{                                                                    \
			Dest.IntVal = APInt(1,true);                                     \
			return Dest;                                                     \
		}                                                                    \
	} else if (X.DoubleVal != X.DoubleVal || Y.DoubleVal != Y.DoubleVal)     \
	{                                                                        \
		Dest.IntVal = APInt(1,true);                                         \
		return Dest;                                                         \
	}

#define IMPLEMENT_VECTOR_UNORDERED(TY, X, Y, FUNC)                           \
	if (TY->isVectorTy())                                                    \
	{                                                                        \
		GenericValue DestMask = Dest;                                        \
		Dest = FUNC(Src1, Src2, Ty);                                         \
		for (size_t _i = 0; _i < Src1.AggregateVal.size(); _i++)             \
			if (DestMask.AggregateVal[_i].IntVal == true)                    \
				Dest.AggregateVal[_i].IntVal = APInt(1, true);               \
		return Dest;                                                         \
	}

GenericValue executeFCMP_UEQ(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	IMPLEMENT_UNORDERED(Ty, Src1, Src2)
	MASK_VECTOR_NANS(Ty, Src1, Src2, true)
	IMPLEMENT_VECTOR_UNORDERED(Ty, Src1, Src2, executeFCMP_OEQ)
	return executeFCMP_OEQ(Src1, Src2, Ty);
}

GenericValue executeFCMP_UNE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	IMPLEMENT_UNORDERED(Ty, Src1, Src2)
	MASK_VECTOR_NANS(Ty, Src1, Src2, true)
	IMPLEMENT_VECTOR_UNORDERED(Ty, Src1, Src2, executeFCMP_ONE)
	return executeFCMP_ONE(Src1, Src2, Ty);
}

GenericValue executeFCMP_ULE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	IMPLEMENT_UNORDERED(Ty, Src1, Src2)
	MASK_VECTOR_NANS(Ty, Src1, Src2, true)
	IMPLEMENT_VECTOR_UNORDERED(Ty, Src1, Src2, executeFCMP_OLE)
	return executeFCMP_OLE(Src1, Src2, Ty);
}

GenericValue executeFCMP_UGE(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	IMPLEMENT_UNORDERED(Ty, Src1, Src2)
	MASK_VECTOR_NANS(Ty, Src1, Src2, true)
	IMPLEMENT_VECTOR_UNORDERED(Ty, Src1, Src2, executeFCMP_OGE)
	return executeFCMP_OGE(Src1, Src2, Ty);
}

GenericValue executeFCMP_ULT(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	IMPLEMENT_UNORDERED(Ty, Src1, Src2)
	MASK_VECTOR_NANS(Ty, Src1, Src2, true)
	IMPLEMENT_VECTOR_UNORDERED(Ty, Src1, Src2, executeFCMP_OLT)
	return executeFCMP_OLT(Src1, Src2, Ty);
}

GenericValue executeFCMP_UGT(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	IMPLEMENT_UNORDERED(Ty, Src1, Src2)
	MASK_VECTOR_NANS(Ty, Src1, Src2, true)
	IMPLEMENT_VECTOR_UNORDERED(Ty, Src1, Src2, executeFCMP_OGT)
	return executeFCMP_OGT(Src1, Src2, Ty);
}

GenericValue executeFCMP_ORD(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	if(Ty->isVectorTy())
	{
		assert(Src1.AggregateVal.size() == Src2.AggregateVal.size());
		Dest.AggregateVal.resize( Src1.AggregateVal.size() );
		if (cast<VectorType>(Ty)->getElementType()->isFloatTy())
		{
			for( size_t _i=0;_i<Src1.AggregateVal.size();_i++)
				Dest.AggregateVal[_i].IntVal = APInt(
						1,
						( (Src1.AggregateVal[_i].FloatVal ==
						Src1.AggregateVal[_i].FloatVal) &&
						(Src2.AggregateVal[_i].FloatVal ==
						Src2.AggregateVal[_i].FloatVal)));
		}
		else
		{
			for( size_t _i=0;_i<Src1.AggregateVal.size();_i++)
				Dest.AggregateVal[_i].IntVal = APInt(
						1,
						( (Src1.AggregateVal[_i].DoubleVal ==
						Src1.AggregateVal[_i].DoubleVal) &&
						(Src2.AggregateVal[_i].DoubleVal ==
						Src2.AggregateVal[_i].DoubleVal)));
		}
	}
	else if (Ty->isFloatTy())
	{
		Dest.IntVal = APInt(1,(Src1.FloatVal == Src1.FloatVal &&
				Src2.FloatVal == Src2.FloatVal));
	}
	else
	{
		Dest.IntVal = APInt(1,(Src1.DoubleVal == Src1.DoubleVal &&
				Src2.DoubleVal == Src2.DoubleVal));
	}
	return Dest;
}

GenericValue executeFCMP_UNO(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Dest;
	if(Ty->isVectorTy())
	{
		assert(Src1.AggregateVal.size() == Src2.AggregateVal.size());
		Dest.AggregateVal.resize( Src1.AggregateVal.size() );
		if (cast<VectorType>(Ty)->getElementType()->isFloatTy())
		{
			for( size_t _i=0;_i<Src1.AggregateVal.size();_i++)
				Dest.AggregateVal[_i].IntVal = APInt(
						1,
						( (Src1.AggregateVal[_i].FloatVal !=
						Src1.AggregateVal[_i].FloatVal) ||
						(Src2.AggregateVal[_i].FloatVal !=
						Src2.AggregateVal[_i].FloatVal)));
		}
		else
		{
			for( size_t _i=0;_i<Src1.AggregateVal.size();_i++)
				Dest.AggregateVal[_i].IntVal = APInt(1,
						( (Src1.AggregateVal[_i].DoubleVal !=
						Src1.AggregateVal[_i].DoubleVal) ||
						(Src2.AggregateVal[_i].DoubleVal !=
						Src2.AggregateVal[_i].DoubleVal)));
		}
	}
	else if (Ty->isFloatTy())
	{
		Dest.IntVal = APInt(1,(Src1.FloatVal != Src1.FloatVal ||
				Src2.FloatVal != Src2.FloatVal));
	}
	else
	{
		Dest.IntVal = APInt(1,(Src1.DoubleVal != Src1.DoubleVal ||
				Src2.DoubleVal != Src2.DoubleVal));
	}
	return Dest;
}

GenericValue executeFCMP_BOOL(
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty,
		const bool val)
{
	GenericValue Dest;
	if(Ty->isVectorTy())
	{
		assert(Src1.AggregateVal.size() == Src2.AggregateVal.size());
		Dest.AggregateVal.resize( Src1.AggregateVal.size() );
		for( size_t _i=0; _i<Src1.AggregateVal.size(); _i++)
		{
			Dest.AggregateVal[_i].IntVal = APInt(1,val);
		}
	}
	else
	{
		Dest.IntVal = APInt(1, val);
	}

	return Dest;
}

GenericValue executeCmpInst(
		unsigned predicate,
		GenericValue Src1,
		GenericValue Src2,
		Type *Ty)
{
	GenericValue Result;
	switch (predicate)
	{
		case ICmpInst::ICMP_EQ:    return executeICMP_EQ(Src1, Src2, Ty);
		case ICmpInst::ICMP_NE:    return executeICMP_NE(Src1, Src2, Ty);
		case ICmpInst::ICMP_UGT:   return executeICMP_UGT(Src1, Src2, Ty);
		case ICmpInst::ICMP_SGT:   return executeICMP_SGT(Src1, Src2, Ty);
		case ICmpInst::ICMP_ULT:   return executeICMP_ULT(Src1, Src2, Ty);
		case ICmpInst::ICMP_SLT:   return executeICMP_SLT(Src1, Src2, Ty);
		case ICmpInst::ICMP_UGE:   return executeICMP_UGE(Src1, Src2, Ty);
		case ICmpInst::ICMP_SGE:   return executeICMP_SGE(Src1, Src2, Ty);
		case ICmpInst::ICMP_ULE:   return executeICMP_ULE(Src1, Src2, Ty);
		case ICmpInst::ICMP_SLE:   return executeICMP_SLE(Src1, Src2, Ty);
		case FCmpInst::FCMP_ORD:   return executeFCMP_ORD(Src1, Src2, Ty);
		case FCmpInst::FCMP_UNO:   return executeFCMP_UNO(Src1, Src2, Ty);
		case FCmpInst::FCMP_OEQ:   return executeFCMP_OEQ(Src1, Src2, Ty);
		case FCmpInst::FCMP_UEQ:   return executeFCMP_UEQ(Src1, Src2, Ty);
		case FCmpInst::FCMP_ONE:   return executeFCMP_ONE(Src1, Src2, Ty);
		case FCmpInst::FCMP_UNE:   return executeFCMP_UNE(Src1, Src2, Ty);
		case FCmpInst::FCMP_OLT:   return executeFCMP_OLT(Src1, Src2, Ty);
		case FCmpInst::FCMP_ULT:   return executeFCMP_ULT(Src1, Src2, Ty);
		case FCmpInst::FCMP_OGT:   return executeFCMP_OGT(Src1, Src2, Ty);
		case FCmpInst::FCMP_UGT:   return executeFCMP_UGT(Src1, Src2, Ty);
		case FCmpInst::FCMP_OLE:   return executeFCMP_OLE(Src1, Src2, Ty);
		case FCmpInst::FCMP_ULE:   return executeFCMP_ULE(Src1, Src2, Ty);
		case FCmpInst::FCMP_OGE:   return executeFCMP_OGE(Src1, Src2, Ty);
		case FCmpInst::FCMP_UGE:   return executeFCMP_UGE(Src1, Src2, Ty);
		case FCmpInst::FCMP_FALSE: return executeFCMP_BOOL(Src1, Src2, Ty, false);
		case FCmpInst::FCMP_TRUE:  return executeFCMP_BOOL(Src1, Src2, Ty, true);
		default:
			dbgs() << "Unhandled Cmp predicate\n";
			llvm_unreachable(nullptr);
	}
	return Result;
}

//
//=============================================================================
// Ternary Instruction Implementations
//=============================================================================
//

GenericValue executeSelectInst(
		GenericValue Src1,
		GenericValue Src2,
		GenericValue Src3,
		Type *Ty)
{
	GenericValue Dest;
	if(Ty->isVectorTy())
	{
		assert(Src1.AggregateVal.size() == Src2.AggregateVal.size());
		assert(Src2.AggregateVal.size() == Src3.AggregateVal.size());
		Dest.AggregateVal.resize( Src1.AggregateVal.size() );
		for (size_t i = 0; i < Src1.AggregateVal.size(); ++i)
			Dest.AggregateVal[i] = (Src1.AggregateVal[i].IntVal == 0) ?
					Src3.AggregateVal[i] : Src2.AggregateVal[i];
	}
	else
	{
		Dest = (Src1.IntVal == 0) ? Src3 : Src2;
	}
	return Dest;
}

//
//=============================================================================
// Terminator Instruction Implementations
//=============================================================================
//

// switchToNewBasicBlock - This method is used to jump to a new basic block.
// This function handles the actual updating of block and instruction iterators
// as well as execution of all of the PHI nodes in the destination block.
//
// This method does this because all of the PHI nodes must be executed
// atomically, reading their inputs before any of the results are updated.  Not
// doing this can cause problems if the PHI nodes depend on other PHI nodes for
// their inputs.  If the input PHI node is updated before it is read, incorrect
// results can happen.  Thus we use a two phase approach.
//
void switchToNewBasicBlock(
		BasicBlock* Dest,
		LocalExecutionContext& SF,
		GlobalExecutionContext& GC)
{
	BasicBlock *PrevBB = SF.curBB;      // Remember where we came from...
	SF.curBB   = Dest;                  // Update CurBB to branch destination
	SF.curInst = SF.curBB->begin();     // Update new instruction ptr...

	if (!isa<PHINode>(SF.curInst))
	{
		return;  // Nothing fancy to do
	}

	// Loop over all of the PHI nodes in the current block, reading their inputs.
	std::vector<GenericValue> ResultValues;

	for (; PHINode *PN = dyn_cast<PHINode>(SF.curInst); ++SF.curInst)
	{
		// Search for the value corresponding to this previous bb...
		int i = PN->getBasicBlockIndex(PrevBB);
		assert(i != -1 && "PHINode doesn't contain entry for predecessor??");
		Value *IncomingValue = PN->getIncomingValue(i);

		// Save the incoming value for this PHI node...
		ResultValues.push_back(GC.getOperandValue(IncomingValue, SF));
	}

	// Now loop over all of the PHI nodes setting their values...
	SF.curInst = SF.curBB->begin();
	for (unsigned i = 0; isa<PHINode>(SF.curInst); ++SF.curInst, ++i)
	{
		PHINode *PN = cast<PHINode>(SF.curInst);
		GC.setValue(PN, ResultValues[i]);
	}
}

//
//=============================================================================
// Memory Instruction Implementations
//=============================================================================
//

/**
 * getElementOffset - The workhorse for getelementptr.
 */
GenericValue executeGEPOperation(
		Value *Ptr,
		gep_type_iterator I,
		gep_type_iterator E,
		LocalExecutionContext& SF,
		GlobalExecutionContext& GC)
{
	assert(Ptr->getType()->isPointerTy()
			&& "Cannot getElementOffset of a nonpointer type!");

	auto& DL = GC.getModule()->getDataLayout();

	uint64_t Total = 0;

	for (; I != E; ++I)
	{
		if (StructType *STy = dyn_cast<StructType>(*I))
		{
			const StructLayout *SLO = DL.getStructLayout(STy);

			const ConstantInt *CPU = cast<ConstantInt>(I.getOperand());
			unsigned Index = unsigned(CPU->getZExtValue());

			Total += SLO->getElementOffset(Index);
		}
		else
		{
			SequentialType *ST = cast<SequentialType>(*I);
			// Get the index number for the array... which must be long type...
			GenericValue IdxGV = GC.getOperandValue(I.getOperand(), SF);

			int64_t Idx;
			unsigned BitWidth = cast<IntegerType>(
					I.getOperand()->getType())->getBitWidth();
			if (BitWidth == 32)
			{
				Idx = static_cast<int64_t>(static_cast<int32_t>(IdxGV.IntVal.getZExtValue()));
			}
			else
			{
				assert(BitWidth == 64 && "Invalid index type for getelementptr");
				Idx = static_cast<int64_t>(IdxGV.IntVal.getZExtValue());
			}
			Total += DL.getTypeAllocSize(ST->getElementType()) * Idx;
		}
	}

	GenericValue Result;
	Result.PointerVal = static_cast<char*>(GC.getOperandValue(Ptr, SF).PointerVal) + Total;
	return Result;
}

//
//=============================================================================
// Conversion Instruction Implementations
//=============================================================================
//

GenericValue executeTruncInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);
	Type *SrcTy = SrcVal->getType();
	if (SrcTy->isVectorTy())
	{
		Type *DstVecTy = DstTy->getScalarType();
		unsigned DBitWidth = cast<IntegerType>(DstVecTy)->getBitWidth();
		unsigned NumElts = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal
		Dest.AggregateVal.resize(NumElts);
		for (unsigned i = 0; i < NumElts; i++)
			Dest.AggregateVal[i].IntVal = Src.AggregateVal[i].IntVal.trunc(DBitWidth);
	}
	else
	{
		IntegerType *DITy = cast<IntegerType>(DstTy);
		unsigned DBitWidth = DITy->getBitWidth();
		Dest.IntVal = Src.IntVal.trunc(DBitWidth);
	}
	return Dest;
}

GenericValue executeSExtInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	Type *SrcTy = SrcVal->getType();
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);
	if (SrcTy->isVectorTy())
	{
		Type *DstVecTy = DstTy->getScalarType();
		unsigned DBitWidth = cast<IntegerType>(DstVecTy)->getBitWidth();
		unsigned size = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal.
		Dest.AggregateVal.resize(size);
		for (unsigned i = 0; i < size; i++)
			Dest.AggregateVal[i].IntVal = Src.AggregateVal[i].IntVal.sext(DBitWidth);
	}
	else
	{
		auto *DITy = cast<IntegerType>(DstTy);
		unsigned DBitWidth = DITy->getBitWidth();
		Dest.IntVal = Src.IntVal.sext(DBitWidth);
	}
	return Dest;
}

GenericValue executeZExtInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	Type *SrcTy = SrcVal->getType();
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);
	if (SrcTy->isVectorTy())
	{
		Type *DstVecTy = DstTy->getScalarType();
		unsigned DBitWidth = cast<IntegerType>(DstVecTy)->getBitWidth();

		unsigned size = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal.
		Dest.AggregateVal.resize(size);
		for (unsigned i = 0; i < size; i++)
			Dest.AggregateVal[i].IntVal = Src.AggregateVal[i].IntVal.zext(DBitWidth);
	}
	else
	{
		auto *DITy = cast<IntegerType>(DstTy);
		unsigned DBitWidth = DITy->getBitWidth();
		Dest.IntVal = Src.IntVal.zextOrTrunc(DBitWidth);
	}
	return Dest;
}

GenericValue executeFPTruncInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);

	if (SrcVal->getType()->getTypeID() == Type::VectorTyID)
	{
		assert(SrcVal->getType()->getScalarType()->isDoubleTy() &&
				DstTy->getScalarType()->isFloatTy() &&
				"Invalid FPTrunc instruction");

		unsigned size = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal.
		Dest.AggregateVal.resize(size);
		for (unsigned i = 0; i < size; i++)
		{
			Dest.AggregateVal[i].FloatVal = static_cast<float>(Src.AggregateVal[i].DoubleVal);
		}
	}
	else if (SrcVal->getType()->isDoubleTy() && DstTy->isFloatTy())
	{
		Dest.FloatVal = static_cast<float>(Src.DoubleVal);
	}
	else if (SrcVal->getType()->isX86_FP80Ty() && DstTy->isDoubleTy())
	{
		Dest.DoubleVal = Src.DoubleVal;
	}
	else
	{
		assert(false && "some other type combo");
	}

	return Dest;
}

GenericValue executeFPExtInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);

	if (SrcVal->getType()->getTypeID() == Type::VectorTyID)
	{
		assert(SrcVal->getType()->getScalarType()->isFloatTy() &&
				DstTy->getScalarType()->isDoubleTy() && "Invalid FPExt instruction");

		unsigned size = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal.
		Dest.AggregateVal.resize(size);
		for (unsigned i = 0; i < size; i++)
			Dest.AggregateVal[i].DoubleVal = static_cast<double>(Src.AggregateVal[i].FloatVal);
	}
	else if (SrcVal->getType()->isFloatTy() && DstTy->isDoubleTy())
	{
		Dest.DoubleVal = static_cast<double>(Src.FloatVal);
	}
	else if (SrcVal->getType()->isDoubleTy() && DstTy->isX86_FP80Ty())
	{
		Dest.DoubleVal = Src.DoubleVal;
	}
	else
	{
		assert(false && "some other type combo");
	}

	return Dest;
}

GenericValue executeFPToUIInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	Type *SrcTy = SrcVal->getType();
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);

	if (SrcTy->getTypeID() == Type::VectorTyID)
	{
		Type *DstVecTy = DstTy->getScalarType();
		Type *SrcVecTy = SrcTy->getScalarType();
		uint32_t DBitWidth = cast<IntegerType>(DstVecTy)->getBitWidth();
		unsigned size = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal.
		Dest.AggregateVal.resize(size);

		if (SrcVecTy->getTypeID() == Type::FloatTyID)
		{
			assert(SrcVecTy->isFloatingPointTy() && "Invalid FPToUI instruction");
			for (unsigned i = 0; i < size; i++)
				Dest.AggregateVal[i].IntVal = APIntOps::RoundFloatToAPInt(
						Src.AggregateVal[i].FloatVal, DBitWidth);
		}
		else
		{
			for (unsigned i = 0; i < size; i++)
				Dest.AggregateVal[i].IntVal = APIntOps::RoundDoubleToAPInt(
						Src.AggregateVal[i].DoubleVal, DBitWidth);
		}
	}
	else
	{
		// scalar
		uint32_t DBitWidth = cast<IntegerType>(DstTy)->getBitWidth();
		assert(SrcTy->isFloatingPointTy() && "Invalid FPToUI instruction");

		if (SrcTy->getTypeID() == Type::FloatTyID)
		{
			Dest.IntVal = APIntOps::RoundFloatToAPInt(Src.FloatVal, DBitWidth);
		}
		else
		{
			Dest.IntVal = APIntOps::RoundDoubleToAPInt(Src.DoubleVal, DBitWidth);
		}
	}

	return Dest;
}

GenericValue executeFPToSIInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	Type *SrcTy = SrcVal->getType();
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);

	if (SrcTy->getTypeID() == Type::VectorTyID)
	{
		Type *DstVecTy = DstTy->getScalarType();
		Type *SrcVecTy = SrcTy->getScalarType();
		uint32_t DBitWidth = cast<IntegerType>(DstVecTy)->getBitWidth();
		unsigned size = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal
		Dest.AggregateVal.resize(size);

		if (SrcVecTy->getTypeID() == Type::FloatTyID)
		{
			assert(SrcVecTy->isFloatingPointTy() && "Invalid FPToSI instruction");
			for (unsigned i = 0; i < size; i++)
				Dest.AggregateVal[i].IntVal = APIntOps::RoundFloatToAPInt(
						Src.AggregateVal[i].FloatVal, DBitWidth);
		}
		else
		{
			for (unsigned i = 0; i < size; i++)
				Dest.AggregateVal[i].IntVal = APIntOps::RoundDoubleToAPInt(
						Src.AggregateVal[i].DoubleVal, DBitWidth);
		}
	}
	else
	{
		// scalar
		unsigned DBitWidth = cast<IntegerType>(DstTy)->getBitWidth();
		assert(SrcTy->isFloatingPointTy() && "Invalid FPToSI instruction");

		if (SrcTy->getTypeID() == Type::FloatTyID)
		{
			Dest.IntVal = APIntOps::RoundFloatToAPInt(Src.FloatVal, DBitWidth);
		}
		else
		{
			Dest.IntVal = APIntOps::RoundDoubleToAPInt(Src.DoubleVal, DBitWidth);
		}
	}
	return Dest;
}

GenericValue executeUIToFPInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);

	if (SrcVal->getType()->getTypeID() == Type::VectorTyID)
	{
		Type *DstVecTy = DstTy->getScalarType();
		unsigned size = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal
		Dest.AggregateVal.resize(size);

		if (DstVecTy->getTypeID() == Type::FloatTyID)
		{
			assert(DstVecTy->isFloatingPointTy()
					&& "Invalid UIToFP instruction");
			for (unsigned i = 0; i < size; i++)
				Dest.AggregateVal[i].FloatVal = APIntOps::RoundAPIntToFloat(
						Src.AggregateVal[i].IntVal);
		}
		else
		{
			for (unsigned i = 0; i < size; i++)
				Dest.AggregateVal[i].DoubleVal = APIntOps::RoundAPIntToDouble(
						Src.AggregateVal[i].IntVal);
		}
	}
	else
	{
		// scalar
		assert(DstTy->isFloatingPointTy() && "Invalid UIToFP instruction");
		if (DstTy->getTypeID() == Type::FloatTyID)
		{
			Dest.FloatVal = APIntOps::RoundAPIntToFloat(Src.IntVal);
		}
		else
		{
			Dest.DoubleVal = APIntOps::RoundAPIntToDouble(Src.IntVal);
		}
	}
	return Dest;
}

GenericValue executeSIToFPInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);

	if (SrcVal->getType()->getTypeID() == Type::VectorTyID)
	{
		Type *DstVecTy = DstTy->getScalarType();
		unsigned size = Src.AggregateVal.size();
		// the sizes of src and dst vectors must be equal
		Dest.AggregateVal.resize(size);

		if (DstVecTy->getTypeID() == Type::FloatTyID)
		{
			assert(DstVecTy->isFloatingPointTy() && "Invalid SIToFP instruction");
			for (unsigned i = 0; i < size; i++)
				Dest.AggregateVal[i].FloatVal =
						APIntOps::RoundSignedAPIntToFloat(Src.AggregateVal[i].IntVal);
		}
		else
		{
			for (unsigned i = 0; i < size; i++)
				Dest.AggregateVal[i].DoubleVal =
						APIntOps::RoundSignedAPIntToDouble(Src.AggregateVal[i].IntVal);
		}
	}
	else
	{
		// scalar
		assert(DstTy->isFloatingPointTy() && "Invalid SIToFP instruction");

		if (DstTy->getTypeID() == Type::FloatTyID)
		{
			Dest.FloatVal = APIntOps::RoundSignedAPIntToFloat(Src.IntVal);
		}
		else
		{
			Dest.DoubleVal = APIntOps::RoundSignedAPIntToDouble(Src.IntVal);
		}
	}

	return Dest;
}

GenericValue executePtrToIntInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	uint32_t DBitWidth = cast<IntegerType>(DstTy)->getBitWidth();
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);
	assert(SrcVal->getType()->isPointerTy() && "Invalid PtrToInt instruction");

	Dest.IntVal = APInt(DBitWidth, reinterpret_cast<intptr_t>(Src.PointerVal));
	return Dest;
}

GenericValue executeIntToPtrInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);
	assert(DstTy->isPointerTy() && "Invalid PtrToInt instruction");

	uint32_t PtrSize = SF.getModule()->getDataLayout().getPointerSizeInBits();
	if (PtrSize != Src.IntVal.getBitWidth())
	{
		Src.IntVal = Src.IntVal.zextOrTrunc(PtrSize);
	}

	Dest.PointerVal = PointerTy(static_cast<intptr_t>(Src.IntVal.getZExtValue()));
	return Dest;
}

GenericValue executeBitCastInst(
		Value *SrcVal,
		Type *DstTy,
		LocalExecutionContext &SF,
		GlobalExecutionContext& GC)
{
	// This instruction supports bitwise conversion of vectors to integers and
	// to vectors of other types (as long as they have the same size)
	Type *SrcTy = SrcVal->getType();
	GenericValue Dest, Src = GC.getOperandValue(SrcVal, SF);

	if ((SrcTy->getTypeID() == Type::VectorTyID)
			|| (DstTy->getTypeID() == Type::VectorTyID))
	{
		// vector src bitcast to vector dst or vector src bitcast to scalar dst or
		// scalar src bitcast to vector dst
		bool isLittleEndian = SF.getModule()->getDataLayout().isLittleEndian();
		GenericValue TempDst, TempSrc, SrcVec;
		Type *SrcElemTy;
		Type *DstElemTy;
		unsigned SrcBitSize;
		unsigned DstBitSize;
		unsigned SrcNum;
		unsigned DstNum;

		if (SrcTy->getTypeID() == Type::VectorTyID)
		{
			SrcElemTy = SrcTy->getScalarType();
			SrcBitSize = SrcTy->getScalarSizeInBits();
			SrcNum = Src.AggregateVal.size();
			SrcVec = Src;
		}
		else
		{
			// if src is scalar value, make it vector <1 x type>
			SrcElemTy = SrcTy;
			SrcBitSize = SrcTy->getPrimitiveSizeInBits();
			SrcNum = 1;
			SrcVec.AggregateVal.push_back(Src);
		}

		if (DstTy->getTypeID() == Type::VectorTyID)
		{
			DstElemTy = DstTy->getScalarType();
			DstBitSize = DstTy->getScalarSizeInBits();
			DstNum = (SrcNum * SrcBitSize) / DstBitSize;
		}
		else
		{
			DstElemTy = DstTy;
			DstBitSize = DstTy->getPrimitiveSizeInBits();
			DstNum = 1;
		}

		if (SrcNum * SrcBitSize != DstNum * DstBitSize)
			llvm_unreachable("Invalid BitCast");

		// If src is floating point, cast to integer first.
		TempSrc.AggregateVal.resize(SrcNum);
		if (SrcElemTy->isFloatTy())
		{
			for (unsigned i = 0; i < SrcNum; i++)
				TempSrc.AggregateVal[i].IntVal = APInt::floatToBits(
				        SrcVec.AggregateVal[i].FloatVal);

		}
		else if (SrcElemTy->isDoubleTy() || SrcElemTy->isX86_FP80Ty())
		{
			for (unsigned i = 0; i < SrcNum; i++)
				TempSrc.AggregateVal[i].IntVal = APInt::doubleToBits(
				        SrcVec.AggregateVal[i].DoubleVal);
		}
		else if (SrcElemTy->isIntegerTy())
		{
			for (unsigned i = 0; i < SrcNum; i++)
				TempSrc.AggregateVal[i].IntVal = SrcVec.AggregateVal[i].IntVal;
		}
		else
		{
			// Pointers are not allowed as the element type of vector.
			llvm_unreachable("Invalid Bitcast");
		}

		// now TempSrc is integer type vector
		if (DstNum < SrcNum)
		{
			// Example: bitcast <4 x i32> <i32 0, i32 1, i32 2, i32 3> to <2 x i64>
			unsigned Ratio = SrcNum / DstNum;
			unsigned SrcElt = 0;
			for (unsigned i = 0; i < DstNum; i++)
			{
				GenericValue Elt;
				Elt.IntVal = 0;
				Elt.IntVal = Elt.IntVal.zext(DstBitSize);
				unsigned ShiftAmt =
				        isLittleEndian ? 0 : SrcBitSize * (Ratio - 1);
				for (unsigned j = 0; j < Ratio; j++)
				{
					APInt Tmp;
					Tmp = Tmp.zext(SrcBitSize);
					Tmp = TempSrc.AggregateVal[SrcElt++].IntVal;
					Tmp = Tmp.zext(DstBitSize);
					Tmp = Tmp.shl(ShiftAmt);
					ShiftAmt += isLittleEndian ? SrcBitSize : -SrcBitSize;
					Elt.IntVal |= Tmp;
				}
				TempDst.AggregateVal.push_back(Elt);
			}
		}
		else
		{
			// Example: bitcast <2 x i64> <i64 0, i64 1> to <4 x i32>
			unsigned Ratio = DstNum / SrcNum;
			for (unsigned i = 0; i < SrcNum; i++)
			{
				unsigned ShiftAmt =
				        isLittleEndian ? 0 : DstBitSize * (Ratio - 1);
				for (unsigned j = 0; j < Ratio; j++)
				{
					GenericValue Elt;
					Elt.IntVal = Elt.IntVal.zext(SrcBitSize);
					Elt.IntVal = TempSrc.AggregateVal[i].IntVal;
					Elt.IntVal = Elt.IntVal.lshr(ShiftAmt);
					// it could be DstBitSize == SrcBitSize, so check it
					if (DstBitSize < SrcBitSize)
						Elt.IntVal = Elt.IntVal.trunc(DstBitSize);
					ShiftAmt += isLittleEndian ? DstBitSize : -DstBitSize;
					TempDst.AggregateVal.push_back(Elt);
				}
			}
		}

		// convert result from integer to specified type
		if (DstTy->getTypeID() == Type::VectorTyID)
		{
			if (DstElemTy->isDoubleTy())
			{
				Dest.AggregateVal.resize(DstNum);
				for (unsigned i = 0; i < DstNum; i++)
					Dest.AggregateVal[i].DoubleVal =
					        TempDst.AggregateVal[i].IntVal.bitsToDouble();
			}
			else if (DstElemTy->isFloatTy())
			{
				Dest.AggregateVal.resize(DstNum);
				for (unsigned i = 0; i < DstNum; i++)
					Dest.AggregateVal[i].FloatVal =
					        TempDst.AggregateVal[i].IntVal.bitsToFloat();
			}
			else
			{
				Dest = TempDst;
			}
		}
		else
		{
			if (DstElemTy->isDoubleTy())
				Dest.DoubleVal = TempDst.AggregateVal[0].IntVal.bitsToDouble();
			else if (DstElemTy->isFloatTy())
			{
				Dest.FloatVal = TempDst.AggregateVal[0].IntVal.bitsToFloat();
			}
			else
			{
				Dest.IntVal = TempDst.AggregateVal[0].IntVal;
			}
		}
	}
	else
	{ //  if ((SrcTy->getTypeID() == Type::VectorTyID) ||
		//     (DstTy->getTypeID() == Type::VectorTyID))

		// scalar src bitcast to scalar dst
		if (DstTy->isPointerTy())
		{
			assert(SrcTy->isPointerTy() && "Invalid BitCast");
			Dest.PointerVal = Src.PointerVal;
		}
		else if (DstTy->isIntegerTy())
		{
			if (SrcTy->isFloatTy())
				Dest.IntVal = APInt::floatToBits(Src.FloatVal);
			else if (SrcTy->isDoubleTy())
			{
				Dest.IntVal = APInt::doubleToBits(Src.DoubleVal);
			}
			else if (SrcTy->isIntegerTy())
			{
				Dest.IntVal = Src.IntVal;
			}
			else
			{
				llvm_unreachable("Invalid BitCast");
			}
		}
		else if (DstTy->isFloatTy())
		{
			if (SrcTy->isIntegerTy())
				Dest.FloatVal = Src.IntVal.bitsToFloat();
			else
			{
				Dest.FloatVal = Src.FloatVal;
			}
		}
		else if (DstTy->isDoubleTy())
		{
			if (SrcTy->isIntegerTy())
				Dest.DoubleVal = Src.IntVal.bitsToDouble();
			else
			{
				Dest.DoubleVal = Src.DoubleVal;
			}
		}
		else
		{
			llvm_unreachable("Invalid Bitcast");
		}
	}

	return Dest;
}

//
//=============================================================================
// Misc
//=============================================================================
//

llvm::GenericValue getConstantExprValue(
		llvm::ConstantExpr* CE,
		LocalExecutionContext& SF,
		GlobalExecutionContext& GC)
{
	switch (CE->getOpcode())
	{
		case Instruction::Trunc:
			return executeTruncInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::ZExt:
			return executeZExtInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::SExt:
			return executeSExtInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::FPTrunc:
			return executeFPTruncInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::FPExt:
			return executeFPExtInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::UIToFP:
			return executeUIToFPInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::SIToFP:
			return executeSIToFPInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::FPToUI:
			return executeFPToUIInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::FPToSI:
			return executeFPToSIInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::PtrToInt:
			return executePtrToIntInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::IntToPtr:
			return executeIntToPtrInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::BitCast:
			return executeBitCastInst(CE->getOperand(0), CE->getType(), SF, GC);
		case Instruction::GetElementPtr:
			return executeGEPOperation(CE->getOperand(0), gep_type_begin(CE),
					gep_type_end(CE), SF, GC);
		case Instruction::FCmp:
		case Instruction::ICmp:
			return executeCmpInst(
					CE->getPredicate(),
					GC.getOperandValue(CE->getOperand(0), SF),
					GC.getOperandValue(CE->getOperand(1), SF),
					CE->getOperand(0)->getType());
		case Instruction::Select:
			return executeSelectInst(
					GC.getOperandValue(CE->getOperand(0), SF),
					GC.getOperandValue(CE->getOperand(1), SF),
					GC.getOperandValue(CE->getOperand(2), SF),
					CE->getOperand(0)->getType());
		default :
			break;
	}

	// The cases below here require a GenericValue parameter for the result
	// so we initialize one, compute it and then return it.
	GenericValue Op0 = GC.getOperandValue(CE->getOperand(0), SF);
	GenericValue Op1 = GC.getOperandValue(CE->getOperand(1), SF);
	GenericValue Dest;
	Type * Ty = CE->getOperand(0)->getType();
	switch (CE->getOpcode())
	{
		case Instruction::Add:  Dest.IntVal = Op0.IntVal + Op1.IntVal; break;
		case Instruction::Sub:  Dest.IntVal = Op0.IntVal - Op1.IntVal; break;
		case Instruction::Mul:  Dest.IntVal = Op0.IntVal * Op1.IntVal; break;
		case Instruction::FAdd: executeFAddInst(Dest, Op0, Op1, Ty); break;
		case Instruction::FSub: executeFSubInst(Dest, Op0, Op1, Ty); break;
		case Instruction::FMul: executeFMulInst(Dest, Op0, Op1, Ty); break;
		case Instruction::FDiv: executeFDivInst(Dest, Op0, Op1, Ty); break;
		case Instruction::FRem: executeFRemInst(Dest, Op0, Op1, Ty); break;
		case Instruction::SDiv: Dest.IntVal = Op0.IntVal.sdiv(Op1.IntVal); break;
		case Instruction::UDiv: Dest.IntVal = Op0.IntVal.udiv(Op1.IntVal); break;
		case Instruction::URem: Dest.IntVal = Op0.IntVal.urem(Op1.IntVal); break;
		case Instruction::SRem: Dest.IntVal = Op0.IntVal.srem(Op1.IntVal); break;
		case Instruction::And:  Dest.IntVal = Op0.IntVal & Op1.IntVal; break;
		case Instruction::Or:   Dest.IntVal = Op0.IntVal | Op1.IntVal; break;
		case Instruction::Xor:  Dest.IntVal = Op0.IntVal ^ Op1.IntVal; break;
		case Instruction::Shl:
			Dest.IntVal = Op0.IntVal.shl(Op1.IntVal.getZExtValue());
			break;
		case Instruction::LShr:
			Dest.IntVal = Op0.IntVal.lshr(Op1.IntVal.getZExtValue());
			break;
		case Instruction::AShr:
			Dest.IntVal = Op0.IntVal.ashr(Op1.IntVal.getZExtValue());
			break;
		default:
			dbgs() << "Unhandled ConstantExpr: " << *CE << "\n";
			llvm_unreachable("Unhandled ConstantExpr");
	}
	return Dest;
}

/**
 * Converts a Constant* into a GenericValue, including handling of
 * ConstantExpr values.
 * Taken from ExecutionEngine/ExecutionEngine.cpp
 */
llvm::GenericValue getConstantValue(const llvm::Constant* C, llvm::Module* m)
{
	auto& DL = m->getDataLayout();

	// If its undefined, return the garbage.
	if (isa<UndefValue>(C))
	{
		GenericValue Result;
		switch (C->getType()->getTypeID())
		{
			default:
				break;
			case Type::IntegerTyID:
			case Type::X86_FP80TyID:
			case Type::FP128TyID:
			case Type::PPC_FP128TyID:
				// Although the value is undefined, we still have to construct an APInt
				// with the correct bit width.
				Result.IntVal = APInt(C->getType()->getPrimitiveSizeInBits(), 0);
				break;
			case Type::StructTyID:
			{
				// if the whole struct is 'undef' just reserve memory for the value.
				if(StructType *STy = dyn_cast<StructType>(C->getType()))
				{
					unsigned int elemNum = STy->getNumElements();
					Result.AggregateVal.resize(elemNum);
					for (unsigned int i = 0; i < elemNum; ++i)
					{
						Type *ElemTy = STy->getElementType(i);
						if (ElemTy->isIntegerTy())
						{
							Result.AggregateVal[i].IntVal =
									APInt(ElemTy->getPrimitiveSizeInBits(), 0);
						}
						else if (ElemTy->isAggregateType())
						{
							const Constant *ElemUndef = UndefValue::get(ElemTy);
							Result.AggregateVal[i] = getConstantValue(ElemUndef, m);
						}
					}
				}
				break;
			}
			case Type::VectorTyID:
				// if the whole vector is 'undef' just reserve memory for the value.
				auto* VTy = dyn_cast<VectorType>(C->getType());
				Type *ElemTy = VTy->getElementType();
				unsigned int elemNum = VTy->getNumElements();
				Result.AggregateVal.resize(elemNum);
				if (ElemTy->isIntegerTy())
					for (unsigned int i = 0; i < elemNum; ++i)
						Result.AggregateVal[i].IntVal =
								APInt(ElemTy->getPrimitiveSizeInBits(), 0);
				break;
		}
		return Result;
	}

	// Otherwise, if the value is a ConstantExpr...
	if (const ConstantExpr *CE = dyn_cast<ConstantExpr>(C))
	{
		Constant *Op0 = CE->getOperand(0);
		switch (CE->getOpcode())
		{
			case Instruction::GetElementPtr:
			{
				// Compute the index
				GenericValue Result = getConstantValue(Op0, m);
				APInt Offset(DL.getPointerSizeInBits(), 0);
				cast<GEPOperator>(CE)->accumulateConstantOffset(DL, Offset);

				char* tmp = static_cast<char*>(Result.PointerVal);
				Result = PTOGV(tmp + Offset.getSExtValue());
				return Result;
			}
			case Instruction::Trunc:
			{
				GenericValue GV = getConstantValue(Op0, m);
				uint32_t BitWidth = cast<IntegerType>(CE->getType())->getBitWidth();
				GV.IntVal = GV.IntVal.trunc(BitWidth);
				return GV;
			}
			case Instruction::ZExt:
			{
				GenericValue GV = getConstantValue(Op0, m);
				uint32_t BitWidth = cast<IntegerType>(CE->getType())->getBitWidth();
				GV.IntVal = GV.IntVal.zext(BitWidth);
				return GV;
			}
			case Instruction::SExt:
			{
				GenericValue GV = getConstantValue(Op0, m);
				uint32_t BitWidth = cast<IntegerType>(CE->getType())->getBitWidth();
				GV.IntVal = GV.IntVal.sext(BitWidth);
				return GV;
			}
			case Instruction::FPTrunc:
			{
				GenericValue GV = getConstantValue(Op0, m);
				GV.FloatVal = float(GV.DoubleVal);
				return GV;
			}
			case Instruction::FPExt:
			{
				GenericValue GV = getConstantValue(Op0, m);
				GV.DoubleVal = double(GV.FloatVal);
				return GV;
			}
			case Instruction::UIToFP:
			{
				GenericValue GV = getConstantValue(Op0, m);
				if (CE->getType()->isFloatTy())
					GV.FloatVal = float(GV.IntVal.roundToDouble());
				else if (CE->getType()->isDoubleTy() || CE->getType()->isX86_FP80Ty())
					GV.DoubleVal = GV.IntVal.roundToDouble();
				else if (CE->getType()->isX86_FP80Ty())
				{
					APFloat apf = APFloat::getZero(APFloat::x87DoubleExtended);
					(void)apf.convertFromAPInt(GV.IntVal,
							false,
							APFloat::rmNearestTiesToEven);
					GV.IntVal = apf.bitcastToAPInt();
				}
				return GV;
			}
			case Instruction::SIToFP:
			{
				GenericValue GV = getConstantValue(Op0, m);
				if (CE->getType()->isFloatTy())
					GV.FloatVal = float(GV.IntVal.signedRoundToDouble());
				else if (CE->getType()->isDoubleTy() || CE->getType()->isX86_FP80Ty())
					GV.DoubleVal = GV.IntVal.signedRoundToDouble();
				else if (CE->getType()->isX86_FP80Ty())
				{
					APFloat apf = APFloat::getZero(APFloat::x87DoubleExtended);
					(void)apf.convertFromAPInt(GV.IntVal,
							true,
							APFloat::rmNearestTiesToEven);
					GV.IntVal = apf.bitcastToAPInt();
				}
				return GV;
			}
			case Instruction::FPToUI: // double->APInt conversion handles sign
			case Instruction::FPToSI:
			{
				GenericValue GV = getConstantValue(Op0, m);
				uint32_t BitWidth = cast<IntegerType>(CE->getType())->getBitWidth();
				if (Op0->getType()->isFloatTy())
					GV.IntVal = APIntOps::RoundFloatToAPInt(GV.FloatVal, BitWidth);
				else if (Op0->getType()->isDoubleTy() || CE->getType()->isX86_FP80Ty())
					GV.IntVal = APIntOps::RoundDoubleToAPInt(GV.DoubleVal, BitWidth);
				else if (Op0->getType()->isX86_FP80Ty())
				{
					APFloat apf = APFloat(APFloat::x87DoubleExtended, GV.IntVal);
					uint64_t v;
					bool ignored;
					(void)apf.convertToInteger(&v, BitWidth,
							CE->getOpcode()==Instruction::FPToSI,
							APFloat::rmTowardZero, &ignored);
					GV.IntVal = v; // endian?
				}
				return GV;
			}
			case Instruction::PtrToInt:
			{
				GenericValue GV = getConstantValue(Op0, m);
				uint32_t PtrWidth = DL.getTypeSizeInBits(Op0->getType());
				assert(PtrWidth <= 64 && "Bad pointer width");
				GV.IntVal = APInt(PtrWidth, uintptr_t(GV.PointerVal));
				uint32_t IntWidth = DL.getTypeSizeInBits(CE->getType());
				GV.IntVal = GV.IntVal.zextOrTrunc(IntWidth);
				return GV;
			}
			case Instruction::IntToPtr:
			{
				GenericValue GV = getConstantValue(Op0, m);
				uint32_t PtrWidth = DL.getTypeSizeInBits(CE->getType());
				GV.IntVal = GV.IntVal.zextOrTrunc(PtrWidth);
				assert(GV.IntVal.getBitWidth() <= 64 && "Bad pointer width");
				GV.PointerVal = PointerTy(uintptr_t(GV.IntVal.getZExtValue()));
				return GV;
			}
			case Instruction::BitCast:
			{
				GenericValue GV = getConstantValue(Op0, m);
				Type* DestTy = CE->getType();
				switch (Op0->getType()->getTypeID())
				{
					default:
						llvm_unreachable("Invalid bitcast operand");
					case Type::IntegerTyID:
						assert(DestTy->isFloatingPointTy() && "invalid bitcast");
						if (DestTy->isFloatTy())
							GV.FloatVal = GV.IntVal.bitsToFloat();
						else if (DestTy->isDoubleTy())
							GV.DoubleVal = GV.IntVal.bitsToDouble();
						break;
					case Type::FloatTyID:
						assert(DestTy->isIntegerTy(32) && "Invalid bitcast");
						GV.IntVal = APInt::floatToBits(GV.FloatVal);
						break;
					case Type::DoubleTyID:
						assert(DestTy->isIntegerTy(64) && "Invalid bitcast");
						GV.IntVal = APInt::doubleToBits(GV.DoubleVal);
						break;
					case Type::PointerTyID:
						assert(DestTy->isPointerTy() && "Invalid bitcast");
						break; // getConstantValue(Op0)  above already converted it
				}
				return GV;
			}
			case Instruction::Add:
			case Instruction::FAdd:
			case Instruction::Sub:
			case Instruction::FSub:
			case Instruction::Mul:
			case Instruction::FMul:
			case Instruction::UDiv:
			case Instruction::SDiv:
			case Instruction::URem:
			case Instruction::SRem:
			case Instruction::And:
			case Instruction::Or:
			case Instruction::Xor:
			{
				GenericValue LHS = getConstantValue(Op0, m);
				GenericValue RHS = getConstantValue(CE->getOperand(1), m);
				GenericValue GV;
				switch (CE->getOperand(0)->getType()->getTypeID())
				{
					default:
						llvm_unreachable("Bad add type!");
					case Type::IntegerTyID:
						switch (CE->getOpcode())
						{
							default: llvm_unreachable("Invalid integer opcode");
							case Instruction::Add: GV.IntVal = LHS.IntVal + RHS.IntVal; break;
							case Instruction::Sub: GV.IntVal = LHS.IntVal - RHS.IntVal; break;
							case Instruction::Mul: GV.IntVal = LHS.IntVal * RHS.IntVal; break;
							case Instruction::UDiv:GV.IntVal = LHS.IntVal.udiv(RHS.IntVal); break;
							case Instruction::SDiv:GV.IntVal = LHS.IntVal.sdiv(RHS.IntVal); break;
							case Instruction::URem:GV.IntVal = LHS.IntVal.urem(RHS.IntVal); break;
							case Instruction::SRem:GV.IntVal = LHS.IntVal.srem(RHS.IntVal); break;
							case Instruction::And: GV.IntVal = LHS.IntVal & RHS.IntVal; break;
							case Instruction::Or:  GV.IntVal = LHS.IntVal | RHS.IntVal; break;
							case Instruction::Xor: GV.IntVal = LHS.IntVal ^ RHS.IntVal; break;
						}
						break;
					case Type::FloatTyID:
						switch (CE->getOpcode())
						{
							default: llvm_unreachable("Invalid float opcode");
							case Instruction::FAdd:
								GV.FloatVal = LHS.FloatVal + RHS.FloatVal; break;
							case Instruction::FSub:
								GV.FloatVal = LHS.FloatVal - RHS.FloatVal; break;
							case Instruction::FMul:
								GV.FloatVal = LHS.FloatVal * RHS.FloatVal; break;
							case Instruction::FDiv:
								GV.FloatVal = LHS.FloatVal / RHS.FloatVal; break;
							case Instruction::FRem:
								GV.FloatVal = std::fmod(LHS.FloatVal,RHS.FloatVal); break;
						}
						break;
					case Type::DoubleTyID:
					case Type::X86_FP80TyID:
						switch (CE->getOpcode())
						{
							default: llvm_unreachable("Invalid double opcode");
							case Instruction::FAdd:
								GV.DoubleVal = LHS.DoubleVal + RHS.DoubleVal; break;
							case Instruction::FSub:
								GV.DoubleVal = LHS.DoubleVal - RHS.DoubleVal; break;
							case Instruction::FMul:
								GV.DoubleVal = LHS.DoubleVal * RHS.DoubleVal; break;
							case Instruction::FDiv:
								GV.DoubleVal = LHS.DoubleVal / RHS.DoubleVal; break;
							case Instruction::FRem:
								GV.DoubleVal = std::fmod(LHS.DoubleVal,RHS.DoubleVal); break;
						}
						break;
//					case Type::X86_FP80TyID:
					case Type::PPC_FP128TyID:
					case Type::FP128TyID:
					{
						const fltSemantics &Sem = CE->getOperand(0)->getType()->getFltSemantics();
						APFloat apfLHS = APFloat(Sem, LHS.IntVal);
						switch (CE->getOpcode())
						{
							default: llvm_unreachable("Invalid long double opcode");
							case Instruction::FAdd:
								apfLHS.add(APFloat(Sem, RHS.IntVal), APFloat::rmNearestTiesToEven);
								GV.IntVal = apfLHS.bitcastToAPInt();
								break;
							case Instruction::FSub:
								apfLHS.subtract(APFloat(Sem, RHS.IntVal),
										APFloat::rmNearestTiesToEven);
								GV.IntVal = apfLHS.bitcastToAPInt();
								break;
							case Instruction::FMul:
								apfLHS.multiply(APFloat(Sem, RHS.IntVal),
										APFloat::rmNearestTiesToEven);
								GV.IntVal = apfLHS.bitcastToAPInt();
								break;
							case Instruction::FDiv:
								apfLHS.divide(APFloat(Sem, RHS.IntVal),
										APFloat::rmNearestTiesToEven);
								GV.IntVal = apfLHS.bitcastToAPInt();
								break;
							case Instruction::FRem:
								apfLHS.mod(APFloat(Sem, RHS.IntVal));
								GV.IntVal = apfLHS.bitcastToAPInt();
								break;
						}
					}
					break;
				}
				return GV;
			}
			default:
				break;
		}

		SmallString<256> Msg;
		raw_svector_ostream OS(Msg);
		OS << "ConstantExpr not handled: " << *CE;
		report_fatal_error(OS.str());
	}

	// Otherwise, we have a simple constant.
	GenericValue Result;
	switch (C->getType()->getTypeID())
	{
		case Type::FloatTyID:
			Result.FloatVal = cast<ConstantFP>(C)->getValueAPF().convertToFloat();
			break;
		case Type::X86_FP80TyID:
		{
			auto apf = cast<ConstantFP>(C)->getValueAPF();
			bool lostPrecision;
			apf.convert(APFloat::IEEEdouble, APFloat::rmNearestTiesToEven, &lostPrecision);
			Result.DoubleVal = apf.convertToDouble();
			break;
		}
		case Type::DoubleTyID:
			Result.DoubleVal = cast<ConstantFP>(C)->getValueAPF().convertToDouble();
			break;
//		case Type::X86_FP80TyID:
		case Type::FP128TyID:
		case Type::PPC_FP128TyID:
			Result.IntVal = cast <ConstantFP>(C)->getValueAPF().bitcastToAPInt();
			break;
		case Type::IntegerTyID:
			Result.IntVal = cast<ConstantInt>(C)->getValue();
			break;
		case Type::PointerTyID:
			if (isa<ConstantPointerNull>(C))
			{
				Result.PointerVal = nullptr;
			}
			else if (const Function *F = dyn_cast<Function>(C))
			{
				//Result = PTOGV(getPointerToFunctionOrStub(const_cast<Function*>(F)));

				// We probably need just any unique value for each function,
				// so pointer to its LLVM representation should be ok.
				// But we probably should not need this in our semantics tests,
				// so we want to know if it ever gets here (assert).
				assert(false && "taking a pointer to function is not implemented");
				Result = PTOGV(const_cast<Function*>(F));
			}
			else if (const GlobalVariable *GV = dyn_cast<GlobalVariable>(C))
			{
				//Result = PTOGV(getOrEmitGlobalVariable(const_cast<GlobalVariable*>(GV)));

				// We probably need just any unique value for each global,
				// so pointer to its LLVM representation should be ok.
				// But we probably should not need this in our semantics tests,
				// so we want to know if it ever gets here (assert).
				assert(false && "taking a pointer to global variable is not implemented");
				Result = PTOGV(const_cast<GlobalVariable*>(GV));
			}
			else
			{
				llvm_unreachable("Unknown constant pointer type!");
			}
			break;
		case Type::VectorTyID:
		{
			unsigned elemNum;
			Type* ElemTy;
			const ConstantDataVector *CDV = dyn_cast<ConstantDataVector>(C);
			const ConstantVector *CV = dyn_cast<ConstantVector>(C);
			const ConstantAggregateZero *CAZ = dyn_cast<ConstantAggregateZero>(C);

			if (CDV)
			{
				elemNum = CDV->getNumElements();
				ElemTy = CDV->getElementType();
			}
			else if (CV || CAZ)
			{
				VectorType* VTy = dyn_cast<VectorType>(C->getType());
				elemNum = VTy->getNumElements();
				ElemTy = VTy->getElementType();
			}
			else
			{
				llvm_unreachable("Unknown constant vector type!");
			}

			Result.AggregateVal.resize(elemNum);
			// Check if vector holds floats.
			if(ElemTy->isFloatTy())
			{
				if (CAZ)
				{
					GenericValue floatZero;
					floatZero.FloatVal = 0.f;
					std::fill(Result.AggregateVal.begin(), Result.AggregateVal.end(),
							floatZero);
					break;
				}
				if(CV)
				{
					for (unsigned i = 0; i < elemNum; ++i)
						if (!isa<UndefValue>(CV->getOperand(i)))
							Result.AggregateVal[i].FloatVal = cast<ConstantFP>(
									CV->getOperand(i))->getValueAPF().convertToFloat();
					break;
				}
				if(CDV)
					for (unsigned i = 0; i < elemNum; ++i)
						Result.AggregateVal[i].FloatVal = CDV->getElementAsFloat(i);

				break;
			}
			// Check if vector holds doubles.
			if (ElemTy->isDoubleTy())
			{
				if (CAZ)
				{
					GenericValue doubleZero;
					doubleZero.DoubleVal = 0.0;
					std::fill(Result.AggregateVal.begin(), Result.AggregateVal.end(),
							doubleZero);
					break;
				}
				if(CV)
				{
					for (unsigned i = 0; i < elemNum; ++i)
						if (!isa<UndefValue>(CV->getOperand(i)))
							Result.AggregateVal[i].DoubleVal = cast<ConstantFP>(
									CV->getOperand(i))->getValueAPF().convertToDouble();
					break;
				}
				if(CDV)
					for (unsigned i = 0; i < elemNum; ++i)
						Result.AggregateVal[i].DoubleVal = CDV->getElementAsDouble(i);

				break;
			}
			// Check if vector holds integers.
			if (ElemTy->isIntegerTy())
			{
				if (CAZ)
				{
					GenericValue intZero;
					intZero.IntVal = APInt(ElemTy->getScalarSizeInBits(), 0ull);
					std::fill(Result.AggregateVal.begin(), Result.AggregateVal.end(),
							intZero);
					break;
				}
				if(CV)
				{
					for (unsigned i = 0; i < elemNum; ++i)
						if (!isa<UndefValue>(CV->getOperand(i)))
							Result.AggregateVal[i].IntVal = cast<ConstantInt>(
									CV->getOperand(i))->getValue();
						else
						{
							Result.AggregateVal[i].IntVal =
									APInt(CV->getOperand(i)->getType()->getPrimitiveSizeInBits(), 0);
						}
					break;
				}
				if(CDV)
					for (unsigned i = 0; i < elemNum; ++i)
						Result.AggregateVal[i].IntVal = APInt(
								CDV->getElementType()->getPrimitiveSizeInBits(),
								CDV->getElementAsInteger(i));

				break;
			}
			llvm_unreachable("Unknown constant pointer type!");
			break;
		}

		default:
			SmallString<256> Msg;
			raw_svector_ostream OS(Msg);
			OS << "ERROR: Constant unimplemented for type: " << *C->getType();
			report_fatal_error(OS.str());
	}

	return Result;
}

} // anonymous namespace

//
//=============================================================================
// GlobalExecutionContext
//=============================================================================
//

GlobalExecutionContext::GlobalExecutionContext(llvm::Module* m) :
		_module(m)
{

}

llvm::Module* GlobalExecutionContext::getModule() const
{
	return _module;
}

llvm::GenericValue GlobalExecutionContext::getMemory(uint64_t addr, bool log)
{
	if (log)
	{
		memoryLoads.push_back(addr);
	}

	auto fIt = memory.find(addr);
	return fIt != memory.end() ? fIt->second : GenericValue();
}

void GlobalExecutionContext::setMemory(
		uint64_t addr,
		llvm::GenericValue val,
		bool log)
{
	if (log)
	{
		memoryStores.push_back(addr);
	}

	memory[addr] = val;
}

llvm::GenericValue GlobalExecutionContext::getGlobal(
		llvm::GlobalVariable* g,
		bool log)
{
	if (log)
	{
		globalsLoads.push_back(g);
	}

	auto fIt = globals.find(g);
	assert(fIt != globals.end());
	return fIt != globals.end() ? fIt->second : GenericValue();
}

void GlobalExecutionContext::setGlobal(
		llvm::GlobalVariable* g,
		llvm::GenericValue val,
		bool log)
{
	if (log)
	{
		globalsStores.push_back(g);
	}

	globals[g] = val;
}

void GlobalExecutionContext::setValue(llvm::Value* v, llvm::GenericValue val)
{
	values[v] = val;
}

llvm::GenericValue GlobalExecutionContext::getOperandValue(
		llvm::Value* val,
		LocalExecutionContext& ec)
{
	if (ConstantExpr* ce = dyn_cast<ConstantExpr>(val))
	{
		return getConstantExprValue(ce, ec, *this);
	}
	else if (Constant* cpv = dyn_cast<Constant>(val))
	{
		return getConstantValue(cpv, getModule());
	}
	else if (isa<GlobalValue>(val))
	{
		assert(false && "get pointer to global variable, how?");
		throw LlvmIrEmulatorError("not implemented");
	}
	else
	{
		return values[val];
	}
}

//
//=============================================================================
// ExecutionContext
//=============================================================================
//

LocalExecutionContext::LocalExecutionContext() :
		curInst(nullptr)
{

}

LocalExecutionContext::LocalExecutionContext(LocalExecutionContext&& o) :
	curFunction(o.curFunction),
	curBB(o.curBB),
	curInst(o.curInst),
	caller(o.caller),
	allocas(std::move(o.allocas))
{

}

LocalExecutionContext& LocalExecutionContext::operator=(LocalExecutionContext&& o)
{
	curFunction = o.curFunction;
	curBB = o.curBB;
	curInst = o.curInst;
	caller = o.caller;
	allocas = std::move(o.allocas);
	return *this;
}

llvm::Module* LocalExecutionContext::getModule() const
{
	return curFunction->getParent();
}

//
//=============================================================================
// LlvmIrEmulator
//=============================================================================
//

LlvmIrEmulator::LlvmIrEmulator(llvm::Module* m) :
		_module(m),
		_globalEc(_module)
{
	for (GlobalVariable& gv : _module->globals())
	{
		auto val = getConstantValue(gv.getInitializer(), _module);
		setGlobalVariableValue(&gv, val);
	}

	IL = new IntrinsicLowering(_module->getDataLayout());
}

LlvmIrEmulator::~LlvmIrEmulator()
{
	delete IL;
}

llvm::GenericValue LlvmIrEmulator::runFunction(
		llvm::Function* f,
		const llvm::ArrayRef<llvm::GenericValue> argVals)
{
	assert(_module == f->getParent());

	const size_t ac = f->getFunctionType()->getNumParams();
	ArrayRef<GenericValue> aargs = argVals.slice(
			0,
			std::min(argVals.size(), ac));

	callFunction(f, aargs);

	run();

	return _exitValue;
}

/**
 * Right now, this can not handle variadic functions. We probably will not
 * need them anyway, but if we did, it is handled in the LLVM interpreter.
 */
void LlvmIrEmulator::callFunction(
		llvm::Function* f,
		llvm::ArrayRef<llvm::GenericValue> argVals)
{
	_ecStack.emplace_back();
	auto& ec = _ecStack.back();
	ec.curFunction = f;

	if (f->isDeclaration())
	{
		assert(false && "external call unhandled");
		return;
	}

	ec.curBB = &f->front();
	ec.curInst = ec.curBB->begin();

	unsigned i = 0;
	for (auto ai = f->arg_begin(), e = f->arg_end(); ai != e; ++ai, ++i)
	{
		_globalEc.setValue(&*ai, argVals[i]);
	}
}

void LlvmIrEmulator::run()
{
	while (!_ecStack.empty())
	{
		auto& ec = _ecStack.back();
		if (ec.curInst == ec.curBB->end())
		{
			break;
		}
		Instruction& i = *ec.curInst++;

		logInstruction(&i);
		visit(i);
	}
}

void LlvmIrEmulator::logInstruction(llvm::Instruction* i)
{
	_visitedInsns.push_back(i);
	if (_visitedBbs.empty() || i->getParent() != _visitedBbs.back())
	{
		_visitedBbs.push_back(i->getParent());
	}
}

const std::list<llvm::Instruction*>& LlvmIrEmulator::getVisitedInstructions() const
{
	return _visitedInsns;
}

const std::list<llvm::BasicBlock*>& LlvmIrEmulator::getVisitedBasicBlocks() const
{
	return _visitedBbs;
}

bool LlvmIrEmulator::wasInstructionVisited(llvm::Instruction* i) const
{
	for (auto* vi : getVisitedInstructions())
	{
		if (vi == i)
		{
			return true;
		}
	}
	return false;
}

bool LlvmIrEmulator::wasBasicBlockVisited(llvm::BasicBlock* bb) const
{
	for (auto* vbb : getVisitedBasicBlocks())
	{
		if (vbb == bb)
		{
			return true;
		}
	}
	return false;
}

llvm::GenericValue LlvmIrEmulator::getExitValue() const
{
	return _exitValue;
}

const std::list<LlvmIrEmulator::CallEntry>& LlvmIrEmulator::getCallEntries() const
{
	return _calls;
}

std::list<llvm::Value*> LlvmIrEmulator::getCalledValues() const
{
	std::list<llvm::Value*> ret;
	for (auto& ce : _calls)
	{
		ret.push_back(ce.calledValue);
	}
	return ret;
}

std::set<llvm::Value*> LlvmIrEmulator::getCalledValuesSet() const
{
	std::set<llvm::Value*> ret;
	for (auto& ce : _calls)
	{
		ret.insert(ce.calledValue);
	}
	return ret;
}

/**
 * @return @c True if value @a v is called at least once.
 */
bool LlvmIrEmulator::wasValueCalled(llvm::Value* v) const
{
	for (auto& ce : _calls)
	{
		if (ce.calledValue == v)
		{
			return true;
		}
	}

	return false;
}

/**
 * @return Pointer to @c n-th call entry calling @c v value, or @c nullptr if
 *         such entry does not exist.
 */
const LlvmIrEmulator::CallEntry* LlvmIrEmulator::getCallEntry(
		llvm::Value* v,
		unsigned n) const
{
	unsigned cntr = 0;
	for (auto& ce : _calls)
	{
		if (ce.calledValue == v)
		{
			if (cntr == n)
			{
				return &ce;
			}
			else
			{
				++cntr;
			}
		}
	}

	return nullptr;
}

bool LlvmIrEmulator::wasGlobalVariableLoaded(llvm::GlobalVariable* gv)
{
	auto& c = _globalEc.globalsLoads;
	return std::find(c.begin(), c.end(), gv) != c.end();
}

bool LlvmIrEmulator::wasGlobalVariableStored(llvm::GlobalVariable* gv)
{
	auto& c = _globalEc.globalsStores;
	return std::find(c.begin(), c.end(), gv) != c.end();
}

std::list<llvm::GlobalVariable*> LlvmIrEmulator::getLoadedGlobalVariables()
{
	return _globalEc.globalsLoads;
}

std::set<llvm::GlobalVariable*> LlvmIrEmulator::getLoadedGlobalVariablesSet()
{
	auto& l = _globalEc.globalsLoads;
	return std::set<GlobalVariable*>(l.begin(), l.end());
}

std::list<llvm::GlobalVariable*> LlvmIrEmulator::getStoredGlobalVariables()
{
	return _globalEc.globalsStores;
}

std::set<llvm::GlobalVariable*> LlvmIrEmulator::getStoredGlobalVariablesSet()
{
	auto& l = _globalEc.globalsStores;
	return std::set<GlobalVariable*>(l.begin(), l.end());
}

llvm::GenericValue LlvmIrEmulator::getGlobalVariableValue(
		llvm::GlobalVariable* gv)
{
	return _globalEc.getGlobal(gv, false);
}

void LlvmIrEmulator::setGlobalVariableValue(
		llvm::GlobalVariable* gv,
		llvm::GenericValue val)
{
	_globalEc.setGlobal(gv, val, false);
}

bool LlvmIrEmulator::wasMemoryLoaded(uint64_t addr)
{
	auto& c = _globalEc.memoryLoads;
	return std::find(c.begin(), c.end(), addr) != c.end();
}

bool LlvmIrEmulator::wasMemoryStored(uint64_t addr)
{
	auto& c = _globalEc.memoryStores;
	return std::find(c.begin(), c.end(), addr) != c.end();
}

std::list<uint64_t> LlvmIrEmulator::getLoadedMemory()
{
	return _globalEc.memoryLoads;
}

std::set<uint64_t> LlvmIrEmulator::getLoadedMemorySet()
{
	auto& l = _globalEc.memoryLoads;
	return std::set<uint64_t>(l.begin(), l.end());
}

std::list<uint64_t> LlvmIrEmulator::getStoredMemory()
{
	return _globalEc.memoryStores;
}

std::set<uint64_t> LlvmIrEmulator::getStoredMemorySet()
{
	auto& l = _globalEc.memoryStores;
	return std::set<uint64_t>(l.begin(), l.end());
}

llvm::GenericValue LlvmIrEmulator::getMemoryValue(uint64_t addr)
{
	return _globalEc.getMemory(addr, false);
}

void LlvmIrEmulator::setMemoryValue(uint64_t addr, llvm::GenericValue val)
{
	_globalEc.setMemory(addr, val, false);
}

/**
 * Get generic value for the passed LLVM value @a val.
 * If @c val is a global variable, result of @c getGlobalVariableValue() is
 * returned.
 * Otherwise, LLVM value to generic value map in global context is used.
 */
llvm::GenericValue LlvmIrEmulator::getValueValue(llvm::Value* val)
{
	if (auto* gv = dyn_cast<GlobalVariable>(val))
	{
		return getGlobalVariableValue(gv);
	}
	else
	{
		return _globalEc.values[val];
	}
}

//
//=============================================================================
// Terminator Instruction Implementations
//=============================================================================
//

void LlvmIrEmulator::popStackAndReturnValueToCaller(
		llvm::Type* retT,
		llvm::GenericValue res)
{
	_ecStackRetired.emplace_back(_ecStack.back());
	_ecStack.pop_back();

	// Finished main. Put result into exit code...
	//
	if (_ecStack.empty())
	{
		if (retT && !retT->isVoidTy())
		{
			_exitValue = res;
		}
		else
		{
			// Matula: This memset is ok.
			memset(&_exitValue.Untyped, 0, sizeof(_exitValue.Untyped));
		}
	}
	// If we have a previous stack frame, and we have a previous call,
	// fill in the return value...
	//
	else
	{
		LocalExecutionContext& callingEc = _ecStack.back();
		if (Instruction* I = callingEc.caller.getInstruction())
		{
			// Save result...
			if (!callingEc.caller.getType()->isVoidTy())
			{
				_globalEc.setValue(I, res);
			}
			if (InvokeInst* II = dyn_cast<InvokeInst>(I))
			{
				switchToNewBasicBlock(II->getNormalDest (), callingEc, _globalEc);
			}
			// We returned from the call...
			callingEc.caller = CallSite();
		}
	}
}

void LlvmIrEmulator::visitReturnInst(llvm::ReturnInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	Type* retTy = Type::getVoidTy(I.getContext());
	GenericValue res;

	// Save away the return value... (if we are not 'ret void')
	if (I.getNumOperands())
	{
		retTy = I.getReturnValue()->getType();
		res = _globalEc.getOperandValue(I.getReturnValue(), ec);
	}

	popStackAndReturnValueToCaller(retTy, res);
}

void LlvmIrEmulator::visitUnreachableInst(llvm::UnreachableInst& I)
{
	throw LlvmIrEmulatorError("Program executed an 'unreachable' instruction!");
}

void LlvmIrEmulator::visitBranchInst(llvm::BranchInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	BasicBlock* dest;

	dest = I.getSuccessor(0);
	if (!I.isUnconditional())
	{
		Value* cond = I.getCondition();
		if (_globalEc.getOperandValue(cond, ec).IntVal == false)
		{
			dest = I.getSuccessor(1);
		}
	}
	switchToNewBasicBlock(dest, ec, _globalEc);
}

void LlvmIrEmulator::visitSwitchInst(llvm::SwitchInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	Value* cond = I.getCondition();
	Type* elTy = cond->getType();
	GenericValue condVal = _globalEc.getOperandValue(cond, ec);

	// Check to see if any of the cases match...
	BasicBlock *dest = nullptr;
	for (SwitchInst::CaseIt i = I.case_begin(), e = I.case_end(); i != e; ++i)
	{
		GenericValue caseVal = _globalEc.getOperandValue(i.getCaseValue(), ec);
		if (executeICMP_EQ(condVal, caseVal, elTy).IntVal != false)
		{
			dest = cast<BasicBlock>(i.getCaseSuccessor());
			break;
		}
	}
	if (!dest)
	{
		dest = I.getDefaultDest();   // No cases matched: use default
	}
	switchToNewBasicBlock(dest, ec, _globalEc);
}

void LlvmIrEmulator::visitIndirectBrInst(llvm::IndirectBrInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	void* dest = GVTOP(_globalEc.getOperandValue(I.getAddress(), ec));
	switchToNewBasicBlock(reinterpret_cast<BasicBlock*>(dest), ec, _globalEc);
}

//
//=============================================================================
// Binary Instruction Implementations
//=============================================================================
//

void LlvmIrEmulator::visitBinaryOperator(llvm::BinaryOperator& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	Type* ty = I.getOperand(0)->getType();
	GenericValue op0 = _globalEc.getOperandValue(I.getOperand(0), ec);
	GenericValue op1 = _globalEc.getOperandValue(I.getOperand(1), ec);
	GenericValue res;

	// First process vector operation
	if (ty->isVectorTy())
	{
		assert(op0.AggregateVal.size() == op1.AggregateVal.size());
		res.AggregateVal.resize(op0.AggregateVal.size());

		// Macros to execute binary operation 'OP' over integer vectors
#define INTEGER_VECTOR_OPERATION(OP)                                   \
	for (unsigned i = 0; i < res.AggregateVal.size(); ++i)             \
		res.AggregateVal[i].IntVal =                                   \
		op0.AggregateVal[i].IntVal OP op1.AggregateVal[i].IntVal;

		// Additional macros to execute binary operations udiv/sdiv/urem/srem since
		// they have different notation.
#define INTEGER_VECTOR_FUNCTION(OP)                                    \
	for (unsigned i = 0; i < res.AggregateVal.size(); ++i)             \
		res.AggregateVal[i].IntVal =                                   \
		op0.AggregateVal[i].IntVal.OP(op1.AggregateVal[i].IntVal);

		// Macros to execute binary operation 'OP' over floating point type TY
		// (float or double) vectors
#define FLOAT_VECTOR_FUNCTION(OP, TY)                                 \
	for (unsigned i = 0; i < res.AggregateVal.size(); ++i)            \
		res.AggregateVal[i].TY =                                      \
		op0.AggregateVal[i].TY OP op1.AggregateVal[i].TY;

		// Macros to choose appropriate TY: float or double and run operation
		// execution
#define FLOAT_VECTOR_OP(OP) {                                               \
	if (cast<VectorType>(ty)->getElementType()->isFloatTy())                \
		FLOAT_VECTOR_FUNCTION(OP, FloatVal)                                 \
	else                                                                    \
	{                                                                       \
		if (cast<VectorType>(ty)->getElementType()->isDoubleTy())           \
			FLOAT_VECTOR_FUNCTION(OP, DoubleVal)                            \
		else                                                                \
		{                                                                   \
			dbgs() << "Unhandled type for OP instruction: " << *ty << "\n"; \
			llvm_unreachable(0);                                            \
		}                                                                   \
	}                                                                       \
}

		switch(I.getOpcode())
		{
			default:
				dbgs() << "Don't know how to handle this binary operator!\n-->" << I;
				llvm_unreachable(nullptr);
				break;
			case Instruction::Add:   INTEGER_VECTOR_OPERATION(+) break;
			case Instruction::Sub:   INTEGER_VECTOR_OPERATION(-) break;
			case Instruction::Mul:   INTEGER_VECTOR_OPERATION(*) break;
			case Instruction::UDiv:  INTEGER_VECTOR_FUNCTION(udiv) break;
			case Instruction::SDiv:  INTEGER_VECTOR_FUNCTION(sdiv) break;
			case Instruction::URem:  INTEGER_VECTOR_FUNCTION(urem) break;
			case Instruction::SRem:  INTEGER_VECTOR_FUNCTION(srem) break;
			case Instruction::And:   INTEGER_VECTOR_OPERATION(&) break;
			case Instruction::Or:    INTEGER_VECTOR_OPERATION(|) break;
			case Instruction::Xor:   INTEGER_VECTOR_OPERATION(^) break;
			case Instruction::FAdd:  FLOAT_VECTOR_OP(+) break;
			case Instruction::FSub:  FLOAT_VECTOR_OP(-) break;
			case Instruction::FMul:  FLOAT_VECTOR_OP(*) break;
			case Instruction::FDiv:  FLOAT_VECTOR_OP(/) break;
			case Instruction::FRem:
			{
				if (cast<VectorType>(ty)->getElementType()->isFloatTy())
				{
					for (unsigned i = 0; i < res.AggregateVal.size(); ++i)
						res.AggregateVal[i].FloatVal =
						fmod(op0.AggregateVal[i].FloatVal, op1.AggregateVal[i].FloatVal);
				}
				else
				{
					if (cast<VectorType>(ty)->getElementType()->isDoubleTy())
					{
						for (unsigned i = 0; i < res.AggregateVal.size(); ++i)
							res.AggregateVal[i].DoubleVal =
							fmod(op0.AggregateVal[i].DoubleVal, op1.AggregateVal[i].DoubleVal);
					}
					else
					{
						dbgs() << "Unhandled type for Rem instruction: " << *ty << "\n";
						llvm_unreachable(nullptr);
					}
				}
				break;
			}
		}
	}
	else
	{
		switch (I.getOpcode())
		{
			default:
				dbgs() << "Don't know how to handle this binary operator!\n-->" << I;
				llvm_unreachable(nullptr);
				break;
			case Instruction::Add:
				res.IntVal = op0.IntVal + op1.IntVal;
				break;
			case Instruction::Sub:   res.IntVal = op0.IntVal - op1.IntVal; break;
			case Instruction::Mul:   res.IntVal = op0.IntVal * op1.IntVal; break;
			case Instruction::FAdd:  executeFAddInst(res, op0, op1, ty); break;
			case Instruction::FSub:  executeFSubInst(res, op0, op1, ty); break;
			case Instruction::FMul:  executeFMulInst(res, op0, op1, ty); break;
			case Instruction::FDiv:  executeFDivInst(res, op0, op1, ty); break;
			case Instruction::FRem:  executeFRemInst(res, op0, op1, ty); break;
			case Instruction::UDiv:  res.IntVal = op0.IntVal.udiv(op1.IntVal); break;
			case Instruction::SDiv:  res.IntVal = op0.IntVal.sdiv(op1.IntVal); break;
			case Instruction::URem:  res.IntVal = op0.IntVal.urem(op1.IntVal); break;
			case Instruction::SRem:  res.IntVal = op0.IntVal.srem(op1.IntVal); break;
			case Instruction::And:   res.IntVal = op0.IntVal & op1.IntVal; break;
			case Instruction::Or:    res.IntVal = op0.IntVal | op1.IntVal; break;
			case Instruction::Xor:   res.IntVal = op0.IntVal ^ op1.IntVal; break;
		}
	}

	_globalEc.setValue(&I, res);
}

void LlvmIrEmulator::visitICmpInst(llvm::ICmpInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	Type* ty = I.getOperand(0)->getType();
	GenericValue op0 = _globalEc.getOperandValue(I.getOperand(0), ec);
	GenericValue op1 = _globalEc.getOperandValue(I.getOperand(1), ec);
	GenericValue res;

	switch (I.getPredicate())
	{
		case ICmpInst::ICMP_EQ:  res = executeICMP_EQ(op0,  op1, ty); break;
		case ICmpInst::ICMP_NE:  res = executeICMP_NE(op0,  op1, ty); break;
		case ICmpInst::ICMP_ULT: res = executeICMP_ULT(op0, op1, ty); break;
		case ICmpInst::ICMP_SLT: res = executeICMP_SLT(op0, op1, ty); break;
		case ICmpInst::ICMP_UGT: res = executeICMP_UGT(op0, op1, ty); break;
		case ICmpInst::ICMP_SGT: res = executeICMP_SGT(op0, op1, ty); break;
		case ICmpInst::ICMP_ULE: res = executeICMP_ULE(op0, op1, ty); break;
		case ICmpInst::ICMP_SLE: res = executeICMP_SLE(op0, op1, ty); break;
		case ICmpInst::ICMP_UGE: res = executeICMP_UGE(op0, op1, ty); break;
		case ICmpInst::ICMP_SGE: res = executeICMP_SGE(op0, op1, ty); break;
		default:
			dbgs() << "Don't know how to handle this ICmp predicate!\n-->" << I;
			llvm_unreachable(nullptr);
	}

	_globalEc.setValue(&I, res);
}

void LlvmIrEmulator::visitFCmpInst(llvm::FCmpInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	Type* ty = I.getOperand(0)->getType();
	GenericValue op0 = _globalEc.getOperandValue(I.getOperand(0), ec);
	GenericValue op1 = _globalEc.getOperandValue(I.getOperand(1), ec);
	GenericValue res;

	switch (I.getPredicate())
	{
		default:
			dbgs() << "Don't know how to handle this FCmp predicate!\n-->" << I;
			llvm_unreachable(nullptr);
			break;
		case FCmpInst::FCMP_FALSE: res = executeFCMP_BOOL(op0, op1, ty, false); break;
		case FCmpInst::FCMP_TRUE:  res = executeFCMP_BOOL(op0, op1, ty, true); break;
		case FCmpInst::FCMP_ORD:   res = executeFCMP_ORD(op0, op1, ty); break;
		case FCmpInst::FCMP_UNO:   res = executeFCMP_UNO(op0, op1, ty); break;
		case FCmpInst::FCMP_UEQ:   res = executeFCMP_UEQ(op0, op1, ty); break;
		case FCmpInst::FCMP_OEQ:   res = executeFCMP_OEQ(op0, op1, ty); break;
		case FCmpInst::FCMP_UNE:   res = executeFCMP_UNE(op0, op1, ty); break;
		case FCmpInst::FCMP_ONE:   res = executeFCMP_ONE(op0, op1, ty); break;
		case FCmpInst::FCMP_ULT:   res = executeFCMP_ULT(op0, op1, ty); break;
		case FCmpInst::FCMP_OLT:   res = executeFCMP_OLT(op0, op1, ty); break;
		case FCmpInst::FCMP_UGT:   res = executeFCMP_UGT(op0, op1, ty); break;
		case FCmpInst::FCMP_OGT:   res = executeFCMP_OGT(op0, op1, ty); break;
		case FCmpInst::FCMP_ULE:   res = executeFCMP_ULE(op0, op1, ty); break;
		case FCmpInst::FCMP_OLE:   res = executeFCMP_OLE(op0, op1, ty); break;
		case FCmpInst::FCMP_UGE:   res = executeFCMP_UGE(op0, op1, ty); break;
		case FCmpInst::FCMP_OGE:   res = executeFCMP_OGE(op0, op1, ty); break;
	}

	_globalEc.setValue(&I, res);
}

//
//=============================================================================
// Ternary Instruction Implementations
//=============================================================================
//

void LlvmIrEmulator::visitSelectInst(llvm::SelectInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	Type* ty = I.getOperand(0)->getType();
	GenericValue op0 = _globalEc.getOperandValue(I.getOperand(0), ec);
	GenericValue op1 = _globalEc.getOperandValue(I.getOperand(1), ec);
	GenericValue op2 = _globalEc.getOperandValue(I.getOperand(2), ec);
	GenericValue res = executeSelectInst(op0, op1, op2, ty);
	_globalEc.setValue(&I, res);
}

//
//=============================================================================
// Memory Instruction Implementations
//=============================================================================
//

/**
 * Matula:
 * Right now, we do the same thing as LLVM's interpreter -- really
 * allocate memory and keed track of it via ExecutionContext::allocas.
 * Maybe this is not needed at all, or it would be better to solve it in a
 * different way without memory allocation.
 */
void LlvmIrEmulator::visitAllocaInst(llvm::AllocaInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();

	Type* ty = I.getType()->getElementType();

	unsigned elemN = _globalEc.getOperandValue(I.getOperand(0), ec).IntVal.getZExtValue();
	unsigned tySz = static_cast<size_t>(_module->getDataLayout().getTypeAllocSize(ty));

	// Avoid malloc-ing zero bytes, use max()...
	unsigned memToAlloc = std::max(1U, elemN * tySz);

	// Allocate enough memory to hold the type...
	void *mem = malloc(memToAlloc);

	GenericValue res = PTOGV(mem);
	assert(res.PointerVal && "Null pointer returned by malloc!");
	_globalEc.setValue(&I, res);

	if (I.getOpcode() == Instruction::Alloca)
	{
		_ecStack.back().allocas.add(mem);
	}
}

void LlvmIrEmulator::visitGetElementPtrInst(llvm::GetElementPtrInst& I)
{
	  LocalExecutionContext& ec = _ecStack.back();
	  _globalEc.setValue(
			  &I,
			  executeGEPOperation(
					  I.getPointerOperand(),
					  gep_type_begin(I),
					  gep_type_end(I),
					  ec,
					  _globalEc));
}

void LlvmIrEmulator::visitLoadInst(llvm::LoadInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	GenericValue res;

	if (auto* gv = dyn_cast<GlobalVariable>(I.getPointerOperand()))
	{
		res = _globalEc.getGlobal(gv);
	}
	else
	{
		GenericValue src = _globalEc.getOperandValue(I.getPointerOperand(), ec);
		GenericValue* ptr = reinterpret_cast<GenericValue*>(GVTOP(src));
		uint64_t ptrVal = reinterpret_cast<uint64_t>(ptr);
		res = _globalEc.getMemory(ptrVal);
	}

	_globalEc.setValue(&I, res);
}

void LlvmIrEmulator::visitStoreInst(llvm::StoreInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	GenericValue val = _globalEc.getOperandValue(I.getOperand(0), ec);

	if (auto* gv = dyn_cast<GlobalVariable>(I.getPointerOperand()))
	{
		_globalEc.setGlobal(gv, val);
	}
	else
	{
		GenericValue dst = _globalEc.getOperandValue(I.getPointerOperand(), ec);
		GenericValue* ptr = reinterpret_cast<GenericValue*>(GVTOP(dst));
		uint64_t ptrVal = reinterpret_cast<uint64_t>(ptr);
		_globalEc.setMemory(ptrVal, val);
	}
}

//
//=============================================================================
// Call Instruction Implementations
//=============================================================================
//

void LlvmIrEmulator::visitCallInst(llvm::CallInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();

	auto* cf = I.getCalledFunction();
	if (cf && cf->isDeclaration() && cf->isIntrinsic() &&
			cf->getIntrinsicID() != Intrinsic::fabs) // can not lower fabs
	{
		assert(cf->getIntrinsicID() != Intrinsic::vastart
				&& cf->getIntrinsicID() != Intrinsic::vaend
				&& cf->getIntrinsicID() != Intrinsic::vacopy);

		BasicBlock::iterator me(&I);
		BasicBlock *Parent = I.getParent();
		bool atBegin(Parent->begin() == me);
		if (!atBegin)
		{
			--me;
		}
		IL->LowerIntrinsicCall(cast<CallInst>(&I));

		// Restore the CurInst pointer to the first instruction newly inserted,
		// if any.
		if (atBegin)
		{
			ec.curInst = Parent->begin();
		}
		else
		{
			ec.curInst = me;
			++ec.curInst;
		}

		return;
	}

	CallEntry ce;
	ce.calledValue = I.getCalledValue();

	for (auto aIt = I.arg_begin(), eIt = I.arg_end(); aIt != eIt; ++aIt)
	{
		Value* val = *aIt;
		ce.calledArguments.push_back(_globalEc.getOperandValue(val, ec));
	}

	_calls.push_back(ce);
}

void LlvmIrEmulator::visitInvokeInst(llvm::InvokeInst& I)
{
	assert(false && "InvokeInst not implemented.");
	throw LlvmIrEmulatorError("InvokeInst not implemented.");
}

//
//=============================================================================
// Shift Instruction Implementations
//=============================================================================
//

unsigned getShiftAmount(
		uint64_t orgShiftAmount,
		llvm::APInt valueToShift)
{
	unsigned valueWidth = valueToShift.getBitWidth();
	if (orgShiftAmount < static_cast<uint64_t>(valueWidth))
	{
		return orgShiftAmount;
	}
	// according to the llvm documentation, if orgShiftAmount > valueWidth,
	// the result is undfeined. but we do shift by this rule:
	return (NextPowerOf2(valueWidth-1) - 1) & orgShiftAmount;
}

void LlvmIrEmulator::visitShl(llvm::BinaryOperator& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	GenericValue op0 = _globalEc.getOperandValue(I.getOperand(0), ec);
	GenericValue op1 = _globalEc.getOperandValue(I.getOperand(1), ec);
	GenericValue Dest;
	Type* ty = I.getType();

	if (ty->isVectorTy())
	{
		uint32_t src1Size = uint32_t(op0.AggregateVal.size());
		assert(src1Size == op1.AggregateVal.size());
		for (unsigned i = 0; i < src1Size; i++)
		{
			GenericValue Result;
			uint64_t shiftAmount = op1.AggregateVal[i].IntVal.getZExtValue();
			llvm::APInt valueToShift = op0.AggregateVal[i].IntVal;
			Result.IntVal = valueToShift.shl(getShiftAmount(shiftAmount, valueToShift));
			Dest.AggregateVal.push_back(Result);
		}
	}
	else
	{
		// scalar
		uint64_t shiftAmount = op1.IntVal.getZExtValue();
		llvm::APInt valueToShift = op0.IntVal;
		Dest.IntVal = valueToShift.shl(getShiftAmount(shiftAmount, valueToShift));
	}

	_globalEc.setValue(&I, Dest);
}

void LlvmIrEmulator::visitLShr(llvm::BinaryOperator& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	GenericValue op0 = _globalEc.getOperandValue(I.getOperand(0), ec);
	GenericValue op1 = _globalEc.getOperandValue(I.getOperand(1), ec);
	GenericValue Dest;
	Type* ty = I.getType();

	if (ty->isVectorTy())
	{
		uint32_t src1Size = uint32_t(op0.AggregateVal.size());
		assert(src1Size == op1.AggregateVal.size());
		for (unsigned i = 0; i < src1Size; i++)
		{
			GenericValue Result;
			uint64_t shiftAmount = op1.AggregateVal[i].IntVal.getZExtValue();
			llvm::APInt valueToShift = op0.AggregateVal[i].IntVal;
			Result.IntVal = valueToShift.lshr(getShiftAmount(shiftAmount, valueToShift));
			Dest.AggregateVal.push_back(Result);
		}
	}
	else
	{
		// scalar
		uint64_t shiftAmount = op1.IntVal.getZExtValue();
		llvm::APInt valueToShift = op0.IntVal;
		Dest.IntVal = valueToShift.lshr(getShiftAmount(shiftAmount, valueToShift));
	}

	_globalEc.setValue(&I, Dest);
}

void LlvmIrEmulator::visitAShr(llvm::BinaryOperator& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	GenericValue op0 = _globalEc.getOperandValue(I.getOperand(0), ec);
	GenericValue op1 = _globalEc.getOperandValue(I.getOperand(1), ec);
	GenericValue Dest;
	Type* ty = I.getType();

	if (ty->isVectorTy())
	{
		size_t src1Size = op0.AggregateVal.size();
		assert(src1Size == op1.AggregateVal.size());
		for (unsigned i = 0; i < src1Size; i++)
		{
			GenericValue Result;
			uint64_t shiftAmount = op1.AggregateVal[i].IntVal.getZExtValue();
			llvm::APInt valueToShift = op0.AggregateVal[i].IntVal;
			Result.IntVal = valueToShift.ashr(getShiftAmount(shiftAmount, valueToShift));
			Dest.AggregateVal.push_back(Result);
		}
	}
	else
	{
		// scalar
		uint64_t shiftAmount = op1.IntVal.getZExtValue();
		llvm::APInt valueToShift = op0.IntVal;
		Dest.IntVal = valueToShift.ashr(getShiftAmount(shiftAmount, valueToShift));
	}

	_globalEc.setValue(&I, Dest);
}

//
//=============================================================================
// Conversion Instruction Implementations
//=============================================================================
//

void LlvmIrEmulator::visitTruncInst(llvm::TruncInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeTruncInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitSExtInst(llvm::SExtInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeSExtInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitZExtInst(llvm::ZExtInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeZExtInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitFPTruncInst(llvm::FPTruncInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeFPTruncInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitFPExtInst(llvm::FPExtInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeFPExtInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitUIToFPInst(llvm::UIToFPInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeUIToFPInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitSIToFPInst(llvm::SIToFPInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeSIToFPInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitFPToUIInst(llvm::FPToUIInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeFPToUIInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitFPToSIInst(llvm::FPToSIInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeFPToSIInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitPtrToIntInst(llvm::PtrToIntInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executePtrToIntInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitIntToPtrInst(llvm::IntToPtrInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeIntToPtrInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

void LlvmIrEmulator::visitBitCastInst(llvm::BitCastInst& I)
{
	LocalExecutionContext& ec = _ecStack.back();
	_globalEc.setValue(&I, executeBitCastInst(I.getOperand(0), I.getType(), ec, _globalEc));
}

//
//=============================================================================
// Miscellaneous Instruction Implementations
//=============================================================================
//

void LlvmIrEmulator::visitVAArgInst(llvm::VAArgInst& I)
{
	assert(false && "Handling of VAArgInst is not implemented");
	throw LlvmIrEmulatorError("Handling of VAArgInst is not implemented");
}

/**
 * This is not really getting the value. It just sets ExtractValueInst's result
 * to uninitialized GenericValue.
 */
void LlvmIrEmulator::visitExtractElementInst(llvm::ExtractElementInst& I)
{
	GenericValue dest;
	_globalEc.setValue(&I, dest);
}

void LlvmIrEmulator::visitInsertElementInst(llvm::InsertElementInst& I)
{
	assert(false && "Handling of InsertElementInst is not implemented");
	throw LlvmIrEmulatorError("Handling of InsertElementInst is not implemented");
}

void LlvmIrEmulator::visitShuffleVectorInst(llvm::ShuffleVectorInst& I)
{
	assert(false && "Handling of ShuffleVectorInst is not implemented");
	throw LlvmIrEmulatorError("Handling of ShuffleVectorInst is not implemented");
}

/**
 * This is not really getting the value. It just sets ExtractValueInst's result
 * to uninitialized GenericValue.
 */
void LlvmIrEmulator::visitExtractValueInst(llvm::ExtractValueInst& I)
{
	GenericValue dest;
	_globalEc.setValue(&I, dest);
}

void LlvmIrEmulator::visitInsertValueInst(llvm::InsertValueInst& I)
{
	assert(false && "Handling of InsertValueInst is not implemented");
	throw LlvmIrEmulatorError("Handling of InsertValueInst is not implemented");
}

void LlvmIrEmulator::visitPHINode(llvm::PHINode& PN)
{
	throw LlvmIrEmulatorError("PHI nodes already handled!");
}

//
//=============================================================================
// Super Instruction Implementations
//=============================================================================
//

/**
 * When visitor does not find visit method for a particular child class,
 * it uses visit method for the parent class. This is a visit for the super
 * parent class for all LLVM instructions. If visitor gets here, it means
 * the current instruction is not handled -- it should have its own specialized
 * visit method, no instruction should be handled by this super visit method.
 */
void LlvmIrEmulator::visitInstruction(llvm::Instruction& I)
{
	throw LlvmIrEmulatorError(
			"Unhandled instruction visited: " + llvmObjToString(&I));
}

} // llvmir_emul
} // retdec
