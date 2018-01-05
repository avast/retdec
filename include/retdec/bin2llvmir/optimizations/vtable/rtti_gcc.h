/**
 * @file include/retdec/bin2llvmir/optimizations/vtable/rtti_gcc.h
 * @brief Search for gcc&clang RTTI in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 *
 * @note See ABI: http://mentorembedded.github.io/cxx-abi/abi.html#rtti
 *       UML visualization is in decompiler/doc/references/rtti_itanium
 *
 * TODO:
 * In ABI, there are more classes derived from type_info like
 * __fundamental_type_info or __array_type_info.
 * These are not for user-defined virtual classes, but for other
 * (simpler) types.
 * Maybe it would be possible to parse them and use them somehow,
 * but I do not know how.
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_VTABLE_RTTI_GCC_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_VTABLE_RTTI_GCC_H

#include <cassert>
#include <cstdint>
#include <vector>

#include "retdec/utils/address.h"

namespace retdec {
namespace bin2llvmir {

class TypeInfo;
class ClassTypeInfo;
class SiClassTypeInfo;
class VmiClassTypeInfo;
class BaseClassTypeInfo;

/**
 * ABI: @c type_info
 */
class TypeInfo
{
	// ABI specification.
	//
	public:
		virtual ~TypeInfo();
		bool operator==(const TypeInfo& o) const;
		bool operator!=(const TypeInfo& o) const;

	public:
		/// Pointer (address) of virtual table for this @c TypeInfo instance.
		retdec::utils::Address vtableAddr;
		/// NTBS (null-terminated byte string) address.
		retdec::utils::Address nameAddr;

	// Our methods and data.
	//
	public:
		virtual std::string dump() const;

	public:
		/// Position of this @c TypeInfo entry.
		retdec::utils::Address address;
		/// String from @c nameAddr position.
		std::string name;
};

/**
 * ABI: @c __class_type_info
 *
 * Used for class types having no bases, and is also a base type for
 * the other two class type representations.
 */
class ClassTypeInfo : public TypeInfo
{
	// ABI specification.
	//
		// empty

	// Our methods and data.
	//
	public:
		virtual std::string dump() const override;
};

/**
 * ABI: @c __si_class_type_info
 *
 * For classes containing only a single, public, non-virtual base
 * at offset zero.
 */
class SiClassTypeInfo : public ClassTypeInfo
{
	// ABI specification.
	//
	public:
		/// Address of the base class @c TypeInfo structure.
		retdec::utils::Address baseClassAddr;

	// Our methods and data.
	//
	public:
		virtual std::string dump() const override;

	public:
		/// Object created for base on address @c baseClassAddr.
		ClassTypeInfo* baseClass = nullptr;
};

/**
 * ABI: @c __vmi_class_type_info
 *
 * For classes with bases that don't satisfy the @c SiClassTypeInfo constraints.
 */
class VmiClassTypeInfo : public ClassTypeInfo
{
	// ABI specification.
	//
	public:
		enum eFlagMasks
		{
			NON_DIAMOND_REPEAT_MASK = 0x1,
			DIAMOND_SHAPED_MASK = 0x2
		};

	public:
		/// Details about the class structure. Flags refer to both
		/// direct and indirect bases.
		uint32_t flags = 0;
		/// Number of direct proper base class descriptions that follow
		uint32_t baseCount = 0;
		std::vector<BaseClassTypeInfo> baseInfo;

	// Our methods and data.
	//
	public:
		virtual std::string dump() const override;
};

/**
 * ABI: @c __base_class_type_info
 *
 * Base class descriptions -- one for every direct proper base.
 */
class BaseClassTypeInfo
{
	// ABI specification.
	//
	public:
		enum eOffsetFlagsMasks
		{
			BASE_IS_VIRTUAL = 0x1,
			BASE_IS_PUBLIC = 0x2
		};

	public:
		/// Address of the base class @c TypeInfo structure.
		retdec::utils::Address baseClassAddr;
		/// Low-order byte is @c eOffsetFlagsMasks flags.
		/// High 3 bytes are signed offset.
		uint32_t offsetFlags = 0;

	// Our methods and data.
	//
	public:
		std::string dump() const;

	public:
		/// Object created for base on address @c baseClassAddr.
		ClassTypeInfo* baseClass = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
