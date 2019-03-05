/**
 * @file retdec/include/bin2llvmir/providers/calling_convention/cdecl.h
 * @brief Calling convention information for cdecl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X86_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X86_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class CdeclCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		CdeclCallingConvention(const Abi* a);
		virtual ~CdeclCallingConvention();
	
	// Stacks.
	//
	public:
		virtual std::size_t getMaxBytesPerStackParam() const override;
	
	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);
};

class FastcallCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		FastcallCallingConvention(const Abi* a);
		virtual ~FastcallCallingConvention();
	
	// Stacks.
	//
	public:
		virtual std::size_t getMaxBytesPerStackParam() const override;
	
	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);
};

class PascalCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		PascalCallingConvention(const Abi* a);
		virtual ~PascalCallingConvention();
	
	// Stacks.
	//
	public:
		virtual std::size_t getMaxBytesPerStackParam() const override;
	
	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);
};

class PascalFastcallCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		PascalFastcallCallingConvention(const Abi* a);
		virtual ~PascalFastcallCallingConvention();
	
	// Stacks.
	//
	public:
		virtual std::size_t getMaxBytesPerStackParam() const override;
	
	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);
};

class ThiscallCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		ThiscallCallingConvention(const Abi* a);
		virtual ~ThiscallCallingConvention();
	
	// Stacks.
	//
	public:
		virtual std::size_t getMaxBytesPerStackParam() const override;
	
	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);
};

class WatcomCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		WatcomCallingConvention(const Abi* a);
		virtual ~WatcomCallingConvention();
	
	// Stacks.
	//
	public:
		virtual std::size_t getMaxBytesPerStackParam() const override;
	
	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);
};

}
}

#endif
