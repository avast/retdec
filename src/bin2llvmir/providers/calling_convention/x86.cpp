/**
 * @file src/bin2llvmir/providers/calling_convention/x86.cpp
 * @brief Calling convention of architecture x86.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/x86.h"
#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// CdeclCallingConvention
//==============================================================================
//

CdeclCallingConvention::CdeclCallingConvention(const Abi* a) :
		CallingConvention(a)
{
	_returnRegs = {
		X86_REG_EAX,
		X86_REG_EDX
	};

	_returnFPRegs = {
		X86_REG_ST7,
		X86_REG_ST0
	};
}

CdeclCallingConvention::~CdeclCallingConvention()
{
}

std::size_t CdeclCallingConvention::getMaxBytesPerStackParam() const
{
	return _abi->getWordSize()*2;
}

CallingConvention::Ptr CdeclCallingConvention::create(const Abi* a)
{
	return std::make_unique<CdeclCallingConvention>(a);
}

//
//==============================================================================
// FastcallCallingConvention
//==============================================================================
//

FastcallCallingConvention::FastcallCallingConvention(const Abi* a) :
		CallingConvention(a)

{
	_paramRegs = {
		X86_REG_ECX,
		X86_REG_EDX,
	};

	_returnRegs = {
		X86_REG_EAX,
		X86_REG_EDX
	};

	_returnFPRegs = {
		X86_REG_ST7,
		X86_REG_ST0
	};
}

FastcallCallingConvention::~FastcallCallingConvention()
{
}

std::size_t FastcallCallingConvention::getMaxBytesPerStackParam() const
{
	return _abi->getWordSize()*2;
}

CallingConvention::Ptr FastcallCallingConvention::create(const Abi* a)
{
	return std::make_unique<FastcallCallingConvention>(a);
}

//
//==============================================================================
// PascalCallingConvention
//==============================================================================
//

PascalCallingConvention::PascalCallingConvention(const Abi* a) :
		CallingConvention(a)

{
	_returnRegs = {
		X86_REG_EAX,
		X86_REG_EDX
	};

	_returnFPRegs = {
		X86_REG_ST7,
		X86_REG_ST0
	};

	_stackParamOrder = LTR;
}

PascalCallingConvention::~PascalCallingConvention()
{
}

std::size_t PascalCallingConvention::getMaxBytesPerStackParam() const
{
	return _abi->getWordSize()*2;
}

CallingConvention::Ptr PascalCallingConvention::create(const Abi* a)
{
	return std::make_unique<PascalCallingConvention>(a);
}

//
//==============================================================================
// PascalFastcallCallingConvention
//==============================================================================
//

PascalFastcallCallingConvention::PascalFastcallCallingConvention(const Abi* a) :
		CallingConvention(a)

{
	_paramRegs = {
		X86_REG_ECX,
		X86_REG_EDX,
	};

	_returnRegs = {
		X86_REG_EAX,
		X86_REG_EDX
	};

	_returnFPRegs = {
		X86_REG_ST7,
		X86_REG_ST0
	};

	_stackParamOrder = LTR;
}

PascalFastcallCallingConvention::~PascalFastcallCallingConvention()
{
}

std::size_t PascalFastcallCallingConvention::getMaxBytesPerStackParam() const
{
	return _abi->getWordSize()*2;
}

CallingConvention::Ptr PascalFastcallCallingConvention::create(const Abi* a)
{
	return std::make_unique<PascalFastcallCallingConvention>(a);
}

//
//==============================================================================
// ThiscallCallingConvention
//==============================================================================
//

ThiscallCallingConvention::ThiscallCallingConvention(const Abi* a) :
		CallingConvention(a)

{
	_paramRegs = {
		X86_REG_ECX
	};

	_returnRegs = {
		X86_REG_EAX,
		X86_REG_EDX
	};

	_returnFPRegs = {
		X86_REG_ST7,
		X86_REG_ST0
	};
}

ThiscallCallingConvention::~ThiscallCallingConvention()
{
}

std::size_t ThiscallCallingConvention::getMaxBytesPerStackParam() const
{
	return _abi->getWordSize()*2;
}

CallingConvention::Ptr ThiscallCallingConvention::create(const Abi* a)
{
	return std::make_unique<ThiscallCallingConvention>(a);
}

//
//==============================================================================
// WatcomCallingConvention
//==============================================================================
//

WatcomCallingConvention::WatcomCallingConvention(const Abi* a) :
		CallingConvention(a)

{
	_paramRegs = {
		X86_REG_ECX
	};

	_returnRegs = {
		X86_REG_EAX,
		X86_REG_EDX
	};

	_returnFPRegs = {
		X86_REG_ST7,
		X86_REG_ST0
	};
}

WatcomCallingConvention::~WatcomCallingConvention()
{
}

std::size_t WatcomCallingConvention::getMaxBytesPerStackParam() const
{
	return _abi->getWordSize()*2;
}

CallingConvention::Ptr WatcomCallingConvention::create(const Abi* a)
{
	return std::make_unique<WatcomCallingConvention>(a);
}

}
}
