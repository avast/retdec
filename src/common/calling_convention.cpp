/**
 * @file src/common/calling_convention.cpp
 * @brief Calling convention representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <iostream>

#include "retdec/common/calling_convention.h"

namespace retdec {
namespace common {

/**
 * Unknown calling convention is created.
 */
CallingConvention::CallingConvention()
{

}

CallingConvention::CallingConvention(eCC cc) :
		_cc(cc)
{

}

CallingConventionID CallingConvention::getID() const
{
	return _cc;
}

CallingConvention CallingConvention::initVoidarg()  { return CallingConvention(eCC::CC_VOIDARG); }
CallingConvention CallingConvention::initCdecl()    { return CallingConvention(eCC::CC_CDECL); }
CallingConvention CallingConvention::initEllipsis() { return CallingConvention(eCC::CC_ELLIPSIS); }
CallingConvention CallingConvention::initStdcall()  { return CallingConvention(eCC::CC_STDCALL); }
CallingConvention CallingConvention::initPascal()   { return CallingConvention(eCC::CC_PASCAL); }
CallingConvention CallingConvention::initFastcall() { return CallingConvention(eCC::CC_FASTCALL); }
CallingConvention CallingConvention::initThiscall() { return CallingConvention(eCC::CC_THISCALL); }
CallingConvention CallingConvention::initManual()   { return CallingConvention(eCC::CC_MANUAL); }
CallingConvention CallingConvention::initSpoiled()  { return CallingConvention(eCC::CC_SPOILED); }
CallingConvention CallingConvention::initSpecialE() { return CallingConvention(eCC::CC_SPECIALE); }
CallingConvention CallingConvention::initSpecialP() { return CallingConvention(eCC::CC_SPECIALP); }
CallingConvention CallingConvention::initSpecial()  { return CallingConvention(eCC::CC_SPECIAL); }

bool CallingConvention::isUnknown() const  { return _cc == eCC::CC_UNKNOWN; }
bool CallingConvention::isKnown() const    { return !isUnknown(); }
bool CallingConvention::isVoidarg() const  { return _cc == eCC::CC_VOIDARG; }
bool CallingConvention::isCdecl() const    { return _cc == eCC::CC_CDECL; }
bool CallingConvention::isEllipsis() const { return _cc == eCC::CC_ELLIPSIS; }
bool CallingConvention::isStdcall() const  { return _cc == eCC::CC_STDCALL; }
bool CallingConvention::isPascal() const   { return _cc == eCC::CC_PASCAL; }
bool CallingConvention::isFastcall() const { return _cc == eCC::CC_FASTCALL; }
bool CallingConvention::isThiscall() const { return _cc == eCC::CC_THISCALL; }
bool CallingConvention::isManual() const   { return _cc == eCC::CC_MANUAL; }
bool CallingConvention::isSpoiled() const  { return _cc == eCC::CC_SPOILED; }
bool CallingConvention::isSpecialE() const { return _cc == eCC::CC_SPECIALE; }
bool CallingConvention::isSpecialP() const { return _cc == eCC::CC_SPECIALP; }
bool CallingConvention::isSpecial() const  { return _cc == eCC::CC_SPECIAL; }

void CallingConvention::setIsUnknown()  { _cc = eCC::CC_UNKNOWN; }
void CallingConvention::setIsVoidarg()  { _cc = eCC::CC_VOIDARG; }
void CallingConvention::setIsCdecl()    { _cc = eCC::CC_CDECL; }
void CallingConvention::setIsEllipsis() { _cc = eCC::CC_ELLIPSIS; }
void CallingConvention::setIsStdcall()  { _cc = eCC::CC_STDCALL; }
void CallingConvention::setIsPascal()   { _cc = eCC::CC_PASCAL; }
void CallingConvention::setIsFastcall() { _cc = eCC::CC_FASTCALL; }
void CallingConvention::setIsThiscall() { _cc = eCC::CC_THISCALL; }
void CallingConvention::setIsManual()   { _cc = eCC::CC_MANUAL; }
void CallingConvention::setIsSpoiled()  { _cc = eCC::CC_SPOILED; }
void CallingConvention::setIsSpecialE() { _cc = eCC::CC_SPECIALE; }
void CallingConvention::setIsSpecialP() { _cc = eCC::CC_SPECIALP; }
void CallingConvention::setIsSpecial()  { _cc = eCC::CC_SPECIAL; }
void CallingConvention::set(eCC cc) { _cc = cc; }

bool CallingConvention::operator<(const CallingConvention& cc) const
{
	return _cc < cc._cc;
}

std::ostream& operator<<(std::ostream &out, const CallingConventionID& cc)
{
	switch(cc)
	{
		case CallingConvention::eCC::CC_UNKNOWN:  out << "CC_UNKNOWN"; break;
		case CallingConvention::eCC::CC_VOIDARG:  out << "CC_VOIDARG"; break;
		case CallingConvention::eCC::CC_CDECL:    out << "CC_CDECL"; break;
		case CallingConvention::eCC::CC_ELLIPSIS: out << "CC_ELLIPSIS"; break;
		case CallingConvention::eCC::CC_STDCALL:  out << "CC_STDCALL"; break;
		case CallingConvention::eCC::CC_PASCAL:   out << "CC_PASCAL"; break;
		case CallingConvention::eCC::CC_FASTCALL: out << "CC_FASTCALL"; break;
		case CallingConvention::eCC::CC_THISCALL: out << "CC_THISCALL"; break;
		case CallingConvention::eCC::CC_MANUAL:   out << "CC_MANUAL"; break;
		case CallingConvention::eCC::CC_SPOILED:  out << "CC_SPOILED"; break;
		case CallingConvention::eCC::CC_SPECIALE: out << "CC_SPECIALE"; break;
		case CallingConvention::eCC::CC_SPECIALP: out << "CC_SPECIALP"; break;
		case CallingConvention::eCC::CC_SPECIAL:  out << "CC_SPECIAL"; break;
		case CallingConvention::eCC::CC_WATCOM:   out << "CC_WATCOM"; break;
		case CallingConvention::eCC::CC_X64:      out << "CC_X64_OS_DEFAULT"; break;
		case CallingConvention::eCC::CC_ARM:      out << "CC_ARM_DEFAULT"; break;
		case CallingConvention::eCC::CC_ARM64:    out << "CC_ARM64_DEFAULT"; break;
		case CallingConvention::eCC::CC_MIPS:     out << "CC_MIPS_DEFAULT"; break;
		case CallingConvention::eCC::CC_MIPS64:   out << "CC_MIPS64_DEFAULT"; break;
		case CallingConvention::eCC::CC_POWERPC:  out << "CC_POWERPC_DEFAULT"; break;
		case CallingConvention::eCC::CC_POWERPC64:out << "CC_POWERPC64_DEFAULT"; break;
		case CallingConvention::eCC::CC_PIC32:    out << "CC_PIC32_DEFAULT"; break;
		default: out << "UNHANDLED"; break;
	}
	return out;
}

std::ostream& operator<<(std::ostream &out, const CallingConvention& cc)
{
	out << cc._cc;

	return out;
}

CallingConvention& CallingConvention::operator=(const CallingConventionID& cc)
{
	_cc = cc;

	return *this;
}

} // namespace common
} // namespace retdec
