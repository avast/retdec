/**
 * @file src/config/calling_convention.cpp
 * @brief Decompilation configuration manipulation: calling convention.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/config/calling_convention.h"

namespace {

const std::vector<std::string> ccStrings =
{
	"unknown",
	"voidarg",
	"cdecl",
	"ellipsis",
	"stdcall",
	"pascal",
	"fastcall",
	"thiscall",
	"manual",
	"spoiled",
	"speciale",
	"specialp",
	"special"
};

} // anonymous namespace

namespace retdec {
namespace config {

/**
 * Unknown calling convention is created.
 */
CallingConvention::CallingConvention()
{

}

CallingConvention::CallingConvention(eCallingConvention cc) :
		_callingConvention(cc)
{

}

CallingConvention CallingConvention::initVoidarg()  { return CallingConvention(eCallingConvention::CC_VOIDARG); }
CallingConvention CallingConvention::initCdecl()    { return CallingConvention(eCallingConvention::CC_CDECL); }
CallingConvention CallingConvention::initEllipsis() { return CallingConvention(eCallingConvention::CC_ELLIPSIS); }
CallingConvention CallingConvention::initStdcall()  { return CallingConvention(eCallingConvention::CC_STDCALL); }
CallingConvention CallingConvention::initPascal()   { return CallingConvention(eCallingConvention::CC_PASCAL); }
CallingConvention CallingConvention::initFastcall() { return CallingConvention(eCallingConvention::CC_FASTCALL); }
CallingConvention CallingConvention::initThiscall() { return CallingConvention(eCallingConvention::CC_THISCALL); }
CallingConvention CallingConvention::initManual()   { return CallingConvention(eCallingConvention::CC_MANUAL); }
CallingConvention CallingConvention::initSpoiled()  { return CallingConvention(eCallingConvention::CC_SPOILED); }
CallingConvention CallingConvention::initSpecialE() { return CallingConvention(eCallingConvention::CC_SPECIALE); }
CallingConvention CallingConvention::initSpecialP() { return CallingConvention(eCallingConvention::CC_SPECIALP); }
CallingConvention CallingConvention::initSpecial()  { return CallingConvention(eCallingConvention::CC_SPECIAL); }

bool CallingConvention::isUnknown() const  { return _callingConvention == eCallingConvention::CC_UNKNOWN; }
bool CallingConvention::isKnown() const    { return !isUnknown(); }
bool CallingConvention::isVoidarg() const  { return _callingConvention == eCallingConvention::CC_VOIDARG; }
bool CallingConvention::isCdecl() const    { return _callingConvention == eCallingConvention::CC_CDECL; }
bool CallingConvention::isEllipsis() const { return _callingConvention == eCallingConvention::CC_ELLIPSIS; }
bool CallingConvention::isStdcall() const  { return _callingConvention == eCallingConvention::CC_STDCALL; }
bool CallingConvention::isPascal() const   { return _callingConvention == eCallingConvention::CC_PASCAL; }
bool CallingConvention::isFastcall() const { return _callingConvention == eCallingConvention::CC_FASTCALL; }
bool CallingConvention::isThiscall() const { return _callingConvention == eCallingConvention::CC_THISCALL; }
bool CallingConvention::isManual() const   { return _callingConvention == eCallingConvention::CC_MANUAL; }
bool CallingConvention::isSpoiled() const  { return _callingConvention == eCallingConvention::CC_SPOILED; }
bool CallingConvention::isSpecialE() const { return _callingConvention == eCallingConvention::CC_SPECIALE; }
bool CallingConvention::isSpecialP() const { return _callingConvention == eCallingConvention::CC_SPECIALP; }
bool CallingConvention::isSpecial() const  { return _callingConvention == eCallingConvention::CC_SPECIAL; }

void CallingConvention::setIsUnknown()  { _callingConvention = eCallingConvention::CC_UNKNOWN; }
void CallingConvention::setIsVoidarg()  { _callingConvention = eCallingConvention::CC_VOIDARG; }
void CallingConvention::setIsCdecl()    { _callingConvention = eCallingConvention::CC_CDECL; }
void CallingConvention::setIsEllipsis() { _callingConvention = eCallingConvention::CC_ELLIPSIS; }
void CallingConvention::setIsStdcall()  { _callingConvention = eCallingConvention::CC_STDCALL; }
void CallingConvention::setIsPascal()   { _callingConvention = eCallingConvention::CC_PASCAL; }
void CallingConvention::setIsFastcall() { _callingConvention = eCallingConvention::CC_FASTCALL; }
void CallingConvention::setIsThiscall() { _callingConvention = eCallingConvention::CC_THISCALL; }
void CallingConvention::setIsManual()   { _callingConvention = eCallingConvention::CC_MANUAL; }
void CallingConvention::setIsSpoiled()  { _callingConvention = eCallingConvention::CC_SPOILED; }
void CallingConvention::setIsSpecialE() { _callingConvention = eCallingConvention::CC_SPECIALE; }
void CallingConvention::setIsSpecialP() { _callingConvention = eCallingConvention::CC_SPECIALP; }
void CallingConvention::setIsSpecial()  { _callingConvention = eCallingConvention::CC_SPECIAL; }

/**
 * Returns JSON string value holding calling convention information.
 * @return JSON string value.
 */
Json::Value CallingConvention::getJsonValue() const
{
	if (ccStrings.size() > static_cast<size_t>(_callingConvention))
	{
		return ccStrings[ static_cast<size_t>(_callingConvention) ];
	}
	else
	{
		return ccStrings[ static_cast<size_t>(eCallingConvention::CC_UNKNOWN) ];
	}
}

/**
 * Reads JSON string value holding calling convention information.
 * @param val JSON string value.
 */
void CallingConvention::readJsonValue(const Json::Value& val)
{
	if ( val.isNull() )
	{
		return;
	}

	std::string enumStr = safeGetString(val);
	auto it = std::find(ccStrings.begin(), ccStrings.end(), enumStr);
	if (it == ccStrings.end())
	{
		_callingConvention = eCallingConvention::CC_UNKNOWN;
	}
	else
	{
		_callingConvention = static_cast<eCallingConvention>( std::distance(ccStrings.begin(), it) );
	}
}

bool CallingConvention::operator<(const CallingConvention& cc) const
{
	return _callingConvention < cc._callingConvention;
}

std::ostream& operator<<(std::ostream &out, const CallingConvention& cc)
{
	switch(cc._callingConvention)
	{
		case CallingConvention::eCallingConvention::CC_UNKNOWN:  out << "CC_UNKNOWN"; break;
		case CallingConvention::eCallingConvention::CC_VOIDARG:  out << "CC_VOIDARG"; break;
		case CallingConvention::eCallingConvention::CC_CDECL:    out << "CC_CDECL"; break;
		case CallingConvention::eCallingConvention::CC_ELLIPSIS: out << "CC_ELLIPSIS"; break;
		case CallingConvention::eCallingConvention::CC_STDCALL:  out << "CC_STDCALL"; break;
		case CallingConvention::eCallingConvention::CC_PASCAL:   out << "CC_PASCAL"; break;
		case CallingConvention::eCallingConvention::CC_FASTCALL: out << "CC_FASTCALL"; break;
		case CallingConvention::eCallingConvention::CC_THISCALL: out << "CC_THISCALL"; break;
		case CallingConvention::eCallingConvention::CC_MANUAL:   out << "CC_MANUAL"; break;
		case CallingConvention::eCallingConvention::CC_SPOILED:  out << "CC_SPOILED"; break;
		case CallingConvention::eCallingConvention::CC_SPECIALE: out << "CC_SPECIALE"; break;
		case CallingConvention::eCallingConvention::CC_SPECIALP: out << "CC_SPECIALP"; break;
		case CallingConvention::eCallingConvention::CC_SPECIAL:  out << "CC_SPECIAL"; break;
		default: out << "UNHANDLED"; break;
	}
	return out;
}

} // namespace config
} // namespace retdec
