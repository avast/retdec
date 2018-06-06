/**
 * @file src/config/architecture.cpp
 * @brief Decompilation configuration manipulation: architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/config/architecture.h"
#include "retdec/utils/string.h"

namespace {

const std::string ARCH_UNKNOWN = "unknown";
const std::string ARCH_MIPS    = "mips";
const std::string ARCH_PIC32   = "pic32";
const std::string ARCH_ARM     = "arm";
const std::string ARCH_THUMB   = "thumb";
const std::string ARCH_x86     = "x86";
const std::string ARCH_PPC     = "powerpc";

const std::string JSON_name    = "name";
const std::string JSON_endian  = "endian";
const std::string JSON_bitSize = "bitSize";

const std::string JSON_val_little = "little";
const std::string JSON_val_big    = "big";

} // anonymous namespace

namespace retdec {
namespace config {

bool Architecture::isArmOrThumb() const { return isArm() || isThumb(); }
bool Architecture::isPic32() const      { return isArch(eArch::PIC32); }
bool Architecture::isArm() const        { return isArch(eArch::ARM); }
bool Architecture::isThumb() const      { return isArch(eArch::THUMB); }
bool Architecture::isX86() const        { return isArch(eArch::X86); }
bool Architecture::isX86_16() const     { return isX86() && getBitSize() == 16; }
bool Architecture::isX86_32() const     { return isX86() && getBitSize() == 32; }
bool Architecture::isX86_64() const     { return isX86() && getBitSize() == 64; }
bool Architecture::isPpc() const        { return isArch(eArch::PPC); }
bool Architecture::isKnown() const      { return !isUnknown(); }
bool Architecture::isUnknown() const    { return isArch(eArch::UNKNOWN); }
bool Architecture::isMips() const       { return isArch(eArch::MIPS); }
bool Architecture::isMipsOrPic32() const{ return isMips() || isPic32(); }

/**
 * Checks if this architecture instance matches with the provided architecture name.
 * Matching is successful if instance's name contains (case insensitive) the provided name.
 * @param a Name to match with.
 * @return @c True if matching successful, @c false otherwise.
 */
bool Architecture::isArch(const std::string& a) const
{
	return retdec::utils::containsCaseInsensitive(_name, a);
}

bool Architecture::isArch(eArch a) const
{
	return _arch == a;
}

bool Architecture::isEndianLittle() const  { return _endian == E_LITTLE; }
bool Architecture::isEndianBig() const     { return _endian == E_BIG; }
bool Architecture::isEndianUnknown() const { return _endian == E_UNKNOWN; }
bool Architecture::isEndianKnown() const   { return !isEndianUnknown(); }

void Architecture::setIsUnknown() { setName(ARCH_UNKNOWN); }
void Architecture::setIsMips()    { setName(ARCH_MIPS); }
void Architecture::setIsPic32()   { setName(ARCH_PIC32); }
void Architecture::setIsArm()     { setName(ARCH_ARM); }
void Architecture::setIsThumb()   { setName(ARCH_THUMB); }
void Architecture::setIsX86()     { setName(ARCH_x86); }
void Architecture::setIsPpc()     { setName(ARCH_PPC); }

void Architecture::setIsEndianLittle()           { _endian = E_LITTLE; }
void Architecture::setIsEndianBig()              { _endian = E_BIG; }
void Architecture::setIsEndianUnknown()          { _endian = E_UNKNOWN; }
void Architecture::setBitSize(unsigned bs)       { _bitSize = bs; }

unsigned Architecture::getBitSize() const  { return _bitSize; }

/**
 * @return Byte size computed from bit size by dividing it by 8.
 */
unsigned Architecture::getByteSize() const { return _bitSize/8; }

/**
 * @return Architecture name. For unknown architecture returns "unknown" string.
 */
std::string Architecture::getName() const
{
	return _name.empty() ? ARCH_UNKNOWN : _name;
}

void Architecture::setName(const std::string& n)
{
	_name = n;
	setArch();
}

void Architecture::setArch()
{
	if (retdec::utils::containsCaseInsensitive(_name, ARCH_UNKNOWN))
	{
		_arch = eArch::UNKNOWN;
	}
	else if (retdec::utils::containsCaseInsensitive(_name, ARCH_MIPS))
	{
		_arch = eArch::MIPS;
	}
	else if (retdec::utils::containsCaseInsensitive(_name, ARCH_PIC32))
	{
		_arch = eArch::PIC32;
	}
	else if (retdec::utils::containsCaseInsensitive(_name, ARCH_ARM))
	{
		_arch = eArch::ARM;
	}
	else if (retdec::utils::containsCaseInsensitive(_name, ARCH_THUMB))
	{
		_arch = eArch::THUMB;
	}
	else if (retdec::utils::containsCaseInsensitive(_name, ARCH_x86))
	{
		_arch = eArch::X86;
	}
	else if (retdec::utils::containsCaseInsensitive(_name, ARCH_PPC))
	{
		_arch = eArch::PPC;
	}
}

/**
 * Returns JSON object (associative array) holding architecture information.
 * @return JSON object.
 */
Json::Value Architecture::getJsonValue() const
{
	Json::Value arch;

	arch[JSON_name] = getName();
	arch[JSON_bitSize] = getBitSize();
	if (isEndianLittle())
		arch[JSON_endian] = JSON_val_little;
	else if (isEndianBig())
		arch[JSON_endian] = JSON_val_big;

	return arch;
}

/**
 * Reads JSON object (associative array) holding architecture information.
 * @param val JSON object.
 */
void Architecture::readJsonValue(const Json::Value& val)
{
	if ( val.isNull() || !val.isObject() )
	{
		return;
	}

	setName( safeGetString(val, JSON_name) );
	setBitSize( safeGetUint(val, JSON_bitSize) );

	std::string e = safeGetString(val, JSON_endian);
	if (e == JSON_val_big)
		setIsEndianBig();
	else if (e == JSON_val_little)
		setIsEndianLittle();
	else
		setIsEndianUnknown();
}

} // namespace config
} // namespace retdec
