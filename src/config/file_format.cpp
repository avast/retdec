/**
 * @file src/config/file_format.cpp
 * @brief Decompilation configuration manipulation: file format.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/config/file_format.h"

namespace retdec {
namespace config {

bool FileFormat::isUnknown() const    { return _fileFormat == FF_UNKNOWN; }
bool FileFormat::isKnown() const      { return _fileFormat != FF_UNKNOWN; }
bool FileFormat::isElf() const        { return _fileFormat == FF_ELF; }
bool FileFormat::isElf32() const      { return isElf() && is32bit(); }
bool FileFormat::isElf64() const      { return isElf() && is64bit(); }
bool FileFormat::isPe() const         { return _fileFormat == FF_PE; }
bool FileFormat::isPe32() const       { return isPe() && is32bit(); }
bool FileFormat::isPe64() const       { return isPe() && is64bit(); }
bool FileFormat::isCoff() const       { return _fileFormat == FF_COFF; }
bool FileFormat::isCoff32() const     { return isCoff() && is32bit(); }
bool FileFormat::isCoff64() const     { return isCoff() && is64bit(); }
bool FileFormat::isMacho() const      { return _fileFormat == FF_MACHO; }
bool FileFormat::isMacho32() const    { return isMacho() && is32bit(); }
bool FileFormat::isMacho64() const    { return isMacho() && is64bit(); }
bool FileFormat::isIntelHex() const   { return _fileFormat == FF_IHEX; }
bool FileFormat::isIntelHex16() const { return isIntelHex() && is16bit(); }
bool FileFormat::isIntelHex32() const { return isIntelHex() && is32bit(); }
bool FileFormat::isIntelHex64() const { return isIntelHex() && is64bit(); }
bool FileFormat::isRaw() const        { return _fileFormat == FF_RAW; }
bool FileFormat::isRaw32() const      { return isRaw() && is32bit(); }
bool FileFormat::isRaw64() const      { return isRaw() && is64bit(); }
bool FileFormat::is16bit() const      { return isFileClassBits(16); }
bool FileFormat::is32bit() const      { return isFileClassBits(32); }
bool FileFormat::is64bit() const      { return isFileClassBits(64); }
/**
 * Check bit size associated with the file format value.
 * It does not have to be the same as target architecture bit size.
 * @param b Bit size.
 */
bool FileFormat::isFileClassBits(unsigned b) const
{
	return _fileClassBits == b;
}

void FileFormat::setIsUnknown()    { _fileFormat = FF_UNKNOWN; }
void FileFormat::setIsElf()        { _fileFormat = FF_ELF; }
void FileFormat::setIsElf32()      { setIsElf(); setIs32bit(); }
void FileFormat::setIsElf64()      { setIsElf(); setIs64bit(); }
void FileFormat::setIsPe()         { _fileFormat = FF_PE; }
void FileFormat::setIsPe32()       { setIsPe(); setIs32bit(); }
void FileFormat::setIsPe64()       { setIsPe(); setIs64bit(); }
void FileFormat::setIsCoff()       { _fileFormat = FF_COFF; }
void FileFormat::setIsCoff32()     { setIsCoff(); setIs32bit(); }
void FileFormat::setIsCoff64()     { setIsCoff(); setIs64bit(); }
void FileFormat::setIsMacho()      { _fileFormat = FF_MACHO; }
void FileFormat::setIsMacho32()    { setIsMacho(); setIs32bit(); }
void FileFormat::setIsMacho64()    { setIsMacho(); setIs64bit(); }
void FileFormat::setIsIntelHex()   { _fileFormat = FF_IHEX; }
void FileFormat::setIsIntelHex16() { setIsIntelHex(); setIs16bit(); }
void FileFormat::setIsIntelHex32() { setIsIntelHex(); setIs32bit(); }
void FileFormat::setIsIntelHex64() { setIsIntelHex(); setIs64bit(); }
void FileFormat::setIsRaw()        { _fileFormat = FF_RAW; }
void FileFormat::setIsRaw32()      { setIsRaw(); setIs32bit(); }
void FileFormat::setIsRaw64()      { setIsRaw(); setIs64bit(); }
void FileFormat::setIs16bit()      { setFileClassBits(16); }
void FileFormat::setIs32bit()      { setFileClassBits(32); }
void FileFormat::setIs64bit()      { setFileClassBits(64); }
/**
 * Set bit size associated with the file format.
 * It does not have to be the same as target architecture bit size.
 * @param b Bit size.
 */
void FileFormat::setFileClassBits(unsigned b)
{
	_fileClassBits = b;
}

/**
 * Set file format with provided name.
 * Supported names are: {elf, elf32, elf64, pe, pe32, pe64, coff, coff32, coff64}.
 * @param n File format name.
 */
void FileFormat::setName(const std::string& n)
{
	std::string nn = n;
	std::transform(nn.begin(), nn.end(), nn.begin(), ::tolower);

	if (nn == "elf") setIsElf();
	else if (nn == "elf32") setIsElf32();
	else if (nn == "elf64") setIsElf64();
	else if (nn == "pe") setIsPe();
	else if (nn == "pe32") setIsPe32();
	else if (nn == "pe64") setIsPe64();
	else if (nn == "coff") setIsCoff();
	else if (nn == "coff32") setIsCoff32();
	else if (nn == "coff64") setIsCoff64();
	else if (nn == "macho") setIsMacho();
	else if (nn == "macho32") setIsMacho32();
	else if (nn == "macho64") setIsMacho64();
	else if (nn == "ihex") setIsIntelHex();
	else if (nn == "ihex16") setIsIntelHex16();
	else if (nn == "ihex32") setIsIntelHex32();
	else if (nn == "ihex64") setIsIntelHex64();
	else if (nn == "raw") setIsRaw();
	else if (nn == "raw32") setIsRaw32();
	else if (nn == "raw64") setIsRaw64();
	else if (nn == "unknown32") setIs32bit();
	else if (nn == "unknown64") setIs64bit();
	else setIsUnknown();
}

/**
 * Get file format name.
 * @return File format name from this set of possible values:
 * {unknown, elf, pe, coff}.
 */
std::string FileFormat::getName() const
{
	if (isElf()) return "elf";
	else if (isPe()) return "pe";
	else if (isCoff()) return "coff";
	else if (isIntelHex()) return "ihex";
	else if (isMacho()) return "macho";
	else if (isRaw()) return "raw";
	else return "unknown";
}

/**
 * Get bit size associated with the file format.
 * It does not have to be the same as target architecture bit size.
 * @return Bit size. If not set return default value = 0.
 */
unsigned FileFormat::getFileClassBits() const
{
	return _fileClassBits;
}

/**
 * Returns JSON string value holding file format information.
 * @return JSON string value.
 */
Json::Value FileFormat::getJsonValue() const
{
	if (getFileClassBits())
		return getName() + std::to_string(getFileClassBits());
	else
		return getName();
}

/**
 * Reads JSON string value holding file format information.
 * @param val JSON string value.
 */
void FileFormat::readJsonValue(const Json::Value& val)
{
	if ( val.isNull() )
	{
		return;
	}
	setName( safeGetString(val) );
}

} // namespace config
} // namespace retdec
