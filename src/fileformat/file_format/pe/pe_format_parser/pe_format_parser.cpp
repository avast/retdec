/**
 * @file src/fileformat/file_format/pe/pe_format_parser/pe_format_parser.cpp
 * @brief Methods of PeFormatParser class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 * @param fInputFile Pointer to input file
 */
PeFormatParser::PeFormatParser(const FileFormat *fInputFile) : inputFile(fInputFile)
{

}

/**
 * Destructor
 */
PeFormatParser::~PeFormatParser()
{

}

/**
 * @fn unsigned long long PeFormatParser::getDeclaredNumberOfSections() const
 * Get declared number of sections in file
 * @return Declared number of sections in file
 */

/**
 * @fn unsigned long long PeFormatParser::getStoredNumberOfSections() const
 * Get stored number of sections in file
 * @return Stored number of sections in file
 */

/**
 * @fn unsigned long long PeFormatParser::getMachineType() const
 * Get code of target architecture
 * @return Code of target architecture
 */

/**
 * @fn unsigned long long PeFormatParser::getImageBaseAddress() const
 * Get image base address
 * @return Image base address
 */

/**
 * @fn unsigned long long PeFormatParser::getCoffSymbolTableOffset() const
 * Get offset of COFF symbol table
 * @return Offset of COFF symbol table
 */

/**
 * @fn unsigned long long PeFormatParser::getNumberOfCoffSymbols() const
 * Get number of symbols in COFF symbol table
 * @return Number of symbols in COFF symbol table
 */

/**
 * @fn unsigned long long PeFormatParser::getMajorLinkerVersion() const
 * Get major version of used linker
 * @return Major version of used linker
 */

/**
 * @fn unsigned long long PeFormatParser::getMinorLinkerVersion() const
 * Get minor version of used linker
 * @return Minor version of used linker
 */

/**
 * @fn unsigned long long PeFormatParser::getFileFlags() const
 * Get file flags
 * @return File flags as number
 */

/**
 * @fn unsigned long long PeFormatParser::getTimeStamp() const
 * Get time stamp
 * @return Time stamp of file
 */

/**
 * @fn unsigned long long PeFormatParser::getOptionalHeaderSize() const
 * Get size of optional header
 * @return Size of optional header
 */

/**
 * @fn unsigned long long PeFormatParser::getChecksum() const
 * Get file checksum
 * @return File checksum
 */

/**
 * @fn unsigned long long PeFormatParser::getSizeOfStackReserve() const
 * Get size of the stack to reserve
 * @return Size of the stack to reserve
 */

/**
 * @fn unsigned long long PeFormatParser::getSizeOfStackCommit() const
 * Get size of the stack to commit
 * @return Size of the stack to commit
 */

/**
 * @fn unsigned long long PeFormatParser::getSizeOfHeapReserve() const
 * Get size of the local heap space to reserve
 * @return Size of the local heap space to reserve
 */

/**
 * @fn unsigned long long PeFormatParser::getSizeOfHeapCommit() const
 * Get size of the local heap space to commit
 * @return Size of the local heap space to commit
 */

/**
 * @fn unsigned long long PeFormatParser::getSizeOfPeSignature() const
 * Get size of the PE signature
 * @return Size of the PE signature
 */

/**
 * @fn unsigned long long PeFormatParser::getLoadedSizeOfNtHeaders() const
 * Get real loaded size of the NT headers (PE file signature +
 *    COFF file header + optional header + data directories)
 * @return Loaded size of the NT headers
 */

/**
 * @fn unsigned long long PeFormatParser::getAllocatedSizeOfNtHeaders() const
 * Get allocated size of the NT headers (PE file signature +
 *    COFF file header + optional header + data directories)
 * @return Allocated size of the NT headers
 */

/**
 * @fn unsigned long long PeFormatParser::getDeclaredNumberOfDataDirectories() const
 * Get declared number of data-directory entries
 * @return Declared number of data-directory entries
 */

/**
 * @fn unsigned long long PeFormatParser::getStoredNumberOfDataDirectories() const
 * Get stored number of data-directory entries in input file
 * @return Stored number of data-directory entries in input file
 */

/**
 * @fn unsigned long long PeFormatParser::getNumberOfImportedLibraries() const
 * Get number of imported libraries
 * @return Number of imported DLL files
 */

/**
 * @fn unsigned long long PeFormatParser::getNumberOfDelayImportedLibraries() const
 * Get number of delay imported libraries
 * @return Number of delay imported DLL files
 */

/**
 * @fn bool PeFormatParser::isDll() const
 * @return @c true if file is dynamic linked library, @c false otherwise
 */

/**
 * @fn bool PeFormatParser::getEpAddress(unsigned long long &epAddress) const
 * Get virtual address of entry point
 * @param epAddress Into this parameter the resulting number is stored
 * @return @c true if file has entry point and entry point address was successfully detected,
 *    @c false otherwise
 *
 * If file has no associated entry point, @a epAddress is left unchanged
 */

/**
 * @fn bool PeFormatParser::getEpOffset(unsigned long long &epOffset) const
 * Get offset of entry point
 * @param epOffset Into this parameter the resulting number is stored
 * @return @c true if file has entry point and entry point offset was successfully detected,
 *    @c false otherwise
 *
 * If file has no associated entry point, @a epOffset is left unchanged
 */

/**
 * @fn bool PeFormatParser::getSection(unsigned long long secIndex, PeCoffSection &section) const
 * Get information about section with index @a secIndex
 * @param secIndex Index of section (indexed from 0)
 * @param section Into this parameter is stored information about section
 * @return @c true if section index is valid and section is detected, @c false otherwise
 */

/**
 * @fn bool PeFormatParser::getDllFlags(unsigned long long &dllFlags) const
 * Get DLL flags
 * @param dllFlags Into this parameter DLL flags will be stored
 * @return @c true if file is DLL and flags are successfully detected, @c false otherwise
 *
 * If file is not DLL, @a dllFlags is left unchanged
 */

/**
 * @fn bool PeFormatParser::getDataDirectoryRelative(unsigned long long index, unsigned long long &relAddr, unsigned long long &size) const
 * Get information about data directory
 * @param index Index of selected directory
 * @param relAddr Into this parameter is stored relative virtual address of directory
 * @param size Into this parameter is stored size of directory
 * @return @c true if index of selected directory is valid, @c false otherwise
 *
 * If method returns @c false, @a relAddr and @a size are left unchanged.
 */

/**
 * @fn bool PeFormatParser::getDataDirectoryAbsolute(unsigned long long index, unsigned long long &absAddr, unsigned long long &size) const
 * Get information about data directory
 * @param index Index of selected directory
 * @param absAddr Into this parameter is stored absolute virtual address of directory
 * @param size Into this parameter is stored size of directory
 * @return @c true if index of selected directory is valid, @c false otherwise
 *
 * If method returns @c false, @a absAddr and @a size are left unchanged.
 */

/**
 * @fn bool PeFormatParser::getImportedLibraryFileName(unsigned long long index, std::string &fileName) const
 * Get file name of imported library
 * @param index Index of selected library (indexed from 0)
 * @param fileName Into this parameter is stored name of selected library
 * @return @c true if index of selected directory is valid, @c false otherwise
 */

/**
 * @fn std::unique_ptr<PeImport> PeFormatParser::getImport(unsigned long long fileIndex, unsigned long long importIndex) const
 * @param fileIndex Index of selected library (indexed from 0)
 * @param importIndex Index of selected import in selected library (indexed from 0)
 * @return Newly created import if index of library and index of import are valid, @c nullptr otherwise
 */

} // namespace fileformat
} // namespace retdec
