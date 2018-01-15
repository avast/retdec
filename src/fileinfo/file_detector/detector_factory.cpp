/**
 * @file src/fileinfo/file_detector/detector_factory.cpp
 * @brief Functions for creating file detectors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_detector/coff_detector.h"
#include "fileinfo/file_detector/elf_detector.h"
#include "fileinfo/file_detector/intel_hex_detector.h"
#include "fileinfo/file_detector/macho_detector.h"
#include "fileinfo/file_detector/pe_detector.h"
#include "fileinfo/file_detector/raw_data_detector.h"

using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Create file detector
 * @param pathToInputFile Path to input file
 * @param fileFormat Format of input file
 * @param finfo Instance of class for storing information about input file
 * @param searchPar Parameters for detection of used compiler or packer
 * @param loadFlags Load flags
 * @return Pointer to instance of detector or @c nullptr if any error
 *
 * Pointer to detector is dynamically allocated and must be released (otherwise there is a memory leak).
 * If format of input file is not supported, function will return @c nullptr.
 */
FileDetector* createFileDetector(std::string pathToInputFile, retdec::fileformat::Format fileFormat, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags)
{
	switch(fileFormat)
	{
		case Format::PE:
			return new PeDetector(pathToInputFile, finfo, searchPar, loadFlags);
		case Format::ELF:
			return new ElfDetector(pathToInputFile, finfo, searchPar, loadFlags);
		case Format::COFF:
			return new CoffDetector(pathToInputFile, finfo, searchPar, loadFlags);
		case Format::MACHO:
			return new MachODetector(pathToInputFile, finfo, searchPar, loadFlags);
		case Format::INTEL_HEX:
			return new IntelHexDetector(pathToInputFile, finfo, searchPar, loadFlags);
		case Format::RAW_DATA:
			return new RawDataDetector(pathToInputFile, finfo, searchPar, loadFlags);
		default:
			return nullptr;
	}
}

} // namespace fileinfo
