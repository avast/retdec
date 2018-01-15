/**
 * @file src/fileinfo/file_detector/detector_factory.h
 * @brief Functions for creating file detectors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_DETECTOR_DETECTOR_FACTORY_H
#define FILEINFO_FILE_DETECTOR_DETECTOR_FACTORY_H

#include "fileinfo/file_detector/file_detector.h"

namespace fileinfo {

FileDetector* createFileDetector(std::string pathToInputFile, retdec::fileformat::Format fileFormat, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags);

} // namespace fileinfo

#endif
