/**
 * @file include/fileformat/format_factory.h
 * @brief Factory for creating file detectors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_FORMAT_FACTORY_H
#define FILEFORMAT_FORMAT_FACTORY_H

#include <memory>

#include "fileformat/file_format/file_format.h"

namespace fileformat {

std::unique_ptr<FileFormat> createFileFormat(const std::string &filePath, retdec_config::Config *config = nullptr, LoadFlags loadFlags = LoadFlags::NONE);

} // namespace fileformat

#endif
