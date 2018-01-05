/**
 * @file include/retdec/fileformat/format_factory.h
 * @brief Factory for creating file detectors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FORMAT_FACTORY_H
#define RETDEC_FILEFORMAT_FORMAT_FACTORY_H

#include <memory>

#include "retdec/fileformat/file_format/file_format.h"

namespace retdec {
namespace fileformat {

std::unique_ptr<FileFormat> createFileFormat(const std::string &filePath, retdec::config::Config *config = nullptr, LoadFlags loadFlags = LoadFlags::NONE);

} // namespace fileformat
} // namespace retdec

#endif
