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

std::unique_ptr<FileFormat> createFileFormat(
		const std::string &filePath,
		const std::string &dllListFile,
		bool isRaw = false,
		LoadFlags loadFlags = LoadFlags::NONE);

std::unique_ptr<FileFormat> createFileFormat(
		const std::string &filePath,
		bool isRaw = false,
		LoadFlags loadFlags = LoadFlags::NONE);

std::unique_ptr<FileFormat> createFileFormat(
		std::istream &inputStream,
		bool isRaw = false,
		LoadFlags loadFlags = LoadFlags::NONE);

std::unique_ptr<FileFormat> createFileFormat(
		const std::uint8_t *data,
		std::size_t size,
		bool isRaw = false,
		LoadFlags loadFlags = LoadFlags::NONE);

} // namespace fileformat
} // namespace retdec

#endif
