/**
 * @file include/retdec/loader/image_factory.h
 * @brief Factory for creating loaded images.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_IMAGE_FACTORY_H
#define RETDEC_LOADER_IMAGE_FACTORY_H

#include <memory>
#include <string>

#include "retdec/loader/loader/image.h"

namespace loader {

std::unique_ptr<Image> createImage(const std::string& filePath, retdec::config::Config *config = nullptr);
std::unique_ptr<Image> createImage(const std::shared_ptr<fileformat::FileFormat>& fileFormat);

} // namespace loader

#endif
