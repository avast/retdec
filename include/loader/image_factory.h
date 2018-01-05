/**
 * @file include/loader/image_factory.h
 * @brief Factory for creating loaded images.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_IMAGE_FACTORY_H
#define LOADER_IMAGE_FACTORY_H

#include <memory>
#include <string>

#include "loader/loader/image.h"

namespace loader {

std::unique_ptr<Image> createImage(const std::string& filePath, retdec_config::Config *config = nullptr);
std::unique_ptr<Image> createImage(const std::shared_ptr<fileformat::FileFormat>& fileFormat);

} // namespace loader

#endif
