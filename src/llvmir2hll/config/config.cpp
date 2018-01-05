/**
* @file src/llvmir2hll/config/config.cpp
* @brief Implementation of the base class for all configs.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/config/config.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs the exception with the given error message.
*/
ConfigError::ConfigError(const std::string &message):
	message(message) {}

const char *ConfigError::what() const noexcept {
	return message.c_str();
}

const std::string &ConfigError::getMessage() const noexcept {
	return message;
}

Config::~Config() = default;

} // namespace llvmir2hll
} // namespace retdec
