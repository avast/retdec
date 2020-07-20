#ifndef RETDEC_UTILS_IO_LOG_H
#define RETDEC_UTILS_IO_LOG_H

#include "retdec/utils/io/logger.h"

namespace retdec {
namespace utils {
namespace io {

namespace Log {

enum class Type : int {
	Info = 0,
	Debug,
	Error,
	Undefined
};

/**
 * Returns corresponding initialized logger for logType provided
 * as parameter. At the beginning all the logger types are initialized
 * to undefined logger.
 */
Logger& get(const Type& logType);

void set(const Type& logType, Logger::Ptr&& logger);

/**
 * Shortcut for Log::get(Log::Type::Info).
 */
Logger& info();

/**
 * Shortcut for printing phase:
 *
 * Log::info() << Log::Color::Yellow << action
 *             << phase << Log::ElapsedTime
 *             << LogL::Color::Default << std::endl;;
 */
Logger& phase(const std::string& phase, const Log::Action& action = Log::Phase);

/**
 * Shortcut for Log::get(Log::Type::Debug).
 */
Logger& debug();

/**
 * Shortcut for Log::get(Log::Type::Error).
 */
Logger& error();

};

}
}
}


#endif
