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
 * Shortcut for Logger(Log::get(Log::Type::Info)).
 *
 * Creates temporary copy of Info logger. This is particulart
 * useful when changing color of the output. On destruction
 * color is changed to default.
 */
Logger info();

/**
 * Shortcut for Logger(Log::get(Log::Type::Debug)).
 *
 * Creates temporary copy of Debug logger. This is particulart
 * useful when changing color of the output. On destruction
 * color is changed to default.
 */
Logger debug();

/**
 * Shortcut for Logger(Log::get(Log::Type::Error)).
 *
 * Creates temporary copy of Error logger. This is particulart
 * useful when changing color of the output. On destruction
 * color is changed to default.
 */
Logger error();

void phase(const std::string& phaseId, const Log::Action& action = Log::Phase);

};

}
}
}


#endif
