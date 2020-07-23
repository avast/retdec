/**
* @file include/retdec/utils/io/logger.h
* @brief Provides unified logging interface.
* @copyright (c) 2020 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_IO_LOG_H
#define RETDEC_UTILS_IO_LOG_H

#include "retdec/utils/io/logger.h"

namespace retdec {
namespace utils {
namespace io {

class Log {
public:
	/**
	 * Each type represents different logging style. For each
	 * type is provided a logger by calling Log::get function
	 */
	enum class Type : int {
		Info = 0,
		Debug,
		Error,
		Undefined
	};

	using Color = Logger::Color;
	using Action = Logger::Action;

public:
	/**
	 * Returns corresponding initialized logger for logType provided
	 * as parameter. At the beginning all the logger types are initialized
	 * to default logger.
	 *
	 * For debug/info:
	 *  - verbose
	 *  - logs to std::out
	 *
	 * For error:
	 *  - verbose
	 *  - logs to std::err
	 */
	static Logger& get(const Type& logType);

	/**
	 * Sets appropriate logger based on logType value.
	 */
	static void set(const Type& logType, Logger::Ptr&& logger);

	/**
	 * Shortcut for Logger(Log::get(Log::Type::Info)).
	 *
	 * Creates temporary copy of Info logger. This is particularly
	 * useful when changing color of the output. On destruction
	 * color is changed to default.
	 */
	static Logger info();

	/**
	 * Shortcut for Logger(Log::get(Log::Type::Debug)).
	 *
	 * Creates temporary copy of Debug logger. This is particularly
	 * useful when changing color of the output. On destruction
	 * color is changed to default.
	 */
	static Logger debug();

	/**
	 * Shortcut for Logger(Log::get(Log::Type::Error)).
	 *
	 * Creates temporary copy of Error logger. This is particularly
	 * useful when changing color of the output. On destruction
	 * color is changed to default.
	 */
	static Logger error();

	/**
	 * Shortcut for Log::info() << action << phaseId << Log::Action::ElapsedTime << std::endl.
	 */
	static void phase(
		const std::string& phaseId,
		const Log::Action& action = Log::Action::Phase);

public:
	/**
	 * Representation of Error Action that can be inserted into logger.
	 * Shortcut for Log::Action::Error
	 */
	static const Action Error;

	/**
	 * Representation of Warning Action that can be inserted into logger.
	 * Shortcut for Log::Action::Warning
	 */
	static const Action Warning;

	/**
	 * Representation of Phase Action that can be inserted into logger.
	 * Shortcut for Log::Action::Phase
	 */
	static const Action Phase;

	/**
	 * Representation of SubPhase Action that can be inserted into logger.
	 * Shortcut for Log::Action::SubPhase
	 */
	static const Action SubPhase;

	/**
	 * Representation of SubSubPhase Action that can be inserted into logger.
	 * Shortcut for Log::Action::SubSubPhase
	 */
	static const Action SubSubPhase;

	/**
	 * Representation of ElapsedTime Action that can be inserted into logger.
	 * Shortcut for Log::Action::ElapsedTime
	 */
	static const Action ElapsedTime;

private:
	/**
	 * Structure containing initialized/default loggers.
	 */
	static Logger::Ptr writers[static_cast<int>(Type::Undefined)+1];

	/**
	 * Fallback logger. In case of bad initialization of the writers
	 * this logger is used as fallback to log (calling set with nullptr).
	 */
	static Logger defaultLogger;
};

}
}
}


#endif
