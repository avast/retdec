#include "retdec/utils/io/log.h"

namespace retdec {
namespace utils {
namespace io {

/**
 * Structure containing initialized/default loggers.
 */
static Logger::Ptr loggers[static_cast<int>(Log::Type::Undefined)+1] = {
	/*Info*/      /*default*/ nullptr,
	/*Debug*/     /*default*/ nullptr,
	/*Error*/     Logger::Ptr(new Logger(std::cerr)),
	/*Undefined*/ Logger::Ptr(new Logger(std::cout, false))
};

static Logger defaultLogger(std::cout, true);

Logger& Log::get(const Log::Type& logType)
{
	if (auto logger = loggers[static_cast<int>(logType)].get())
		return *logger;

	return defaultLogger;
}

void Log::set(const Log::Type& lt, Logger::Ptr&& logger)
{
	if (lt != Log::Type::Undefined) {
		loggers[static_cast<int>(lt)] = std::move(logger);
	}
}

Logger& Log::info()
{
	return get(Log::Type::Info);
}

Logger& Log::phase(const std::string& phase, const Log::Action& action)
{
	return Log::info() << Log::Color::Yellow << action
		<< phase << Log::ElapsedTime
		<< Log::Color::Default
		<< std::endl;
}

Logger& Log::debug()
{
	return get(Log::Type::Debug);
}

Logger& Log::error()
{
	return get(Log::Type::Error);
}

}
}
}
