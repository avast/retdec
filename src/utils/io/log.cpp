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

Logger Log::info()
{
	return get(Log::Type::Info);
}

void Log::phase(const std::string& phase, const Log::Action& action)
{
	Log::info() << action << phase << Log::ElapsedTime << std::endl;
}

Logger Log::debug()
{
	return Logger(get(Log::Type::Debug));
}

Logger Log::error()
{
	return Logger(get(Log::Type::Error));
}

}
}
}
