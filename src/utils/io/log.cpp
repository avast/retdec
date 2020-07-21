#include "retdec/utils/io/log.h"

namespace retdec {
namespace utils {
namespace io {

/*
 * Initalization of Shorctuts
 */
const Log::Action Log::Error = Log::Action::Error;
const Log::Action Log::Warning = Log::Action::Warning;
const Log::Action Log::Phase = Log::Action::Phase;
const Log::Action Log::SubPhase = Log::Action::SubPhase;
const Log::Action Log::SubSubPhase = Log::Action::SubSubPhase;
const Log::Action Log::ElapsedTime = Log::Action::ElapsedTime;

Logger::Ptr Log::writers[] = {
	/*Info*/      /*default*/ nullptr,
	/*Debug*/     /*default*/ nullptr,
	/*Error*/     Logger::Ptr(new Logger(std::cerr)),
	/*Undefined*/ Logger::Ptr(new Logger(std::cout, false))
};

Logger Log::defaultLogger(std::cout, true);

Logger& Log::get(const Log::Type& logType)
{
	if (auto logger = writers[static_cast<int>(logType)].get())
		return *logger;

	return defaultLogger;
}

void Log::set(const Log::Type& lt, Logger::Ptr&& logger)
{
	if (lt != Log::Type::Undefined) {
		writers[static_cast<int>(lt)] = std::move(logger);
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
