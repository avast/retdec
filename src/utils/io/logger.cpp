#include <iomanip>
#include <map>
#include <sstream>

#if __has_include(<unistd.h>)
#include <unistd.h>
auto isConsole = isatty;
auto fileDescriptor = fileno;
#else
#include <io.h>
auto isConsole = _isatty;
auto fileDescriptor = _fileno;
#endif

#include "retdec/utils/time.h"
#include "retdec/utils/io/logger.h"

namespace retdec {
namespace utils {
namespace io {

//////////
//
// Logger
//
//////

Logger::Logger(std::ostream& stream, bool verbose):
	_out(stream),
	_verbose(verbose)
{
}

Logger& Logger::operator << (const Log::Action& p)
{
	if (p == Log::Phase) {
		return *this << "Running phase: ";
	}
	if (p == Log::SubPhase) {
		return *this << " -> ";
	}
	if (p == Log::SubSubPhase) {
		return *this << "     -> ";
	}
	if (p == Log::SubSubPhase) {
		return *this << "         -> ";
	}
	if (p == Log::Error) {
		return *this << "Error: ";
	}
	if (p == Log::Warning) {
		return *this << Log::Color::DarkCyan << "Warning: ";
	}
	if (p == Log::ElapsedTime) {
		std::stringstream formatted;
		formatted << std::fixed << std::setprecision(2) << getElapsedTime();
		return *this << " ( " << formatted.str() << "s )";
	}

	return *this;
}

Logger& Logger::operator << (const Log::Color& lc)
{
	static std::string ansiMap[static_cast<int>(Log::Color::Default)+1] = {
		/*Log::Color::Red*/     "\u001b[0;1;31m",
		/*Log::Color::Green*/   "\u001b[0;1;32m",
		/*Log::Color::Blue*/    "\u001b[0;1;34m",
		/*Log::Color::Yellow*/  "\u001b[0;1;33m",
		/*Log::Color::DarkCyan*/"\u001b[0;1;36m",
		/*Log::Color::Default*/ "\u001b[0m"
	};

	if (isRedirected(_out))
		return *this;

	return *this << ansiMap[static_cast<int>(lc)];
}

bool Logger::isRedirected(const std::ostream& stream) const
{
	if (stream.rdbuf() == std::cout.rdbuf()) {
		return isConsole(fileDescriptor(stdout)) == 0;
	}
	else if (stream.rdbuf() == std::cerr.rdbuf()) {
		return isConsole(fileDescriptor(stderr)) == 0;
	}

	return true;
}

std::string Logger::buffer() const
{
	return _buffer.str();
}

//////////
//
// FileLogger
//
//////

FileLogger::FileLogger(const std::string& file, bool verbose):
	Logger(_file, verbose)
{
	_file.open(file, std::ofstream::out);
	if (!_file)
		throw std::runtime_error("unable to open file \""+file+"\" for writing.");
}

}
}
}
