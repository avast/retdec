#include <iomanip>
#include <map>
#include <sstream>

#if __has_include(<io.h>)
#include <io.h>
#else
#include <unistd.h>
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

Logger::Logger(const Logger& from):
	Logger(from._out, from._verbose)
{
	_currentBrush = from._currentBrush;
}

Logger::~Logger()
{
	if (_currentBrush != Color::Default)
		*this << Color::Default;
}

Logger& Logger::operator << (const Action& p)
{
	if (p == Phase) {
		return *this << Color::Yellow << "Running phase: ";
	}
	if (p == SubPhase) {
		return *this << Color::Yellow << " -> ";
	}
	if (p == SubSubPhase) {
		return *this << Color::Yellow << "     -> ";
	}
	if (p == SubSubPhase) {
		return *this << Color::Yellow << "         -> ";
	}
	if (p == Error) {
		return *this << "Error: ";
	}
	if (p == Warning) {
		return *this << Color::DarkCyan << "Warning: ";
	}
	if (p == ElapsedTime) {
		std::stringstream formatted;
		formatted << std::fixed << std::setprecision(2) << getElapsedTime();
		return *this << " ( " << formatted.str() << "s )";
	}

	return *this;
}

Logger& Logger::operator << (const Color& lc)
{
	static std::string ansiMap[static_cast<int>(Color::Default)+1] = {
		/*Color::Red*/     "\u001b[0;1;31m",
		/*Color::Green*/   "\u001b[0;1;32m",
		/*Color::Blue*/    "\u001b[0;1;34m",
		/*Color::Yellow*/  "\u001b[0;1;33m",
		/*Color::DarkCyan*/"\u001b[0;1;36m",
		/*Color::Default*/ "\u001b[0m"
	};

	if (isRedirected(_out))
		return *this;

	_currentBrush = lc;
	return *this << ansiMap[static_cast<int>(lc)];
}

bool Logger::isRedirected(const std::ostream& stream) const
{
#if __has_include(<io.h>)
	// On windows POSIX functions isatty and fileno
	// generate Warning.
	auto isConsole = _isatty;
	auto fileDescriptor = _fileno;
#else
	auto isConsole = isatty;
	auto fileDescriptor = fileno;
#endif

	if (stream.rdbuf() == std::cout.rdbuf()) {
		return isConsole(fileDescriptor(stdout)) == 0;
	}
	else if (stream.rdbuf() == std::cerr.rdbuf()) {
		return isConsole(fileDescriptor(stderr)) == 0;
	}

	return true;
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
