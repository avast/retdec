#ifndef RETDEC_UTILS_IO_LOGGER_H
#define RETDEC_UTILS_IO_LOGGER_H

#include <fstream>
#include <iostream>
#include <sstream>
#include <memory>

namespace retdec {
namespace utils {
namespace io {

namespace Log {

enum Action: int {
	Phase,
	SubPhase,
	SubSubPhase,
	ElapsedTime,
	Error,
	Warning,
	NoAction
};

enum class Color: int {
	Red,
	Green,
	Blue,
	Yellow,
	DarkCyan,
	Default
};

}

/**
 * @brief Provides Logger inteface that is used for logging events during decompilation.
 */
class Logger {
public:
	using Ptr = std::unique_ptr<Logger>;

protected:
	typedef std::ostream& (*StreamManipulator) (std::ostream&);

public:
	Logger(std::ostream& stream, bool verbose = true);
	Logger(const Logger& logger);
	~Logger();

	template <typename T>
	Logger& operator << (const T& p);

	Logger& operator << (const StreamManipulator& manip);
	Logger& operator << (const Log::Action& ia);
	Logger& operator << (const Log::Color& lc);

private:
	bool isRedirected(const std::ostream& stream) const;

protected:
	std::ostream& _out;

	bool _verbose = true;
	Log::Color _currentBrush = Log::Color::Default;
};

class FileLogger : public Logger {
public:
	FileLogger(const std::string& file, bool verbose = true);

private:
	std::ofstream _file;
};

template<typename T>
inline Logger& Logger::operator << (const T& p)
{
	if (!_verbose)
		return *this;

	_out << p;

	return *this;
}

inline Logger& Logger::operator << (const Logger::StreamManipulator& p)
{
	if (!_verbose)
		return *this;

	_out << p;

	return *this;
}

}
}
}

#endif
