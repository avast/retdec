/**
 * @file src/unpackertool/arg_handler.cpp
 * @brief ArgHandler class implementation for command line argument parsing.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstring>
#include <ostream>

#include "arg_handler.h"

namespace retdec {
namespace unpackertool {

/**
 * Constructor.
 *
 * @param runString Run string to be shown in help.
 */
ArgHandler::ArgHandler(const std::string& runString) : _runString(runString), _count(0)
{
}

/**
 * Destructor.
 */
ArgHandler::~ArgHandler()
{
	for (auto& pair : _argMap)
	{
		// Delete only the ones stored for short option
		// Long options contains the same pointer as short option
		if (pair.first.length() == 1 && pair.second)
			delete pair.second;
	}
}

/**
 * Set the run string to be shown in help.
 *
 * @param runString Run string to set.
 */
void ArgHandler::setRunString(const std::string& runString)
{
	_runString = runString;
}

/**
 * Returns the run string to be shown in help.
 *
 * @return Run string.
 */
const std::string& ArgHandler::getRunString() const
{
	return _runString;
}

/**
 * Register a command-line argument to the handler. The registration may fail if
 * there is already an argument with the specified short or long option.
 *
 * @param opt Short option of an argument.
 * @param longOpt Long option of an argument.
 * @param hasInput True if the argument has an input, defaultly false.
 *
 * @return True if the registration was successful, otherwise false.
 */
bool ArgHandler::registerArg(char opt, const std::string& longOpt, bool hasInput /*= false*/)
{
	// '-' is reserved character for long options
	if (opt == '-')
		return false;

	std::string shortOpt(&opt, 1);
	// Test if there is command with that option
	if (_argMap.find(shortOpt) != _argMap.end())
		return false;

	// Test also long option if it is not missing
	if (!longOpt.empty())
	{
		if (_argMap.find(longOpt) != _argMap.end())
			return false;
	}

	_argMap[shortOpt] = new ArgInfo(opt, longOpt, hasInput);
	if (!longOpt.empty())
	{
		// Long option and short option are both using the same ArgInfo
		_argMap[longOpt] = _argMap[shortOpt];
	}

	return true;
}

/**
 * Array like access to the command-line arguments. Accessor is short option.
 *
 * @param opt Short option of an argument.
 *
 * @return ArgData if they are available, nullptr otherwise.
 */
const ArgData* ArgHandler::operator [](char opt) const
{
	std::string optStr(&opt, 1);
	return (*this)[optStr];
}

/**
 * Array like access to the command-line arguments. Accessor is short or long option.
 *
 * @param opt Short or long option of an argument.
 *
 * @return ArgData if they are available, nullptr otherwise.
 */
const ArgData* ArgHandler::operator [](const std::string& opt) const
{
	// Try to find the option by short option
	ArgMap::const_iterator itr = _argMap.find(opt);
	if (itr == _argMap.end())
		return nullptr;

	return (*itr).second->_data;
}

/**
 * Return the raw inputs in command-line arguments.
 *
 * @return The raw string list.
 */
const std::vector<std::string>& ArgHandler::getRawInputs() const
{
	return _rawInputs;
}

/**
 * Sets the message shown in help.
 *
 * @param helpString Message shown in help.
 */
void ArgHandler::setHelp(const std::string& helpString)
{
	_helpString = helpString;
}

/**
 * Gets the message shown in help.
 *
 * @return Message shown in help.
 */
const std::string& ArgHandler::getHelp() const
{
	return _helpString;
}

/**
 * Parses the arguments from the command-line.
 *
 * @param argc Number of arguments.
 * @param argv Raw argument values.
 *
 * @return True if the parsing was successful, otherwise false.
 */
bool ArgHandler::parse(int argc, char** argv)
{
	resetArgData();

	// argc should never be less than 1
	if (argc < 1)
		return false;

	// skip the argv[0] as it is the executable name
	for (int i = 1; i < argc; ++i)
	{
		ArgInfo* arg = nullptr;

		// We expect it to be a long option
		if (strncmp(argv[i], "--", 2) == 0)
		{
			std::string longOpt = std::string(argv[i] + 2);

			// -- terminates the argument input in the most cases
			if (longOpt.empty())
				break;

			ArgMap::iterator itr = _argMap.find(longOpt);
			if (itr == _argMap.end())
				return false;

			arg = (*itr).second;
		}
		// else it is short option
		else if (argv[i][0] == '-')
		{
			// there should be no more than 1 character after '-'
			if (strlen(argv[i]) > 2)
				return false;

			ArgMap::iterator itr = _argMap.find(std::string(&argv[i][1], 1));
			if (itr == _argMap.end())
				return false;

			arg = (*itr).second;
		}
		// Doesn't belong to any argument, it is a raw input
		else
		{
			_rawInputs.push_back(std::string(argv[i]));
			continue;
		}

		// Option already used
		if (arg->_data->used)
			return false;

		arg->_data->used = true;
		if (arg->_hasInput)
		{
			// check if we won't access out of argv memory
			if (i + 1 >= argc)
				return false;

			arg->_data->input = argv[i + 1];
			i += 1; // skip this one arg as it was used as the data
		}

		_count++;
	}

	return true;
}

/**
 * Returns the number of used arguments.
 *
 * @return Number of used arguments.
 */
uint32_t ArgHandler::count() const
{
	return _count;
}

/**
 * Resets the used arguments.
 */
void ArgHandler::resetArgData()
{
	_count = 0;
	ArgMap::iterator end = _argMap.end();
	for (ArgMap::iterator itr = _argMap.begin(); itr != end; ++itr)
	{
		(*itr).second->_data->used = false;
		(*itr).second->_data->input = std::string();
	}
	_rawInputs.clear();
}

/**
 * Prints the help with the registered arguments.
 *
 * @param out The output stream to print to.
 * @param handler The argument handler itself.
 *
 * @return The output stream it prints to.
 */
std::ostream& operator <<(std::ostream& out, const ArgHandler& handler)
{
	out << "Generic Unpacker\r\n"
		<< "Usage:\r\n"
		<< "\t" << handler.getRunString() << "\r\n" << std::endl;

	out << handler.getHelp();
	out.flush();
	return out;
}

} // namespace unpackertool
} // namespace retdec
