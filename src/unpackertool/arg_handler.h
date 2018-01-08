/**
 * @file src/unpackertool/arg_handler.h
 * @brief ArgHandler class declaration for command line argument parsing.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_ARG_HANDLER_H
#define UNPACKERTOOL_ARG_HANDLER_H

#include <map>
#include <string>
#include <vector>

namespace retdec {
namespace unpackertool {

/**
 * @brief Argument data for command-line arguments.
 *
 * ArgData represents the information whether command-line argument
 * was used or not. If it is used, this structure also contains the
 * input data of the argument.
 */
struct ArgData
{
	ArgData() : used(false), input() {} ///< Constructor.
	ArgData(const ArgData& data) : used(data.used), input(data.input) {} ///< Copy constructor.

	/**
	 * Functor for usage in conditions.
	 *
	 * @return True if command-line argument was used, otherwise false.
	 */
	operator bool() const
	{
		return used;
	}

	bool used; ///< Argument usage.
	std::string input; ///< Input text of argument.
};

/**
 * @brief Metadata for commend-line arguments.
 *
 * ArgInfo represents the metadata for all available command-line
 * arguments. If the command-line argument is used during the program
 * startup it also contains the data of the command-line argument.
 * If the argument is marked as input argument, the next argument will
 * be considered as an input to this argument.
 */
struct ArgInfo
{
	ArgInfo(char opt, const std::string& longOpt, bool hasInput)
		: _opt(opt), _longOpt(longOpt), _hasInput(hasInput), _data(new ArgData) ///< Constructor.
	{}

	~ArgInfo() ///< Destructor.
	{
		if (_data)
			delete _data;
	}

	char _opt; ///< Short option.
	std::string _longOpt; ///< Long option.
	bool _hasInput; ///< Has an input.
	ArgData* _data; ///< Data.
};

/**
 * @brief Command-line argument handler.
 *
 * ArgHandler handles the parsing of command-line arguments. It offers
 * the argument registration, checking, help message building and parsing.
 * Supports both short and long option arguments.
 */
class ArgHandler
{
	using ArgMap = std::map<std::string, ArgInfo*>; ///< Mapping of option to ArgInfo.

public:
	ArgHandler(const std::string& runString);
	~ArgHandler();

	void setRunString(const std::string& scriptName);
	const std::string& getRunString() const;

	void setHelp(const std::string& helpString);
	const std::string& getHelp() const;

	bool parse(int argc, char** argv);
	std::uint32_t count() const;

	bool registerArg(char opt, const std::string& longOpt, bool hasInput = false);
	const ArgData* operator [](char opt) const;
	const ArgData* operator [](const std::string& opt) const;
	const std::vector<std::string>& getRawInputs() const;

	friend std::ostream& operator <<(std::ostream& out, const ArgHandler& handler);

private:
	ArgHandler();
	ArgHandler(const ArgHandler&);
	ArgHandler& operator =(const ArgHandler&);

	void resetArgData();

	ArgMap _argMap; ///< Registered arguments.
	std::string _runString; ///< Script name printed in help.
	std::string _helpString; ///< Help text printed in help.
	std::uint32_t _count; ///< Number of used arguments.
	std::vector<std::string> _rawInputs; ///< Holds the non-argument raw input.
};

} // namespace unpackertool
} // namespace retdec

#endif
