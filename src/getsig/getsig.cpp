/**
 * @file src/getsig/getsig.cpp
 * @brief Generate signatures from binary files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <getopt.h>
#include <vector>

#include "retdec/fileformat/format_factory.h"
#include "retdec/utils/conversion.h"

using namespace retdec::fileformat;
using namespace retdec::utils;

/**
 * Print usage.
 */
void printUsage()
{
	std::cout <<
	"getsig - generator of YARA tool signatures\n\n"
	"Program takes executable files, compares their content at given\n"
	"offset and prints signature representing contents of all files.\n\n"
	"Usage: getsig [OPTIONS] FILE1 [FILE2 ...]\n\n"
	"General:\n"
	"  -h --help              Print this message.\n\n"
	"Type of tool:\n"
	"  -p --packer            Set tool type to packer.\n"
	"  -c --compiler          Set tool type to compiler.\n"
	"  -i --installer         Set tool type to installer.\n\n"
	"  Tool type will be set to 'U' (unknown) if no option is used.\n\n"
	"Other rule options:\n"
	"  -n=NAME     --name=NAME\n"
	"    Set name of tool. Default value is 'unknown'.\n\n"
	"  -v=VERSION  --version=VERSION\n"
	"    Set version of tool. Attribute is omitted if not specified.\n\n"
	"  -e=INFO     --extra=INFO\n"
	"    Set extra information. Attribute is omitted if not specified\n\n"
	"Search options:\n"
	"  -s=NUMBER   --size=NUMBER\n"
	"    Use NUMBER of bytes to create signature. NUMBER must be decimal\n"
	"    number. Default value is 100 bytes.\n\n"
	"  -o=OFFSET   --offset=OFFSET\n"
	"    Specify starting offset for signature creation. OFFSET must be\n"
	"    hexadecimal number. Default value is entry point offset.\n\n"
	"Output options:\n"
	"  -a=FILENAME --add=FILENAME, \n"
	"    Append signature to FILENAME file.\n\n";
}

/**
 * Program options.
 */
struct Options
{
	public:
		// Output rule description.
		std::string rule = "unknown";
		std::string name = "unknown";
		std::string type = "U";
		std::string extra;
		std::string version;
		std::string language;
		std::string source;
		bool bytecode = false;

		// I/O settings.
		std::string outputFile;
		std::vector<std::string> input;

		// Search settings.
		long long unsigned size = 100; ///< maximum size of pattern (bytes)
		long long unsigned offset;     ///< value of search offset
		bool isOffset = false;         ///< @c true if user provided offset
};


/**
 * Print error message and return non-zero value.
 * @param message error message
 * @return non-zero value
 */
int printError(
		const std::string& message)
{
	std::cerr << "Error: " << message << ".\n";
	return 1;
}


/**
 * Print warning message.
 * @param message warning message
 */
void printWarning(
		const std::string& message)
{
	std::cerr << "Warning: " << message << ".\n";
}


/**
 * Get value of application argument
 * @param value value of argument as pointer to char
 * @param result string for storing the result
 */
void getArgumentValue(
		const char* value,
		std::string& result)
{
	if (value)
	{
		result = static_cast<std::string>(value);
		if (!result.empty() && result[0] == '=')
		{
			result.erase(0, 1);
		}
	}
}


/**
 * Process parameters
 * @param argc number of program parameters
 * @param argv vector of program parameters
 * @param options structure for storing information
 * @return @c true if processing was completed successfully, @c false otherwise
 */
bool doParams(
		int argc,
		char** argv,
		Options& options)
{
	if (argc < 2)
	{
		printUsage();
		exit(EXIT_SUCCESS);
	}
	else if (!argv)
	{
		return false;
	}

	const struct option longopts[] =
	{
		{ "help",       no_argument,         nullptr,  'h'    },
		{ "packer",     no_argument,         nullptr,  'p'    },
		{ "compiler",   no_argument,         nullptr,  'c'    },
		{ "installer",  no_argument,         nullptr,  'i'    },
		{ "size",       required_argument,   nullptr,  's'    },
		{ "offset",     required_argument,   nullptr,  'o'    },
		{ "name",       required_argument,   nullptr,  'n'    },
		{ "version",    required_argument,   nullptr,  'v'    },
		{ "extra",      required_argument,   nullptr,  'e'    },
		{ "add",        required_argument,   nullptr,  'a'    },
		{ nullptr,      no_argument,         nullptr,   0     }
	};

	int opt;
	std::string argument;
	while ((opt = getopt_long(argc, argv, "hpcis:o:n:v:e:a:", longopts, nullptr)) != -1)
	{
		switch(opt)
		{
			case 'h':
				printUsage();
				exit(EXIT_SUCCESS);

			case 'p':
			case 'c':
				/* fall-thru */
			case 'i':
				options.type = std::toupper(opt);
				break;

			case 'o':
				getArgumentValue(optarg, argument);
				if (!strToNum(argument, options.offset, std::hex))
				{
					return false;
				}
				options.isOffset = true;
				break;

			case 's':
				getArgumentValue(optarg, argument);
				if (!strToNum(argument, options.size) || options.size < 1)
				{
					return false;
				}
				break;

			case 'n':
				getArgumentValue(optarg, options.name);
				break;

			case 'v':
				getArgumentValue(optarg, options.version);
				break;

			case 'e':
				getArgumentValue(optarg, options.extra);
				break;

			case 'a':
				getArgumentValue(optarg, options.outputFile);
				break;

			default:
				return false;
		}
	}

	while (argc - optind)
	{
		// All other arguments are considered input files.
		options.input.push_back(static_cast<std::string>(argv[optind++]));
	}
	return !options.input.empty();
}


/**
 * Get length of shortest string in given vector.
 * @param inputs vector of strings
 * @return length of shortest string or 0
 *
 * If input vector is empty, function returns 0.
 */
std::size_t getShortestLength(
		const std::vector<std::string> &inputs)
{
	if (inputs.empty())
	{
		return 0;
	}

	auto min = std::numeric_limits<std::size_t>::max();
	for (const auto& input :inputs)
	{
		const auto& length = input.length();
		if (length < min)
		{
			min = length;
		}
	}

	return min;
}


/**
 * Creates signature pattern from vector of strings
 * @param contents Vector of bytes from files
 * @param return created signature
 */
std::string createSignature(const std::vector<std::string> &contents)
{
	const auto length = getShortestLength(contents);
	if (!length)
	{
		// No data are available.
		return std::string();
	}

	std::string pattern;
	for (std::size_t i = 0; i < length; ++i)
	{
		bool insignificant = false;
		for (std::size_t j = 1, f = contents.size(); j < f; ++j)
		{
			if (contents[0][i] != contents[j][i])
			{
				insignificant = true;
				break;
			}
		}

		// Add nibble or '?' if nibbles differ.
		pattern += !insignificant ? contents[0][i] : '?';
	}

	// Remove trailing insignificant nibbles.
	std::size_t index = length - 1;
	while (index > 0 && pattern[index] == '?')
	{
		pattern.erase(index, 1);
		--index;
	}

	// Pattern length has to be even number.
	if (pattern.length() % 2)
	{
		pattern.pop_back();
	}

	return pattern;
}


/**
 * Form entry point condition from format.
 * @param format file format
 * @return condition as string
 */
std::string formatToCondition(
		const Format& format)
{
	std::string formatStr;
	switch (format)
	{
		case Format::PE:
			formatStr = "pe";
			break;

		case Format::ELF:
			formatStr = "elf";
			break;

		case Format::MACHO:
			formatStr = "macho";
			break;

		default:
			return "entrypoint";
	}

	return formatStr + ".entry_point";
}


/**
 * Create YARA rule from pattern.
 * @param pattern input pattern
 * @param fileFormat file format
 * @param options application options
 * @return YARA rule as string
 */
std::string getYaraRule(
		const std::string& pattern,
		const Format& fileFormat,
		const Options& options)
{
	// Form condition.
	std::string condition = "$1 at ";
	if (options.isOffset)
	{
		condition += numToStr(options.offset);
	}
	else
	{
		condition += formatToCondition(fileFormat);
	}

	std::ostringstream out;
	out << "rule " << options.rule << "\n{\n";
	out << "\tmeta:\n";
	out << "\t\ttool = "    << "\"" << options.type << "\"\n";
	out << "\t\tname = "    << "\"" << options.name << "\"\n";

	// Optional meta attributes.
	if (!options.version.empty())
	{
		out << "\t\tversion = " << "\"" << options.version << "\"\n";
	}
	if (!options.extra.empty())
	{
		out << "\t\textra = " << "\"" << options.extra << "\"\n";
	}
	if (!options.language.empty())
	{
		out << "\t\tlanguage = " << "\"" << options.language << "\"\n";
	}
	if (options.bytecode)
	{
		out << "\t\tbytecode = " << "true\n";
	}
	if (options.isOffset)
	{
		out << "\t\tabsoluteStart = " << options.offset << "\n";
	}
	if (!options.source.empty())
	{
		out << "\t\tsource = " << "\"" << options.source << "\"\n";
	}

	// Meta pattern.
	out << "\t\tpattern = " << "\"" << pattern << "\"\n";

	// String section.
	out << "\tstrings:\n" << "\t\t$1 = {";
	// Add spaces for more readable output.
	for (std::size_t i = 0; i < pattern.size(); ++i)
	{
		if (i % 2 == 0)
		{
			out << ' ';
		}
		out << pattern[i];
	}
	out << " }\n";

	// Condition.
	out << "\tcondition:\n";
	out << "\t\t" << condition << "\n}\n";

	return out.str();
}

int main(int argc, char** argv) {

	Options options;
	if (!doParams(argc, argv, options)) {
		return printError("invalid arguments");
	}

	Format format = Format::UNKNOWN;
	std::vector<std::string> contents;
	for (const auto& path : options.input)
	{
		auto fileParser = createFileFormat(path);
		if (!fileParser)
		{
			printWarning("skipping '" + path + "' - invalid file");
			continue;
		}

		// Format must be same for all files.
		auto actualFormat = fileParser->getFileFormat();
		if (format == Format::UNKNOWN)
		{
			// Set format from first file.
			format = actualFormat;
		}
		if (format != actualFormat)
		{
			// Ignore files with other formats.
			printWarning("skipping '" + path + "' - format mismatch");
			continue;
		}

		if (!options.isOffset && !fileParser->getEpOffset(options.offset))
		{
			printWarning("skipping '" + path + "' - EP problem");
			continue;
		}

		std::string content;
		if (!fileParser->getHexBytes(content, options.offset, options.size))
		{
			printWarning("skipping '" + path + "' - data problem");
			continue;
		}
		else
		{
			contents.push_back(content);
		}
	}

	if (contents.empty())
	{
		return printError("no valid data collected");
	}

	// create detection rule
	const auto rule = getYaraRule(createSignature(contents), format, options);
	std::cout << rule;

	return 0;
}

