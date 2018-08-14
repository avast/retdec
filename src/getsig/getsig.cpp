/**
 * @file src/getsig/getsig.cpp
 * @brief Generate signatures from binary files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cctype>
#include <iostream>
#include <vector>

#include "retdec/fileformat/format_factory.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

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
	"Rule options:\n"
	"  -r --rule-name NAME\n"
	"    Set name of rule. Default value is 'unknown'.\n\n"
	"  -n --name NAME\n"
	"    Set name of tool. Default value is 'unknown'.\n\n"
	"  -v --version VERSION\n"
	"    Set version of tool. Attribute is omitted if not specified.\n\n"
	"  -e --extra INFO\n"
	"    Set extra information. Attribute is omitted if not specified.\n\n"
	"  -l --language NAME\n"
	"    Set language information. Attribute is omitted if not specified.\n\n"
	"  -b --bytecode\n"
	"    Set language type to bytecode.\n\n"
	"  -p --packer\n"
	"    Set tool type to packer.\n\n"
	"  -c --compiler\n"
	"    Set tool type to compiler.\n\n"
	"  -i --installer\n"
	"    Set tool type to installer.\n\n"
	"  Tool type will be set to 'U' (unknown) if no option is used.\n\n"
	"Search options:\n"
	"  -s --size NUMBER\n"
	"    Use NUMBER of bytes to create signature. NUMBER must be decimal\n"
	"    number. Default value is 100 bytes.\n\n"
	"  -o --offset OFFSET\n"
	"    Specify starting offset for signature creation. OFFSET must be\n"
	"    hexadecimal number. Default value is entry point offset.\n\n"
	"Output options:\n"
	"  -a --add FILENAME, \n"
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
 * Fetch parameter value or die with error message.
 * @param argv vector with arguments
 * @param i index of argument
 * @return argument value
 */
std::string getParamOrDie(std::vector<std::string> &argv, std::size_t &i)
{
	if (argv.size() > i + 1)
	{
		return argv[++i];
	}
	else
	{
		std::cerr << "Error: missing argument value.\n\n";
		printUsage();
		exit(1);
	}
}

/**
 * Process parameters
 * @param argc number of program parameters
 * @param _argv array of program parameters
 * @param options structure for storing information
 * @return @c true if processing was completed successfully, @c false otherwise
 */
bool doParams(
		int argc,
		char** _argv,
		Options& options)
{
	if (argc < 2)
	{
		printUsage();
		exit(EXIT_SUCCESS);
	}
	else if (!_argv)
	{
		return false;
	}

	std::set<std::string> withArgs =
	{
		"r",    "rule-name",
		"n",    "name",
		"v",    "version",
		"e",    "extra",
		"l",    "language",
		"s",    "size",
		"o",    "offset",
		"a",    "add",
		"source"
	};

	std::vector<std::string> argv;
	for (int i = 1; i < argc; ++i)
	{
		std::string a = _argv[i];

		bool added = false;
		for (auto& o : withArgs)
		{
			std::string start = (o.size() == 1 ? "-" : "--") + o + "=";
			if (retdec::utils::startsWith(a, start))
			{
				argv.push_back(a.substr(0, start.size()-1));
				argv.push_back(a.substr(start.size()));
				added = true;
				break;
			}
		}
		if (added)
		{
			continue;
		}

		argv.push_back(a);
	}

	for (std::size_t i = 0; i < argv.size(); ++i)
	{
		std::string c = argv[i];

		if (c == "-h" || c == "--help")
		{
			printUsage();
			exit(EXIT_SUCCESS);
		}
		else if (c == "-b" || c == "--bytecode")
		{
			options.bytecode = true;
		}
		else if (c == "-p" || c == "-c" || c == "-i")
		{
			options.type = std::toupper(c[1]);
		}
		else if (c == "--packer"
				|| c == "--compiler"
				|| c == "--installer")
		{
			options.type = std::toupper(c[2]);
		}
		else if (c == "-o" || c == "--offset")
		{
			const auto arg = getParamOrDie(argv, i);
			if (!strToNum(arg, options.offset, std::hex))
			{
				return false;
			}
			options.isOffset = true;
		}
		else if (c == "-s" || c == "--size")
		{
			const auto arg = getParamOrDie(argv, i);
			if (!strToNum(arg, options.size) || options.size < 1)
			{
				return false;
			}
		}
		else if (c == "-r" || c == "--rule-name")
		{
			options.rule = getParamOrDie(argv, i);
		}
		else if (c == "-n" || c == "--name")
		{
			options.name = getParamOrDie(argv, i);
		}
		else if (c == "-v" || c == "--version")
		{
			options.version = getParamOrDie(argv, i);
		}
		else if (c == "-e" || c == "--extra")
		{
			options.extra = getParamOrDie(argv, i);
		}
		else if (c == "-l" || c == "--language")
		{
			options.language = getParamOrDie(argv, i);
		}
		else if (c == "-a" || c == "--add")
		{
			options.outputFile = getParamOrDie(argv, i);
		}
		else if (c == "--source")
		{
			options.source = getParamOrDie(argv, i);
		}
		else
		{
			options.input.push_back(c);
		}
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
 * @return created signature
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

	// create signature
	const auto signature = createSignature(contents);
	if (signature.empty())
	{
		return printError("no common data found for input files");
	}

	// create detection rule
	const auto rule = getYaraRule(signature, format, options);
	std::cout << rule;

	if (!options.outputFile.empty())
	{
		std::ofstream outStream(options.outputFile, std::ofstream::app);
		if (outStream)
		{
			outStream << "\n" << rule << "\n";
			if (!outStream.good())
			{
				return printError("could not write to output file");
			}
		}
		else
		{
			return printError("could not open output file");
		}
	}

	return 0;
}

