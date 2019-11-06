/**
 * @file src/retdectool/retdec.cpp
 * @brief RetDec tool.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <cstdlib>
#include <iostream>

#include "retdec/retdec/retdec.h"

class ProgramOptions
{
	public:
		ProgramOptions(int argc, char *argv[])
		{
			if (argc > 0)
			{
				_programName = argv[0];
			}

			for (int i = 1; i < argc; ++i)
			{
				std::string c = argv[i];

				if (c == "-i")
				{
					inputFile = getParamOrDie(argc, argv, i);
				}
				else if (c == "-h")
				{
					printHelpAndDie();
				}
				else
				{
					printHelpAndDie();
				}
			}
		}

		std::string getParamOrDie(int argc, char *argv[], int& i)
		{
			if (argc > i+1)
			{
				return argv[++i];
			}
			else
			{
				printHelpAndDie();
				return std::string();
			}
		}

		void dump()
		{
			std::cout << std::endl;
			std::cout << "Program Options:" << std::endl;
			std::cout << "\t" << "input file : " << inputFile << std::endl;
			std::cout << std::endl;
		}

		void printHelpAndDie()
		{
			std::cout << _programName << ":\n"
					<< "\t-i inputFile\n";

			exit(EXIT_SUCCESS);
		}

	public:
		std::string inputFile;

	private:
		std::string _programName;
};

int main(int argc, char **argv)
{
	ProgramOptions po(argc, argv);
	po.dump();

	retdec::hello(po.inputFile);

	return EXIT_SUCCESS;
}
