/**
 * @file src/demangler_grammar_gen/demangler_grammar_gen.cpp
 * @brief Grammar generation tool.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstring>
#include <iostream>

#include "retdec/demangler/demangler.h"

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		std::cerr << "\n"
				"Error: No input and output was specified\n"
				"\n"
				"usage: " << argv[0] << " <input grammar> <output grammar>\n"
				"output is generated to ./stgrammars/<output grammar>\n"
				"stgrammars directory must exist before generation\n"
				<< std::endl;
		return 1;
	}
	else
	{
		std::cout << argv[1] << std::endl;
		std::cout << argv[2] << std::endl;

		retdec::demangler::CDemangler dem(std::string(), false);
		std::cout << dem.printError() << std::endl;
		dem.createGrammar(argv[1], argv[2]);
		std::cout << dem.printError() << std::endl;

		return 0;
	}
}
