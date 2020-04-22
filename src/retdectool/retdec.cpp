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

	retdec::common::FunctionSet fs;
	retdec::disassemble(po.inputFile, &fs);

	for (auto& f : fs)
	{
		std::cout << std::endl;
		std::cout << f.getName() << " @ " << f << std::endl;

		std::cout << std::endl;
		std::cout << "\t" << "code refs (insns referencing this function):"
			<< std::endl;
		for (auto& r : f.codeReferences)
		{
			auto* f = fs.getRange(r);
			std::cout << "\t\t" << r
				<< " ( @ " << (f ? f->getName() : "unknown") << " )"
				<< std::endl;
		}

		for (auto& bb : f.basicBlocks)
		{
			std::cout << std::endl;
			std::cout << "\t" << "bb @ " << bb << std::endl;

			std::cout << "\t\t" << "preds:" << std::endl;
			for (auto p : bb.preds)
			{
				std::cout << "\t\t\t" << p << std::endl;
			}

			std::cout << "\t\t" << "succs:" << std::endl;
			for (auto s : bb.succs)
			{
				std::cout << "\t\t\t" << s << std::endl;
			}

			std::cout << "\t\t" << "calls:" << std::endl;
			for (auto c : bb.calls)
			{
				auto* f = fs.getRange(c.targetAddr);
				std::cout << "\t\t\t" << c.srcAddr << "  ->  " << c.targetAddr
					<< " ( @ " << (f ? f->getName() : "unknown") << " )"
					<< std::endl;
			}

			// These are not only text entries!!!
			// There is a full Capstone representation for every instruction.
			std::cout << "\t\t" << "instructions:" << std::endl;
			for (auto* insn : bb.instructions)
			{
				std::cout << "\t\t\t" << retdec::common::Address(insn->address)
					<< " @ " << insn->mnemonic << " " << insn->op_str
					<< std::endl;
			}
		}
	}

	return EXIT_SUCCESS;
}
