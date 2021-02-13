/**
 * @file src/retdectool/retdec.cpp
 * @brief RetDec tool.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <cstdlib>

#include "retdec/retdec/retdec.h"
#include "retdec/utils/io/log.h"
#include "retdec/utils/version.h"

using namespace retdec::utils::io;

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
				else if (c == "-h" || c == "--help")
				{
					printHelpAndDie();
				}
				else if (c == "--version")
				{
					Log::info() << retdec::utils::version::getVersionStringLong()
							<< "\n";
					exit(EXIT_SUCCESS);
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
			Log::info() << std::endl;
			Log::info() << "Program Options:" << std::endl;
			Log::info() << "\t" << "input file : " << inputFile << std::endl;
		}

		void printHelpAndDie()
		{
			Log::info() << _programName << ":\n"
					<< "\t-h|--help Show this help.\n"
					<< "\t--version Show RetDec version.\n"
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
		Log::info() << std::endl;
		Log::info() << f.getName() << " @ " << f << std::endl;

		Log::info() << std::endl;
		Log::info() << "\t" << "code refs (insns referencing this function):"
			<< std::endl;
		for (auto& r : f.codeReferences)
		{
			auto* f = fs.getRange(r);
			Log::info() << "\t\t" << r
				<< " ( @ " << (f ? f->getName() : "unknown") << " )"
				<< std::endl;
		}

		for (auto& bb : f.basicBlocks)
		{
			Log::info() << std::endl;
			Log::info() << "\t" << "bb @ " << bb << std::endl;

			Log::info() << "\t\t" << "preds:" << std::endl;
			for (auto p : bb.preds)
			{
				Log::info() << "\t\t\t" << p << std::endl;
			}

			Log::info() << "\t\t" << "succs:" << std::endl;
			for (auto s : bb.succs)
			{
				Log::info() << "\t\t\t" << s << std::endl;
			}

			Log::info() << "\t\t" << "calls:" << std::endl;
			for (auto c : bb.calls)
			{
				auto* f = fs.getRange(c.targetAddr);
				Log::info() << "\t\t\t" << c.srcAddr << "  ->  " << c.targetAddr
					<< " ( @ " << (f ? f->getName() : "unknown") << " )"
					<< std::endl;
			}

			// These are not only text entries!!!
			// There is a full Capstone representation for every instruction.
			Log::info() << "\t\t" << "instructions:" << std::endl;
			for (auto* insn : bb.instructions)
			{
				Log::info() << "\t\t\t" << retdec::common::Address(insn->address)
					<< " @ " << insn->mnemonic << " " << insn->op_str
					<< std::endl;
			}
		}
	}

	return EXIT_SUCCESS;
}
