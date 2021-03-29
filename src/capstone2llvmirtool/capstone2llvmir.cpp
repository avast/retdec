/**
 * @file src/capstone2llvmirtool/capstone2llvmir.cpp
 * @brief Decodes specified bytes to LLVM IR using capstone2llvmir library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>

#include <keystone/keystone.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/common/address.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/utils/io/log.h"
#include "retdec/utils/version.h"

#include "retdec/capstone2llvmir/capstone2llvmir.h"

using namespace retdec::utils;
using namespace retdec::utils::io;

// byte ptr [0x12345678], 0x11
std::vector<uint8_t> CODE = retdec::utils::hexStringToBytes("80 05 78 56 34 12 11 00");

class ProgramOptions
{
	public:
		ProgramOptions()
		{

		}
		ProgramOptions(int argc, char *argv[])
		{
			if (argc > 0)
			{
				_programName = argv[0];
			}

			for (int i = 1; i < argc; ++i)
			{
				std::string c = argv[i];

				if (c == "--version")
				{
					Log::info() << version::getVersionStringLong() << "\n";
					exit(0);
				}
				else if (c == "-a")
				{
					_arch = getParamOrDie(argc, argv, i);
					if (_arch == "arm") arch = CS_ARCH_ARM;
					else if (_arch == "arm64") arch = CS_ARCH_ARM64;
					else if (_arch == "mips") arch = CS_ARCH_MIPS;
					else if (_arch == "x86") arch = CS_ARCH_X86;
					else if (_arch == "ppc") arch = CS_ARCH_PPC;
					else if (_arch == "sparc") arch = CS_ARCH_SPARC;
					else if (_arch == "sysz") arch = CS_ARCH_SYSZ;
					else if (_arch == "xcore") arch = CS_ARCH_XCORE;
					else printHelpAndDie();
				}
				else if (c == "-b")
				{
					_base = getParamOrDie(argc, argv, i);
					if (!retdec::utils::strToNum(_base, base, std::hex))
					{
						printHelpAndDie();
					}
				}
				else if (c == "-c")
				{
					_code = getParamOrDie(argc, argv, i);
					code = retdec::utils::hexStringToBytes(_code);
				}
				else if (c == "-t")
				{
					text = getParamOrDie(argc, argv, i);
				}
				else if (c == "-m")
				{
					_basicMode = getParamOrDie(argc, argv, i);
					_useDefaultBasicMode = false;
					if (_basicMode == "arm") basicMode = CS_MODE_ARM;
					else if (_basicMode == "thumb") basicMode = CS_MODE_THUMB;
					else if (_basicMode == "16") basicMode = CS_MODE_16;
					else if (_basicMode == "32") basicMode = CS_MODE_32;
					else if (_basicMode == "64") basicMode = CS_MODE_64;
					else if (_basicMode == "mips3") basicMode = CS_MODE_MIPS3;
					else if (_basicMode == "mips32r6") basicMode = CS_MODE_MIPS32R6;
					else if (_basicMode == "mips32") basicMode = CS_MODE_MIPS32;
					else if (_basicMode == "mips64") basicMode = CS_MODE_MIPS64;
					else printHelpAndDie();
				}
				else if (c == "-e")
				{
					_extraMode = getParamOrDie(argc, argv, i);
					if (_extraMode == "little") extraMode = CS_MODE_LITTLE_ENDIAN;
					else if (_extraMode == "mclass") extraMode = CS_MODE_MCLASS;
					else if (_extraMode == "v8") extraMode = CS_MODE_V8;
					else if (_extraMode == "micro") extraMode = CS_MODE_MICRO;
					else if (_extraMode == "v9") extraMode = CS_MODE_V9;
					else if (_extraMode == "big") extraMode = CS_MODE_BIG_ENDIAN;
					else printHelpAndDie();
				}
				else if (c == "-o")
				{
					outFile = getParamOrDie(argc, argv, i);
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

			if (_useDefaultBasicMode)
			{
				basicMode = getDefaultBasicModeFromArch(arch);
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

		cs_mode getDefaultBasicModeFromArch(cs_arch a)
		{
			switch (a)
			{
				case CS_ARCH_ARM: return CS_MODE_ARM; // CS_MODE_THUMB
				case CS_ARCH_ARM64: return CS_MODE_ARM;
				case CS_ARCH_MIPS: return CS_MODE_MIPS32; // CS_MODE_MIPS{32, 64, 32R6}
				case CS_ARCH_X86: return CS_MODE_32; // CS_MODE_{16, 32, 64}
				case CS_ARCH_PPC: return CS_MODE_32;
				case CS_ARCH_SPARC: return CS_MODE_LITTLE_ENDIAN; // 0
				case CS_ARCH_SYSZ: return CS_MODE_LITTLE_ENDIAN;
				case CS_ARCH_XCORE: return CS_MODE_LITTLE_ENDIAN;
				case CS_ARCH_MAX:
				case CS_ARCH_ALL:
				default:
					Log::error() << "Can not get Capstone arch to default Capstone basic mode." << std::endl;
					exit(1);
			}
		}

		void dump()
		{
			std::string tmp;
			retdec::utils::bytesToHexString(code, tmp, 0, 0, false, true);
			Log::info() << std::endl;
			Log::info() << "Program Options:" << std::endl;
			Log::info() << "\t" << "arch   : " << arch << " (" << _arch << ")" << std::endl;
			Log::info() << "\t" << "base   : " << std::hex << base << " (" << _base << ")" << std::endl;
			Log::info() << "\t" << "code   : " << tmp << " (" << _code << ")" << std::endl;
			Log::info() << "\t" << "asm text : " << text << std::endl;
			Log::info() << "\t" << "b mode : " << std::hex << basicMode << " (" << _basicMode << ")" << std::endl;
			Log::info() << "\t" << "e mode : " << std::hex << extraMode << " (" << _extraMode << ")" << std::endl;
			Log::info() << "\t" << "out    : " << outFile << std::endl;
			Log::info() << std::endl;
		}

		void printHelpAndDie()
		{
			std::string tmp;
			retdec::utils::bytesToHexString(CODE, tmp, 0, 0, false, true);
			Log::info() << _programName << ":\n"
				"\t-h|--help Show this help.\n"
				"\t--version Show RetDec version.\n"
				"\t-a name   Set architecture name.\n"
				"\t          Possible values: arm, arm64, mips, x86, ppc, sparc, sysz, xcore\n"
				"\t          Default value: x86.\n"
				"\t-b base   Base address in hexadecimal format (e.g. 0x1000).\n"
				"\t          Default value 0x1000.\n"
				"\t-c code   Binary data to translate in hexadecimal format.\n"
				"\t          E.g. \"0b 84 d1 a0 80 60 40\" or \"0b84d1a0806040\".\n"
				"\t          Default value: \"" << tmp << "\"\n"
				"\t-t asm    Assembly text to assemble, disassemble and dump.\n"
				"\t          Most of the time, this is more convenient than -c option.\n"
				"\t-m mode   Capstone basic mode to use.\n"
				"\t          Possible values: arm, thumb, 16, 32, 64, mips3, mips32r6,\n"
				"\t          mips32, mips64\n"
				"\t          Default value: 32.\n"
				"\t-e mode   Capstone extra mode to use.\n"
				"\t          Possible values: little, big, micro, mclass, v8, v9.\n"
				"\t          Default value: little.\n"
				"\t-o out    Output file name where LLVM IR will be generated.\n"
				"\t          Default value: stdout\n";

			exit(0);
		}

	public:
		cs_arch arch = CS_ARCH_X86;
		uint64_t base = 0x1000;
		std::vector<uint8_t> code = CODE;
		std::string text;
		cs_mode basicMode = CS_MODE_32;
		cs_mode extraMode = CS_MODE_LITTLE_ENDIAN;
		std::string outFile = "-"; // "-" == stdout for llvm::raw_fd_ostream.

	private:
		std::string _programName = "capstone2llvmir";
		std::string _arch;
		std::string _base;
		std::string _code;
		std::string _basicMode;
		std::string _extraMode;
		bool _useDefaultBasicMode = true;
};

/**
 * Print capstone version get by cs_version().
 */
void printVersion()
{
	int major = 0;
	int minor = 0;
	int version = cs_version(&major, &minor);

	Log::info() << std::endl;
	Log::info() << "Capstone version: " << version << " (major: " << major
			<< ", minor: " << minor << ")" << std::endl;
}

ks_arch capstoneArchToKeystoneArch(cs_arch a)
{
	switch (a)
	{
		case CS_ARCH_ARM: return KS_ARCH_ARM;
		case CS_ARCH_ARM64: return KS_ARCH_ARM64;
		case CS_ARCH_MIPS: return KS_ARCH_MIPS;
		case CS_ARCH_X86: return KS_ARCH_X86;
		case CS_ARCH_PPC: return KS_ARCH_PPC;
		case CS_ARCH_SPARC: return KS_ARCH_SPARC;
		case CS_ARCH_SYSZ: return KS_ARCH_SYSTEMZ;
		case CS_ARCH_XCORE:
		case CS_ARCH_MAX:
		case CS_ARCH_ALL:
		default:
			Log::error() << "Can not convert Capstone arch to Keystone arch." << std::endl;
			exit(1);
	}
}

ks_mode capstoneModeBasicToKeystoneMode(cs_arch a, cs_mode m)
{
	if (m == CS_MODE_16) // 1 << 1
	{
		return KS_MODE_16;
	}
	else if (m == CS_MODE_32) // 1 << 2 == CS_MODE_MIPS32
	{
		return KS_MODE_32;
	}
	else if (m == CS_MODE_64) // 1 << 3 == CS_MODE_MIPS64
	{
		return KS_MODE_64;
	}
	else if (a == CS_ARCH_ARM && m == CS_MODE_ARM) // 0
	{
		return KS_MODE_ARM;
	}
	else if (a == CS_ARCH_ARM && m == CS_MODE_THUMB) // 1 << 4
	{
		return KS_MODE_THUMB;
	}
	else if (a == CS_ARCH_ARM64 && m == CS_MODE_ARM) // 0
	{
		return KS_MODE_LITTLE_ENDIAN;
		// In the keystone examples, only little endian mode is used with CS_ARCH_ARM64
		// test_ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, "ldr w1, [sp, #0x8]", 0);
	}
	else if (a == CS_ARCH_MIPS && m == CS_MODE_MIPS3) // 1 << 5
	{
		return KS_MODE_MIPS3;
	}
	else if (a == CS_ARCH_MIPS && m == CS_MODE_MIPS32R6) // 1 << 6
	{
		return KS_MODE_MIPS32R6;
	}
	else
	{
		Log::error() << "Can not convert Capstone basic mode to Keystone mode." << std::endl;
		exit(1);
	}
}

ks_mode capstoneModeExtraToKeystoneMode(cs_arch a, cs_mode m)
{
	if (m == CS_MODE_LITTLE_ENDIAN) // 0
	{
		return KS_MODE_LITTLE_ENDIAN;
	}
	else if (m == CS_MODE_BIG_ENDIAN) // 1 << 31
	{
		return KS_MODE_BIG_ENDIAN;
	}
	else if (a == CS_ARCH_ARM && m == CS_MODE_MCLASS) // 1 << 5
	{
		return KS_MODE_LITTLE_ENDIAN; // There is no MCLASS in Keystone.
	}
	else if (a == CS_ARCH_ARM && m == CS_MODE_V8) // 1 << 6
	{
		return KS_MODE_V8;
	}
	else if (a == CS_ARCH_MIPS && m == CS_MODE_MICRO) // 1 << 4
	{
		return KS_MODE_MICRO;
	}
	else if (a == CS_ARCH_SPARC && m == CS_MODE_V9) // 1 << 4
	{
		return KS_MODE_V9;
	}
	else
	{
		Log::error() << "Can not convert Capstone extra mode to Keystone mode." << std::endl;
		exit(1);
	}
}

/**
 * Use keystone do assemble input asm into bytes that will be disassembled.
 */
void assemble(ProgramOptions& po)
{
	ks_engine *ks;

	ks_arch arch = capstoneArchToKeystoneArch(po.arch);
	ks_mode basic = capstoneModeBasicToKeystoneMode(po.arch, po.basicMode);
	ks_mode extra = capstoneModeExtraToKeystoneMode(po.arch, po.extraMode);

	if (ks_open(arch, basic | extra, &ks) != KS_ERR_OK)
	{
		ks_err err = ks_errno(ks);
		Log::error() << Log::Error << "Keystone: " << ks_strerror(err) << std::endl;
		exit(1);
	}

	unsigned char* enc;
	size_t sz;
	size_t cnt;

	if (ks_asm(ks, po.text.data(), po.base, &enc, &sz, &cnt) != KS_ERR_OK)
	{
		ks_err err = ks_errno(ks);
		Log::error() << Log::Error << "Keystone: " << ks_strerror(err) << std::endl;
		exit(1);
	}

	po.code.clear();
	po.code.reserve(sz);
	for (size_t i = 0; i < sz; ++i)
	{
		po.code.push_back(enc[i]);
	}

	ks_free(enc);
	if (ks_close(ks) != KS_ERR_OK)
	{
		ks_err err = ks_errno(ks);
		Log::error() << Log::Error << "Keystone : " << ks_strerror(err) << std::endl;
		exit(1);
	}
}

using namespace retdec::capstone2llvmir;

int main(int argc, char *argv[])
{
	ProgramOptions po(argc, argv);

	if (!po.text.empty())
	{
		assemble(po);
	}

	printVersion();

	llvm::LLVMContext ctx;
	llvm::Module module("test", ctx);

	auto* f = llvm::Function::Create(
			llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), false),
			llvm::GlobalValue::ExternalLinkage,
			"root",
			&module);
	llvm::BasicBlock::Create(module.getContext(), "entry", f);
	llvm::IRBuilder<> irb(&f->front());

	auto* ret = irb.CreateRetVoid();
	irb.SetInsertPoint(ret);

	try
	{
		auto c2l = Capstone2LlvmIrTranslator::createArch(
				po.arch,
				&module,
				po.basicMode,
				po.extraMode);
		c2l->translate(po.code.data(), po.code.size(), po.base, irb);
	}
	catch (const BaseError& e)
	{
		Log::error() << e.what() << std::endl;
		assert(false);
	}
	catch (...)
	{
		Log::error() << "Some unhandled exception" << std::endl;
	}

	std::error_code ec;
	llvm::raw_fd_ostream out(po.outFile, ec, llvm::sys::fs::F_None);
	module.print(out, nullptr);

	return EXIT_SUCCESS;
}
