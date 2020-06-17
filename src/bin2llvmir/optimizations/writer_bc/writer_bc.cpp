/**
 * @file src/bin2llvmir/optimizations/writer_bc/writer_bc.cpp
 * @brief Generate the current bitcode.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/ToolOutputFile.h>

#include "retdec/bin2llvmir/optimizations/writer_bc/writer_bc.h"
#include "retdec/bin2llvmir/providers/config.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char BitcodeWriter::ID = 0;

static RegisterPass<BitcodeWriter> X(
		"retdec-write-bc",
		"Generate the current bitcode",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

BitcodeWriter::BitcodeWriter() :
		ModulePass(ID)
{

}

/**
 * Create bitcode output file object.
 */
std::unique_ptr<ToolOutputFile> createBitcodeOutputFile(
		const std::string& outputFile)
{
	std::unique_ptr<ToolOutputFile> Out;

	if (outputFile.empty())
	{
		throw std::runtime_error("bitcode output file was not specified");
	}

	std::error_code EC;
	Out.reset(new ToolOutputFile(outputFile, EC, sys::fs::F_None));
	if (EC)
	{
		throw std::runtime_error(
			"failed to create llvm::ToolOutputFile for .bc: " + EC.message()
		);
	}

	return Out;
}

bool BitcodeWriter::runOnModule(Module& M)
{
	auto* c = ConfigProvider::getConfig(&M);

	auto out = c->getConfig().parameters.getOutputBitcodeFile();
	if (out.empty())
	{
		return false;
	}

	std::unique_ptr<ToolOutputFile> bcOut = createBitcodeOutputFile(out);
	raw_ostream* bcOs = &bcOut->os();
	bool ShouldPreserveUseListOrder = true;
	WriteBitcodeToFile(M, *bcOs, ShouldPreserveUseListOrder);
	bcOut->keep();

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
