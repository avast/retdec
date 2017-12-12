/**
 * @file src/debugformat/dwarf.cpp
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#define LOG_ENABLED false

#include <iostream>

#include "demangler/demangler.h"
#include "tl-cpputils/debug.h"
#include "tl-cpputils/string.h"
#include "debugformat/debugformat.h"

namespace debugformat {

void DebugFormat::loadDwarf()
{
	if (!_dwarfFile)
		return;

	loadDwarfTypes();
	loadDwarfGlobalVariables();
	loadDwarfFunctions();
}

void DebugFormat::loadDwarfTypes()
{
	auto* ts = _dwarfFile->getTypes();
	for (auto* t : *ts)
	{
		if (t)
		{
			types.insert(loadDwarfType(t));
		}
	}
}

void DebugFormat::loadDwarfGlobalVariables()
{
	auto* dwarfGvars = _dwarfFile->getGlobalVars();
	if (dwarfGvars == nullptr)
		return;

	for (auto* gvar : *dwarfGvars)
	{
		if (gvar->location == nullptr || !gvar->location->isNormal() || gvar->name.empty())
		{
			continue;
		}

		Dwarf_Addr address;
		std::string n;
		dwarfparser::DwarfLocationDesc::cLocType loc = gvar->getLocation(&n, &address, 1);
		if (loc.isAddress())
		{
			std::string name = gvar->name.empty() ? "glob_var_" + tl_cpputils::toHexString(address) : gvar->name;
			auto addr = tl_cpputils::Address(address);
			if (!addr.isDefined())
				continue;
			retdec_config::Object gv(name, retdec_config::Storage::inMemory(addr));
			gv.type = loadDwarfType(gvar->type);
			if (gv.type.getLlvmIr() == "void")
				gv.type.setLlvmIr("i32");
			globals.insert(gv);
		}
	}
}

void DebugFormat::loadDwarfFunctions()
{
	// Lines
	//
	std::map<tl_cpputils::Address, int> lines;
	for (auto* line : *_dwarfFile->getLines())
	{
		lines[line->addr] = line->lineNum;
	}

	// Functions
	//
	for (auto* df : *_dwarfFile->getFunctions())
	{
		if (df->lowAddr <= 0)
			continue;

		std::string name;
		std::string demangledName;
		if (df->linkageName.empty())
		{
			name = df->name;
		}
		else
		{
			name = df->linkageName;
			demangledName = _demangler->demangleToString(name);
			if (demangledName.empty())
			{
				demangledName = name;
			}
		}

		retdec_config::Function dif(name);
		dif.setDemangledName(demangledName);

		dif.setStart(df->lowAddr);
		dif.setEnd(df->highAddr - 1);
		dif.setSourceFileName(df->file);
		dif.setIsVariadic(df->isVariadic);
		dif.returnType = loadDwarfType(df->type);

		dif.setStartLine(df->line);
		auto lastLine = lines.find(dif.getStart());
		while (lastLine != lines.end() && lastLine->first < dif.getEnd())
		{
			dif.setEndLine(lastLine->second);
			++lastLine;
		}

		auto* sym = _inFile->getFileFormat()->getSymbol(df->lowAddr + 1);
		dif.setIsThumb(sym && sym->isThumbSymbol());

		std::string regName;
		Dwarf_Addr frameRegNum = 0;
		if (df->frameBase && df->frameBase->computeLocation(&regName, &frameRegNum).isRegister())
		{
			dif.frameBaseStorage = retdec_config::Storage::inRegister(frameRegNum);
		}

		unsigned argCntr = 0;
		for (auto* param : *df->getParams())
		{
			std::string name = param->name.empty() ? std::string("arg") + std::to_string(argCntr) : param->name;
			retdec_config::Object newArg(name, retdec_config::Storage::undefined());
			newArg.type = loadDwarfType(param->type); // void -> i32
			dif.parameters.insert(newArg);
			++argCntr;
		}

		for (auto* var : *df->getVars())
		{
			if (var->location == nullptr || var->location->isEmpty() || var->name.empty())
			{
				continue;
			}

			retdec_config::Storage storage;
			Dwarf_Signed address;
			int regNum = -1;
			bool deref;
			if (var->isOnStack(&address, &deref, 0, &regNum))
			{
				storage = retdec_config::Storage::onStack(address, regNum);
			}

			retdec_config::Object newLocalVar(var->name, storage);
			newLocalVar.type = loadDwarfType(var->type); // TODO: void -> i32
			dif.locals.insert(newLocalVar);
		}

		dif.setIsFromDebug(true);
		functions.insert( {dif.getStart(), dif} );
	}
}

/**
 * Convert DWARF type representation into common type representation.
 * @param type DWARF type.
 * @return Common type representation.
 */
retdec_config::Type DebugFormat::loadDwarfType(dwarfparser::DwarfType* type)
{
	if (type == nullptr)
	{
		return retdec_config::Type("i32");
	}
	auto t = retdec_config::Type(type->toLLVMString());
	return t.isDefined() ? t : retdec_config::Type("i32");
}

} // namespace debugformat
