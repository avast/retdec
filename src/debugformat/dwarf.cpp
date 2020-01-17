/**
 * @file src/debugformat/dwarf.cpp
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#define LOG_ENABLED false

#include <iostream>

#include "retdec/demangler/demangler.h"
#include "retdec/utils/debug.h"
#include "retdec/utils/string.h"
#include "retdec/debugformat/debugformat.h"

namespace {

retdec::common::Address getLineFromAddress(
		const llvm::DWARFDebugLine::LineTable* table,
		retdec::common::Address addr)
{
	retdec::common::Address ret;

	if (table == nullptr)
	{
		return ret;
	}

	llvm::DWARFDebugLine::Row tmpRow;
	tmpRow.Address = addr;
	auto it = std::upper_bound(
			table->Rows.begin(),
			table->Rows.end(),
			tmpRow,
			llvm::DWARFDebugLine::Row::orderByAddress);
	if (it != table->Rows.begin())
	{
		--it;
		ret = it->Line;
	}

	return ret;
}

std::string getDefaultDataType()
{
	return "i32";
}

} // anonymous namespace

namespace retdec {
namespace debugformat {

void DebugFormat::loadDwarf()
{
	// Open input file as buffer.
	//
	llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> buffOrErr =
			llvm::MemoryBuffer::getFileOrSTDIN(
				_inFile->getFileFormat()->getPathToFile());
	if (buffOrErr.getError())
	{
		return;
	}
	std::unique_ptr<llvm::MemoryBuffer> bufferPtr = std::move(buffOrErr.get());
	llvm::MemoryBufferRef buffer = *bufferPtr;

	// Open buffer as a binary file.
	//
	llvm::Expected<std::unique_ptr<llvm::object::Binary>> binOrErr
			= llvm::object::createBinary(buffer);
	auto binErr = errorToErrorCode(binOrErr.takeError());
	if (binErr)
	{
		return;
	}

	// Handle different flavours of binary files.
	//
	auto* obj = llvm::dyn_cast<llvm::object::ObjectFile>(binOrErr->get());
	if (obj == nullptr)
	{
		// There might be other flavours than llvm::object::ObjectFile.
		// E.g. llvm::object::MachOUniversalBinary, llvm::object::Archive>
		// These are unhandled at the moment.
		return;
	}
	std::unique_ptr<llvm::DWARFContext> DICtx = llvm::DWARFContext::create(*obj);

	LOG << "\n*** DebugFormat::DebugFormat(): DWARF" << std::endl;

	// Inspect compilation unit DIEs.
	//
	for (auto& unit : DICtx->compile_units())
	{
		if (auto unitDie = unit->getUnitDIE(false))
		{
			loadDwarf_CU(unitDie);
		}
	}

	// exit(1);
}

void DebugFormat::loadDwarf_CU(llvm::DWARFDie die)
{
	for (auto c : die.children())
	{
		switch (c.getTag())
		{
			case llvm::dwarf::DW_TAG_subprogram:
				loadDwarf_subprogram(c);
				break;
			default:
				break;
		}
	}
}

void DebugFormat::loadDwarf_subprogram(llvm::DWARFDie die)
{
	// Start & end address.
	//
	common::Address start, end;
	if (auto s = llvm::dwarf::toAddress(die.find(llvm::dwarf::DW_AT_low_pc)))
	{
		start = s.getValue();
	}
	if (auto e = llvm::dwarf::toAddress(die.find(llvm::dwarf::DW_AT_high_pc)))
	{
		end = e.getValue();
	}
	if (start.isUndefined() || end.isUndefined())
	{
		return;
	}

	// Names
	//
	std::string name, linkageName, demangledName;
	if (auto n = llvm::dwarf::toString(die.find(
			llvm::dwarf::DW_AT_name)))
	{
		name = n.getValue();
	}
	if (auto ln = llvm::dwarf::toString(die.find(
				llvm::dwarf::DW_AT_linkage_name)))
	{
		linkageName = ln.getValue();
		auto dn = _demangler->demangleToString(linkageName);
		demangledName = dn.empty() ? linkageName : dn;
	}
	if (name.empty() && linkageName.empty())
	{
		return;
	}

	auto* unit = die.getDwarfUnit();
	auto* lines = unit->getContext().getLineTableForUnit(unit);

	retdec::common::Function dif(linkageName.empty() ? name : linkageName);

	dif.setIsFromDebug(true);
	dif.setStartEnd(start, end);
	dif.setDemangledName(demangledName);

	auto* sym = _inFile->getFileFormat()->getSymbol(start + 1);
	dif.setIsThumb(sym && sym->isThumbSymbol());

	// Source file name.
	//
	if (auto i = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_decl_file)))
	{
		if (lines)
		{
			std::string declFile;
			if (lines->getFileNameByIndex(
					i.getValue(),
					unit->getCompilationDir(),
					llvm::DILineInfoSpecifier::FileLineInfoKind::AbsoluteFilePath,
					declFile))
			{
				dif.setSourceFileName(declFile);
			}
		}
	}

	// Start & end line.
	//
	retdec::common::Address startLine, endLine;
	if (auto s = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_decl_line)))
	{
		startLine = s.getValue();
	}
	if (startLine.isUndefined())
	{
		startLine = getLineFromAddress(lines, start);
	}
	endLine = getLineFromAddress(lines, end-1);
	dif.setStartLine(startLine);
	dif.setEndLine(endLine);

	// Return type.
	//
	if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
	{
		if (auto odie = unit->getDIEForOffset(o.getValue()))
		{
			dif.returnType = loadDwarf_type(odie);
		}
	}

	// Children.
	//
	unsigned argCntr = 0;
	for (auto c : die.children())
	{
		switch (c.getTag())
		{
			case llvm::dwarf::DW_TAG_unspecified_parameters:
				dif.setIsVariadic(true);
				break;
			case llvm::dwarf::DW_TAG_formal_parameter:
				dif.parameters.push_back(loadDwarf_formal_parameter(c, argCntr++));
				break;
			case llvm::dwarf::DW_TAG_variable:
				dif.locals.insert(loadDwarf_variable(c));
				break;
			default:
				break;
		}
	}

	functions.insert({dif.getStart(), dif});

//==============================================================================
std::cout << std::endl;
std::cout << "\t" << "name       : " << dif.getName() << std::endl;
std::cout << "\t" << "range      : " << dif.getStart() << " - " << dif.getEnd() << std::endl;
std::cout << "\t" << "demangled  : " << dif.getDemangledName() << std::endl;
std::cout << "\t" << "src file   : " << dif.getSourceFileName() << std::endl;
std::cout << "\t" << "variadic?  : " << dif.isVariadic() << std::endl;
std::cout << "\t" << "ret type   : " << dif.returnType.getLlvmIr() << std::endl;
std::cout << "\t" << "lines      : " << dif.getStartLine() << " - " << dif.getEndLine() << std::endl;
std::cout << "\t" << "thumb?     : " << dif.isThumb() << std::endl;
std::cout << "\t" << "param #    : " << dif.parameters.size() << std::endl;
for (auto& p : dif.parameters)
{
	std::cout << std::endl;
	std::cout << "\t\t" << "name    : " << p.getName() << std::endl;
	std::cout << "\t\t" << "type    : " << p.type.getLlvmIr() << std::endl;
}
std::cout << "\t" << "local #    : " << dif.locals.size() << std::endl;
for (auto& l : dif.locals)
{
	std::cout << std::endl;
	std::cout << "\t\t" << "name    : " << l.getName() << std::endl;
	std::cout << "\t\t" << "type    : " << l.type.getLlvmIr() << std::endl;
	std::cout << "\t\t" << "stack   : " << l.getStorage().getStackOffset()
			<< " from "
			<< (l.getStorage().getRegisterNumber().has_value()
				? l.getStorage().getRegisterNumber().value()
				: -1)
			<< std::endl;
}
//==============================================================================

}

std::string DebugFormat::loadDwarf_type(llvm::DWARFDie die)
{
	std::string ret = "i32";

	switch (die.getTag())
	{
		case llvm::dwarf::DW_TAG_base_type:
		{

			break;
		}
		default:
			break;
	}

	types.insert(ret);
	return ret;
}

retdec::common::Object DebugFormat::loadDwarf_formal_parameter(
		llvm::DWARFDie die,
		unsigned argCntr)
{
	std::string name = std::string("arg") + std::to_string(argCntr);
	if (auto n = llvm::dwarf::toString(die.find(
			llvm::dwarf::DW_AT_name)))
	{
		name = n.getValue();
	}

	retdec::common::Object arg(name, retdec::common::Storage::undefined());
	arg.type = getDefaultDataType();
	if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
	{
		if (auto odie = die.getDwarfUnit()->getDIEForOffset(o.getValue()))
		{
			arg.type = loadDwarf_type(odie);
		}
	}
	return arg;
}

retdec::common::Object DebugFormat::loadDwarf_variable(llvm::DWARFDie die)
{
	std::string name;
	if (auto n = llvm::dwarf::toString(die.find(
			llvm::dwarf::DW_AT_name)))
	{
		name = n.getValue();
	}

	retdec::common::Storage storage;
	// storage = retdec::common::Storage::onStack(address, regNum);
	retdec::common::Object var(name, storage);

	if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
	{
		if (auto odie = die.getDwarfUnit()->getDIEForOffset(o.getValue()))
		{
			var.type = loadDwarf_type(odie);
		}
	}

	return var;
}

// void DebugFormat::loadDwarfFunctions()
// {
// 		for (auto* var : *df->getVars())
// 		{
// 			if (var->location == nullptr || var->location->isEmpty() || var->name.empty())
// 			{
// 				continue;
// 			}
// 			retdec::common::Storage storage;
// 			Dwarf_Signed address;
// 			int regNum = -1;
// 			bool deref;
// 			if (var->isOnStack(&address, &deref, 0, &regNum))
// 			{
// 				storage = retdec::common::Storage::onStack(address, regNum);
// 			}
// 			retdec::common::Object newLocalVar(var->name, storage);
// 		}
// }

// void DebugFormat::loadDwarfGlobalVariables()
// {
// std::cout << "loadDwarfGlobalVariables():" << std::endl;
// 	auto* dwarfGvars = _dwarfFile->getGlobalVars();
// 	if (dwarfGvars == nullptr)
// 		return;

// 	for (auto* gvar : *dwarfGvars)
// 	{
// 		if (gvar->location == nullptr || !gvar->location->isNormal() || gvar->name.empty())
// 		{
// 			continue;
// 		}

// 		Dwarf_Addr address;
// 		std::string n;
// 		retdec::dwarfparser::DwarfLocationDesc::cLocType loc = gvar->getLocation(&n, &address, 1);
// 		if (loc.isAddress())
// 		{
// 			auto addr = retdec::common::Address(address);
// 			std::string name = gvar->name.empty() ? "glob_var_" + addr.toHexString() : gvar->name;
// 			if (!addr.isDefined())
// 				continue;
// 			retdec::common::Object gv(name, retdec::common::Storage::inMemory(addr));
// 			gv.type = loadDwarfType(gvar->type);
// 			if (gv.type.getLlvmIr() == "void")
// 				gv.type.setLlvmIr("i32");
// std::cout << "\t" << addr << " @ " << name << " : " << gv.type.getLlvmIr() << std::endl;
// 			globals.insert(gv);
// 		}
// 	}
// }

// retdec::common::Type DebugFormat::loadDwarfType(retdec::dwarfparser::DwarfType* type)
// {
	// if (type == nullptr)
	// {
	// 	return retdec::common::Type("i32");
	// }
	// auto t = retdec::common::Type(type->toLLVMString());
	// return t.isDefined() ? t : retdec::common::Type("i32");
// }

} // namespace debugformat
} // namespace retdec
