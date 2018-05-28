/**
 * @file src/pdbparser/pdb_symbols.cpp
 * @brief Symbols
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "retdec/pdbparser/pdb_symbols.h"

using namespace std;

namespace retdec {
namespace pdbparser {

// =================================================================
//
// CLASS PDBFunction
//
// =================================================================

// =================================================================
// PUBLIC METHODS
// =================================================================

void dump_local_variable(PDBLocalVariable &var)
{
	switch (var.location)
	{  // Print variable location and properties
		case PDBLVLOC_REGISTER:
		{
			printf("\t\tREGISTER block: %d reg_num: %08x type: %08x ", var.block, var.register_num, var.type_index);
			break;
		}
		case PDBLVLOC_BPREL32:
		{
			printf("\t\tBPREL32 block: %d offset: %08x type: %08x ", var.block, var.offset, var.type_index);
			break;
		}
		case PDBLVLOC_REGREL32:
		{
			printf("\t\tREGREL32 block: %d reg: %08x offset: %08x typind: %08x ", var.block, var.register_num,
			        var.offset, var.type_index);
			break;
		}
		default:
			break;
	}
	if (var.type_def != nullptr)
		var.type_def->dump(true);  // Print type definition
	else
		printf("(?)");
	printf(" [%s]\n", var.name);  // Print variable name
}

void PDBFunction::dump(void)
{
	printf("** Function [%s] at 0x%08x\n", name, address);
	if (overload_index > 0)
		printf("\tFunction is overloaded. Index: %d\n", overload_index);
	printf("\tOffset : %08x\n", offset);
	printf("\tSection: %04x\n", section);
	printf("\tModule : %d\n", module_index);
	printf("\tLength : %08x (%d bytes)\n", length, length);
	printf("\tType   : %08x ", type_index);
	if (type_def != nullptr)
	{
		assert(type_def->type_class == PDBTYPE_FUNCTION);
		type_def->dump(true);
	}
	puts("");
	int nblocks = blocks.size();
	if (nblocks > 1)
	{
		printf("\tCode blocks (%d):", nblocks);
		for (int i = 0; i < nblocks; i++)
			printf(" %08x", blocks[i]);
		puts("");
	}
	printf("\tFunction arguments:\n");
	for (unsigned int i = 0; i < arguments.size(); i++)
	{
		dump_local_variable(arguments[i]);
	}
	printf("\tLocal variables:\n");
	for (unsigned int i = 0; i < loc_variables.size(); i++)
	{
		dump_local_variable(loc_variables[i]);
	}
	printf("\tData in function's code:\n");
	for (unsigned int i = 0; i < data.size(); i++)
	{
		printf("\t\tDATA Offset : %08x Section: %04x Type: %08x ", data[i].offset, data[i].section, data[i].type_index);
		int size = -1;
		if (data[i].type_def != nullptr)
		{
			data[i].type_def->dump(true);
			size = data[i].type_def->size_bytes;
		}
		printf(" Size: %d bytes [%s] at 0x%08x\n", size, data[i].name, data[i].address);
	}
	printf("\tLine number information:\n");
	for (unsigned int i = 0; i < lines.size(); i++)
	{
		printf("\t\tLine: %d Offset: %08x (%08x)\n", lines[i].line, lines[i].offset, lines[i].offset + address);
	}
	puts("");
}

bool PDBFunction::parse_symbol(PDBGeneralSymbol *symbol, PDBTypes *types, PDBSymbols *pdbsyms)
{
	switch (symbol->type)
	{
		case S_GPROC32:
		case S_LPROC32:
		{  // Function definition
			PROCSYM32 *func_sym = reinterpret_cast<PROCSYM32 *>(symbol);
			name = reinterpret_cast<char *>(func_sym->name);
			overload_index = 0;
			address = pdbsyms->get_virtual_address(func_sym->seg, func_sym->off);
			offset = func_sym->off;
			section = func_sym->seg;
			length = func_sym->len;
			type_index = func_sym->typind;
			type_def = reinterpret_cast<PDBTypeFunction *>(types->get_type_by_index(type_index));

			if (type_def == nullptr || type_def->type_class != PDBTYPE_FUNCTION)
			{
				return false;
			}

			if (type_def != nullptr)
			{
				assert(type_def->type_class == PDBTYPE_FUNCTION);
				args_remain = type_def->func_args_count;
				if (type_def->func_thistype_index)
					args_remain++;  // This-parameter
				if (type_def->func_is_variadic)
					args_remain--;  // Variadic function
			}
			blocks.push_back(func_sym->off);  // First block is function's beginning
			depth = 1;
			cur_block = 0;
			break;
		}
		case S_FRAMEPROC:
		{  // Function stack frame
			break;
		}
		case S_REGREL32:
		{  // Local variable register-relative
			REGREL32 *lvar_sym = reinterpret_cast<REGREL32 *>(symbol);
			PDBLocalVariable new_var =
			{  // Fill local variable structure
			        reinterpret_cast<char *>(lvar_sym->name), PDBLVLOC_REGREL32, cur_block, lvar_sym->off,
			                lvar_sym->reg, lvar_sym->typind, types->get_type_by_index(lvar_sym->typind), };
			if ((args_remain--) > 0)
				arguments.push_back(new_var);  // variable is function argument
			else
				loc_variables.push_back(new_var);  // variable is local variable
			break;
		}
		case S_BPREL32:
		{  // Local variable EBP-relative
			BPRELSYM32 *lvar_sym = reinterpret_cast<BPRELSYM32 *>(symbol);
			PDBLocalVariable new_var =
			{  // Fill local variable structure
			        reinterpret_cast<char *>(lvar_sym->name), PDBLVLOC_BPREL32, cur_block, lvar_sym->off, 0,
			                lvar_sym->typind, types->get_type_by_index(lvar_sym->typind), };
			if ((args_remain--) > 0)
				arguments.push_back(new_var);  // variable is function argument
			else
				loc_variables.push_back(new_var);  // variable is local variable
			break;
		}
		case S_BLOCK32:
		{  // Block
			BLOCKSYM32 *block_sym = reinterpret_cast<BLOCKSYM32 *>(symbol);
			blocks.push_back(block_sym->off);
			depth++;
			cur_block++;
			break;
		}
		case S_REGISTER:
		{  // Local variable in register
			REGSYM *lvar_sym = reinterpret_cast<REGSYM *>(symbol);
			PDBLocalVariable new_var =
			{  // Fill local variable structure
			        reinterpret_cast<char *>(lvar_sym->name), PDBLVLOC_REGISTER, cur_block, 0, lvar_sym->reg,
			                lvar_sym->typind, types->get_type_by_index(lvar_sym->typind), };
			if ((args_remain--) > 0)
				arguments.push_back(new_var);  // variable is function argument
			else
				loc_variables.push_back(new_var);  // variable is local variable
			break;
		}
			//case S_GDATA32:
		case S_LDATA32:
		{  // Data inside function code
			DATASYM32 *data_sym = reinterpret_cast<DATASYM32 *>(symbol);
			PDBFunctionData new_data =
			{  // Fill structure
			        reinterpret_cast<char *>(data_sym->name),  // Name
			                pdbsyms->get_virtual_address(data_sym->seg, data_sym->off),  // Address
			                data_sym->off,  // Offset
			                data_sym->seg,  // Segment
			                data_sym->typind,  // Type index
			                types->get_type_by_index(data_sym->typind),  // Type definition
			        };
			data.push_back(new_data);
			break;
		}
		case S_END:
		{  // Function or block end
			depth--;
			if (depth == 0)
				return true;  // Function ended
			break;
		}
		default:
			break;
	}
	return false;
}

void PDBFunction::parse_line_info(LineInfoHeader *hdr)
{
	if (hdr == nullptr || hdr->off != unsigned(offset))
		return;
	for (unsigned int i = 0; i < hdr->num_records; i++)
	{  // Process all lines
		LineInfoRecord * record = &hdr->records[i];
		PDBLineInfo new_line =
		{  // Fill line info structure
		        record->line, record->off, };
		lines.push_back(new_line);
	}
}

std::string PDBFunction::getNameWithOverloadIndex() const
{
	std::stringstream ret;
	ret << name;
	if (overload_index > 0)
	{
		ret << "_" << overload_index;
	}
	return ret.str();
}

// =================================================================
//
// CLASS PDBSymbols
//
// =================================================================

// =================================================================
// PUBLIC METHODS
// =================================================================

void PDBSymbols::parse_symbols(void)
{
	if (parsed)
		return;

	// Process SYM stream to find global variables
	int position = 0;
	while (unsigned(position) < pdb_sym_size)
	{
		PDBGeneralSymbol *symbol = reinterpret_cast<PDBGeneralSymbol *>(pdb_sym_data + position);
		if (symbol->type == S_GDATA32 /*|| symbol->type == S_LDATA32*/)
		{  // Global variable
			DATASYM32 * sym = reinterpret_cast<DATASYM32 *>(symbol);
			PDBGlobalVariable new_var =
			{reinterpret_cast<char *>(sym->name),  // Name
			        get_virtual_address(sym->seg, sym->off),  // Address
			        sym->off,  // Offset
			        sym->seg,  // Section
			        -1,  // Module index
			        sym->typind,  // Type index
			        types->get_type_by_index(sym->typind),  // Type definition
			        };
			global_variables[new_var.address] = new_var;
		}
		position += symbol->size + 2;
	}

	// Map to help find overloaded functions (key is function name)
	std::map<std::string, PDBFunction *> func_names;

	// Process all modules streams to find functions and all other information
	for (unsigned int m = 0; m < modules.size(); m++)
	{
		if (modules[m].stream_num == 65535)
			continue;
		PDBStream *stream = modules[m].stream;
		position = 4;
		int cnt = 0;
		PDBFunction * new_function = nullptr;
		while (position < stream->size)
		{  // Process all symbols in module stream
			PDBGeneralSymbol *symbol = reinterpret_cast<PDBGeneralSymbol *>(stream->data + position);
			if (symbol->size == 0xf4 || symbol->size == 0 || symbol->type == 0)
				break;  // Determine the end of symbol list
			switch (symbol->type)
			{
				case S_GPROC32:
				case S_LPROC32:
				{  // Symbol is function begin
					new_function = new PDBFunction(m);  // Create new function
					new_function->parse_symbol(symbol, types, this);

					if (new_function == nullptr || new_function->type_def == nullptr || new_function->type_def->type_class != PDBTYPE_FUNCTION)
					{
						delete new_function;
						new_function = nullptr;
					}

					break;
				}
				case S_GDATA32:
				case S_LDATA32:
				{  // Data symbol
					DATASYM32 * sym = reinterpret_cast<DATASYM32 *>(symbol);
					if (new_function != nullptr && sym->seg <= sections[0].file_address)
						// Data inside function's code
						new_function->parse_symbol(symbol, types, this);
					else
					{  // Global variable
						PDBGlobalVariable new_var =
						{reinterpret_cast<char *>(sym->name),  // Name
						        get_virtual_address(sym->seg, sym->off),  // Address
						        sym->off,  // Offset
						        sym->seg,  // Section
						        int(m),  // Module index
						        sym->typind,  // Type index
						        types->get_type_by_index(sym->typind),  // Type definition
						        };
						global_variables[new_var.address] = new_var;
					}
					break;
				}
				default:
				{  // Any other symbols
					if (new_function != nullptr)
					{
						// Let the function parse symbols between begin and end
						bool ended = new_function->parse_symbol(symbol, types, this);
						if (ended)
						{  // Function definition ended
						   // Check if function is overloaded
							std::map<std::string, PDBFunction *>::iterator it;
							it = func_names.find(new_function->name);
							if (it != func_names.end())
							{  // Function with this name already exists, mark both as overloaded
								int cur_index = it->second->overload_index;
								if (cur_index == 0)  // Give first function index 1
									cur_index = it->second->overload_index = 1;
								new_function->overload_index = cur_index + 1;
								it->second = new_function;
							}
							else
								func_names[new_function->name] = new_function;
							// Add function into functions map
							functions[new_function->address] = new_function;
							new_function = nullptr;
						}
					}
					break;
				}
			}
			cnt++;
			position += symbol->size + 2;
		}

		cnt = 0;
		while (position < stream->size)
		{  // Process all big symbols in module stream
			PDBBigSymbol *symbol = reinterpret_cast<PDBBigSymbol *>(stream->data + position);
			if (symbol->type == 0 || symbol->type > 0xFF || position + int(symbol->size) > stream->size)
				break;
			switch (symbol->type)
			{
				case 0xF2:
				{  // Symbol is line info header
					LineInfoHeader *sym = reinterpret_cast<LineInfoHeader *>(symbol);
					int addr = get_virtual_address(sym->seg, sym->off);

					PDBFunctionAddressMap::iterator fIt = functions.find(addr);
					if (fIt != functions.end() && fIt->second != nullptr)
						fIt->second->parse_line_info(sym);
					break;
				}
				default:
					break;
			}
			position += symbol->size + 8;
			cnt++;
		}
	}
	parsed = true;
}

void PDBSymbols::dump_global_symbols(void)
{
	unsigned int position = 0;
	int cnt = 0;
	puts("******* SYM global symbols *******");
	while (position < pdb_sym_size)
	{
		PDBGeneralSymbol *symbol = reinterpret_cast<PDBGeneralSymbol *>(pdb_sym_data + position);
		printf("Symbol %3d: size %04x type %04x: ", cnt, symbol->size, symbol->type);
		dump_symbol(reinterpret_cast<PSYM>(symbol));

		position += symbol->size + 2;
		cnt++;
	}
	puts("");
}

void PDBSymbols::dump_module_symbols(int index)
{
	puts("******* SYM module symbols *******");
	printf("Module #%d Stream number: %d Module name: %s\n", index, modules[index].stream_num, modules[index].name);
	puts("");
	if (modules[index].stream_num == 65535)
	{
		puts("Module stream is not present in PDB file.\n");
		return;
	}
	PDBStream *stream = modules[index].stream;
	int position = 4;
	int cnt = 0;

	while (position < stream->size)
	{  // Dump symbols
		PDBGeneralSymbol *symbol = reinterpret_cast<PDBGeneralSymbol *>(stream->data + position);
		if (symbol->size == 0xf4 || symbol->size == 0 || symbol->type == 0)
			break;
		printf("Symbol %3d: size %04x type %04x: ", cnt, symbol->size - 2, symbol->type);

		switch (symbol->type)
		{
			case S_END:  //0x0006
			{
				printf("END\n");
				break;
			}
			case S_OEM:  //0x0404
			{
				OEMSYMBOL *sym = reinterpret_cast<OEMSYMBOL *>(symbol);
				printf("OEM idOem: (hexstring) typind: %08x rgl: ", sym->typind);
				print_dwords(sym->rgl, symbol->size - 20);
				printf("\n");
				break;
			}
			case S_FRAMEPROC:  //0x1012
			{
				FRAMEPROCSYM *sym = reinterpret_cast<FRAMEPROCSYM *>(symbol);
				printf(
				        "FRAMEPROC cbFrame: %08x cbPad: %08x offPad: %08x cbSaveRegs: %08x offExHdlr: %08x sectExHdlr: %04x flags: \n",
				        sym->cbFrame, sym->cbPad, sym->offPad, sym->cbSaveRegs, sym->offExHdlr,
				        sym->sectExHdlr/*,*((PDB_DWORD *)(&(sym->flags)))*/);
				break;
			}
			case S_OBJNAME:  //0x1101
			{
				OBJNAMESYM *sym = reinterpret_cast<OBJNAMESYM *>(symbol);
				printf("OBJNAME signature: %08x name: %s\n", sym->signature, sym->name);
				break;
			}
			case S_THUNK32:  //0x1102
			{
				THUNKSYM32 *sym = reinterpret_cast<THUNKSYM32 *>(symbol);
				printf(
				        "THUNK32 pParent: %08x pEnd: %08x pNext: %08x off: %08x seg: %04x len: %04x ord: %02x name: %s\n",
				        sym->pParent, sym->pEnd, sym->pNext, sym->off, sym->seg, sym->len, sym->ord, sym->name);
				break;
			}
			case S_BLOCK32:  //0x1103
			{
				BLOCKSYM32 *sym = reinterpret_cast<BLOCKSYM32 *>(symbol);
				printf("BLOCK32 pParent: %08x pEnd: %08x len: %08x off: %08x seg: %04x name: %s\n", sym->pParent,
				        sym->pEnd, sym->len, sym->off, sym->seg, sym->name);
				break;
			}
			case S_LABEL32:  //0x1105
			{
				LABELSYM32 *sym = reinterpret_cast<LABELSYM32 *>(symbol);
				printf("LABEL32 off: %08x seg: %04x flags: %02x name: %s\n", sym->off, sym->seg, sym->flags.bAll,
				        sym->name);
				break;
			}
			case S_REGISTER:  //0x1106
			{
				REGSYM *sym = reinterpret_cast<REGSYM *>(symbol);
				printf("REGISTER typind: %08x reg: %04x name: %s\n", sym->typind, sym->reg, sym->name);
				break;
			}
			case S_CONSTANT:  //0x1107
			{
				CONSTSYM *sym = reinterpret_cast<CONSTSYM *>(symbol);
				PDB_DWORD value;
				PDB_PBYTE name;
				name = RecordValue(reinterpret_cast<PDB_PBYTE>(&sym->value), &value);
				printf("CONSTANT typind: %08x value: %04x name: %s\n", sym->typind, value, name);
				break;
			}
			case S_UDT:  //0x1108
			{
				UDTSYM *sym = reinterpret_cast<UDTSYM *>(symbol);
				printf("UDT typind: %08x name: %s\n", sym->typind, sym->name);
				break;
			}
			case S_BPREL32:  //0x110b
			{
				BPRELSYM32 *sym = reinterpret_cast<BPRELSYM32 *>(symbol);
				printf("BPREL32 off: %08x typind: %08x name: %s\n", sym->off, sym->typind, sym->name);
				break;
			}
			case S_LDATA32:  //0x110c
			{
				DATASYM32 *sym = reinterpret_cast<DATASYM32 *>(symbol);
				printf("LDATA32 typind: %08x off: %08x seg: %04x name: %s\n", sym->typind, sym->off, sym->seg,
				        sym->name);
				break;
			}
			case S_GDATA32:  //0x110d
			{
				DATASYM32 *sym = reinterpret_cast<DATASYM32 *>(symbol);
				printf("GDATA32 typind: %08x off: %08x seg: %04x name: %s\n", sym->typind, sym->off, sym->seg,
				        sym->name);
				break;
			}
			case S_PUB32:  //0x110e
			{
				PUBSYM32 *sym = reinterpret_cast<PUBSYM32 *>(symbol);
				printf("PUB32 pubsymflags: %08x off: %08x seg: %04x name: %s\n", sym->pubsymflags.grfFlags, sym->off,
				        sym->seg, sym->name);
				break;
			}
			case S_LPROC32:  //0x110f
			{
				PROCSYM32 *sym = reinterpret_cast<PROCSYM32 *>(symbol);
				printf(
				        "LPROC32 pParent: %08x pEnd: %08x pNext: %08x len: %08x DbgStart: %08x DbgEnd: %08x typind: %08x off: %08x seg: %04x flags: %02x name: %s\n",
				        sym->pParent, sym->pEnd, sym->pNext, sym->len, sym->DbgStart, sym->DbgEnd, sym->typind,
				        sym->off, sym->seg, sym->flags.bAll, sym->name);
				break;
			}
			case S_GPROC32:  //0x1110
			{
				PROCSYM32 *sym = reinterpret_cast<PROCSYM32 *>(symbol);
				printf(
				        "GPROC32 pParent: %08x pEnd: %08x pNext: %08x len: %08x DbgStart: %08x DbgEnd: %08x typind: %08x off: %08x seg: %04x flags: %02x name: %s\n",
				        sym->pParent, sym->pEnd, sym->pNext, sym->len, sym->DbgStart, sym->DbgEnd, sym->typind,
				        sym->off, sym->seg, sym->flags.bAll, sym->name);
				break;
			}
			case S_REGREL32:  //0x1111
			{
				REGREL32 *sym = reinterpret_cast<REGREL32 *>(symbol);
				printf("REGREL32 off: %08x typind: %08x reg: %04x name: %s\n", sym->off, sym->typind, sym->reg,
				        sym->name);
				break;
			}
			case S_COMPILE2:  //0x1116
			{
				COMPILESYM *sym = reinterpret_cast<COMPILESYM *>(symbol);
				printf(
				        "COMPILE2 machine: %04x verFEMajor: %04x verFEMinor: %04x verFEBuild: %04x verMajor: %04x verMinor: %04x verBuild: %04x verSt: %s\n",
				        sym->machine, sym->verFEMajor, sym->verFEMinor, sym->verFEBuild, sym->verMajor, sym->verMinor,
				        sym->verBuild, sym->verSt);
				break;
			}
			case S_MANSLOT:  //0x1120
			{
				MANSLOTSYM *sym = reinterpret_cast<MANSLOTSYM *>(symbol);
				printf("(?)MANSLOT %08x %08x %08x %08x %s\n", sym->unknown1, sym->unknown2, sym->unknown3,
				        sym->unknown4, sym->name);
				break;
			}
			case S_UNAMESPACE:  //0x1124
			{
				UNAMESPACE *sym = reinterpret_cast<UNAMESPACE *>(symbol);
				printf("UNAMESPACE name: %s\n", sym->name);
				break;
			}
			case S_GMANPROC:  //0x112a
			{
				MANPROCSYM *sym = reinterpret_cast<MANPROCSYM *>(symbol);
				printf(
				        "GMANPROC pParent: %08x pEnd: %08x pNext: %08x len: %08x DbgStart: %08x DbgEnd: %08x token: %08x off: %08x seg: %04x flags: %02x retReg: %04x name: %s\n",
				        sym->pParent, sym->pEnd, sym->pNext, sym->len, sym->DbgStart, sym->DbgEnd, sym->token, sym->off,
				        sym->seg, sym->flags.bAll, sym->retReg, sym->name);
				break;
			}
			case S_LMANPROC:  //0x112b
			{
				MANPROCSYM *sym = reinterpret_cast<MANPROCSYM *>(symbol);
				printf(
				        "LMANPROC pParent: %08x pEnd: %08x pNext: %08x len: %08x DbgStart: %08x DbgEnd: %08x token: %08x off: %08x seg: %04x flags: %02x retReg: %04x name: %s\n",
				        sym->pParent, sym->pEnd, sym->pNext, sym->len, sym->DbgStart, sym->DbgEnd, sym->token, sym->off,
				        sym->seg, sym->flags.bAll, sym->retReg, sym->name);
				break;
			}
			case S_TRAMPOLINE:  //0x112c
			{
				TRAMPOLINESYM *sym = reinterpret_cast<TRAMPOLINESYM *>(symbol);
				printf(
				        "TRAMPOLINE trampType: %04x cbThunk: %04x offThunk: %08x offTarget: %08x sectThunk: %04x sectTarget: %04x\n",
				        sym->trampType, sym->cbThunk, sym->offThunk, sym->offTarget, sym->sectThunk, sym->sectTarget);
				break;
			}
			case 0x1136:  //0x1136
			{
				SECTIONSYM *sym = reinterpret_cast<SECTIONSYM *>(symbol);
				printf("(?)SECTION seg: %04x ?: %04x off: %08x len: %08x ?: %08x name: %s\n", sym->seg, sym->unknown1,
				        sym->off, sym->len, sym->unknown2, sym->name);
				break;
			}
			case 0x1137:  //0x1137
			{
				COFFGROUPSYM *sym = reinterpret_cast<COFFGROUPSYM *>(symbol);
				printf("(?)COFFGROUP len: %08x ?: %08x off: %08x seg: %04x name: %s\n", sym->len, sym->unknown1,
				        sym->off, sym->seg, sym->name);
				break;
			}
			case 0x1138:  //0x1139
			{
				EXPORTSYM *sym = reinterpret_cast<EXPORTSYM *>(symbol);
				printf("(?)EXPORT %04x %04x %s\n", sym->unknown1, sym->unknown2, sym->name);
				break;
			}
			case 0x1139:  //0x1139
			{
				CALLSITEINFOSYM *sym = reinterpret_cast<CALLSITEINFOSYM *>(symbol);
				printf("(?)CALLSITEINFO %08x %08x %08x\n", sym->unknown1, sym->unknown2, sym->unknown3);
				break;
			}
			case 0x113a:  //0x113a
			{
				FRAMECOOKIESYM *sym = reinterpret_cast<FRAMECOOKIESYM *>(symbol);
				printf("(?)FRAMECOOKIE %08x %08x\n", sym->unknown1, sym->unknown2);
				break;
			}
			case 0x113c:  //0x113c
			{
				COMPILE3SYM *sym = reinterpret_cast<COMPILE3SYM *>(symbol);
				printf("(?)COMPILE3 %08x %04x %08x %08x %08x %08x %s\n", sym->unknown1, sym->unknown2, sym->unknown3,
				        sym->unknown4, sym->unknown5, sym->unknown6, sym->name);
				break;
			}
			case 0x113d:  //0x113d
			{
				printf("(?)ENVBLOCK ");
				for (int i = 0; i < symbol->size - 2; i++)
					putchar(symbol->data[i]);
				printf("\n");
				break;
			}
			case 0x113e:  //0x113e
			{
				LOCALSYM *sym = reinterpret_cast<LOCALSYM *>(symbol);
				printf("(?)LOCAL %08x %04x %s\n", sym->unknown1, sym->unknown2, sym->name);
				break;
			}
			case 0x1141:  //0x1141
			{
				DEFRANGE_REGISTERSYM *sym = reinterpret_cast<DEFRANGE_REGISTERSYM *>(symbol);
				printf("(?)DEFRANGE_REGISTER %08x %08x %04x %04x\n", sym->unknown1, sym->unknown2, sym->unknown3,
				        sym->unknown4);
				break;
			}
			case 0x1142:  //0x1142
			{
				printf("(?)DEFRANGE_FRAMEPOINTER_REL ");
				print_dwords(reinterpret_cast<PDB_DWORD *>(symbol->data), symbol->size);
				printf("\n");
				break;
			}
			case 0x1143:  //0x1143
			{
				printf("(?)DEFRANGE_SUBFIELD_REGISTER ");
				print_dwords(reinterpret_cast<PDB_DWORD *>(symbol->data), symbol->size);
				printf("\n");
				break;
			}
			case 0x1144:  //0x1144
			{
				printf("(?)DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE ");
				print_dwords(reinterpret_cast<PDB_DWORD *>(symbol->data), symbol->size);
				printf("\n");
				break;
			}
			case 0x1145:  //0x1145
			{
				printf("(?)DEFRANGE_REGISTER_REL ");
				print_bytes(reinterpret_cast<PDB_BYTE *>(symbol->data), symbol->size);
				printf("\n");
				break;
			}
			default:
			{
				for (int i = 0; i < symbol->size - 2; i++)
					putchar(symbol->data[i]);
				printf("\n");
			}
		}

		position += symbol->size + 2;
		cnt++;
	}

	puts("");
	cnt = 0;

	while (position < stream->size)
	{  // Dump big symbols
		PDBBigSymbol *symbol = reinterpret_cast<PDBBigSymbol *>(stream->data + position);
		if (symbol->type == 0 || symbol->type > 0xFF || position + int(symbol->size) > stream->size)
			break;
		printf("Big symbol %2d: size %08x type %08x: ", cnt, symbol->size, symbol->type);

		switch (symbol->type)
		{
			case 0xF2:
			{
				LineInfoHeader *sym = reinterpret_cast<LineInfoHeader *>(symbol);
				printf("FUNCTION LINE INFO off: %08x seg: %08x len: %08x lines: %3d u1: %08x u2: %08x\n", sym->off,
				        sym->seg, sym->len, sym->num_records, sym->unknown1, sym->unknown2);
				break;
			}
			default:
			{
				printf("\n");
			}
		}
		position += symbol->size + 8;
		cnt++;
	}
	puts("");
}

void PDBSymbols::dump_all_modules(void)
{
	for (unsigned int i = 0; i < modules.size(); i++)
	{
		dump_module_symbols(i);
		puts("");
	}
}

void PDBSymbols::print_functions(void)
{
	puts("******* SYM functions list *******");
	for (PDBFunctionAddressMap::iterator it = functions.begin(); it != functions.end(); ++it)
	{
		if (it->second != nullptr)
			it->second->dump();
	}
}

void PDBSymbols::print_global_variables(void)
{
	puts("******* SYM global variables list *******");
	for (PDBGlobalVarAddressMap::iterator it = global_variables.begin(); it != global_variables.end(); ++it)
	{
		printf("Global variable [%s] at 0x%08x\n", it->second.name, it->second.address);
		printf("\tOffset : %08x\n", it->second.offset);
		printf("\tSection: %04x\n", it->second.section);
		printf("\tModule : %d\n", it->second.module_index);
		printf("\tType   : %08x ", it->second.type_index);
		int size = -1;
		if (it->second.type_def != nullptr)
		{
			it->second.type_def->dump(true);
			size = it->second.type_def->size_bytes;
		}
		puts("");
		printf("\tSize   : %d bytes\n", size);
		puts("");
	}
}

PDBSymbols::~PDBSymbols(void)
{
	for (PDBFunctionAddressMap::iterator it = functions.begin(); it != functions.end(); ++it)
	{
		if (it->second != nullptr)
			delete it->second;
	}
}

// =================================================================
// PRIVATE METHODS
// =================================================================

void PDBSymbols::dump_symbol(PSYM Sym)
{
	switch (Sym->Sym.rectyp)
	{
		case S_PUB32:
			printf("S_PUB32| [%04x] public%s%s %04x = %s (type %04x)",
			        Sym->Pub32.seg,  // 0x0c
			        Sym->Pub32.pubsymflags.fCode ? " code" : "", Sym->Pub32.pubsymflags.fFunction ? " function" : "",
			        Sym->Pub32.off, Sym->Pub32.name,  // 0x08 0x0e
			        Sym->Data32.typind);  // 0x04
			break;

		case S_CONSTANT:
			PDB_DWORD value;
			PDB_PBYTE name;
			name = RecordValue(reinterpret_cast<PDB_PBYTE>(&Sym->Const.value), &value);
			printf("S_CONSTANT| const %08x = %s", value, name);
			break;

		case S_UDT:
			printf("S_UDT| [%04x] typedef %s;", Sym->Udt.typind, Sym->Udt.name);
			break;

		case S_LPROCREF:
		case S_PROCREF:
			printf("S_%sPROCREF| procref [%s; mod %04x; ibSym %x] %s", Sym->Sym.rectyp == S_LPROCREF ? "L" : "",
			        Sym->Sym.rectyp == S_LPROCREF ? "local" : "global", Sym->Ref2.imod,  // 0x0c
			        Sym->Ref2.ibSym,  // 0x08
			        Sym->Ref2.name);  // 0x0e
			break;

		case S_LDATA32:
		case S_GDATA32:
		{
			printf("S_%sDATA32| data [%s; type %04x] %04x = %s", Sym->Sym.rectyp == S_LDATA32 ? "L" : "G",
			        Sym->Sym.rectyp == S_LDATA32 ? "local" : "global", Sym->Data32.typind, Sym->Data32.off,
			        Sym->Data32.name);
		}
			break;

		default:
			printf("unknown symbol len %04x type %04x\n", Sym->Sym.reclen, Sym->Sym.rectyp);
	}

	puts("");
}

} // namespace pdbparser
} // namespace retdec
