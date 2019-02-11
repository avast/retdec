/**
 * @file include/retdec/fileformat/types/visual_basic/visual_basic_structures.h
 * @brief Visual basic metadata structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_VISUAL_BASIC_STRUCTURES_H
#define RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_VISUAL_BASIC_STRUCTURES_H

#include <string>

namespace retdec {
namespace fileformat {

constexpr std::size_t VBHEADER_SIGNATURE = 0x21354256;
constexpr std::size_t VB_MAX_STRING_LEN = 100;

enum class VBExternTableEntryType
{
	internal = 0x6,
	external = 0x7
};

struct VBHeader
{
	std::uint32_t signature;                 ///< "VB5!" signature
	std::uint16_t runtimeBuild;              ///< runtime flag
	std::uint8_t languageDLL[14];            ///< language DLL
	std::uint8_t backupLanguageDLL[14];      ///< backup language DLL
	std::uint16_t runtimeDLLVersion;         ///< version of the runtime DLL
	std::uint32_t LCID1;                     ///< primary LCID
	std::uint32_t LCID2;                     ///< backup LCID
	std::uint32_t subMainAddr;               ///< sub main code address
	std::uint32_t projectInfoAddr;           ///< ProjectInfo address
	std::uint32_t MDLIntObjsFlags;           ///< VB controll flags for IDs < 32
	std::uint32_t MDLIntObjsFlags2;          ///< VB controll flags for IDs > 32
	std::uint32_t threadFlags;               ///< thread flags
	std::uint32_t nThreads;                  ///< number of threads to support in pool
	std::uint16_t nForms;                    ///< number of forms in this application
	std::uint16_t nExternals;                ///< number of external OCX components
	std::uint32_t nThunks;                   ///< number of thunks to create
	std::uint32_t GUITableAddr;              ///< GUITable address
	std::uint32_t externalTableAddr;         ///< ExternalTable address
	std::uint32_t COMRegisterDataAddr;       ///< ComRegisterData address
	std::uint32_t projExeNameOffset;         ///< offset to the string containing EXE filename
	std::uint32_t projDescOffset;            ///< offset to the string containing project's description
	std::uint32_t helpFileOffset;            ///< offset to the string containing name of the Help file
	std::uint32_t projNameOffset;            ///< offset to the string containing project's name

	VBHeader()
	{

	}

	std::size_t headerSize()
	{
		return
			sizeof(signature) + sizeof(runtimeBuild) + sizeof(languageDLL) +
			sizeof(backupLanguageDLL) + sizeof(runtimeDLLVersion) + sizeof(LCID1) +
			sizeof(LCID2) + sizeof(subMainAddr) + sizeof(projectInfoAddr) +
			sizeof(MDLIntObjsFlags) + sizeof(MDLIntObjsFlags2) + sizeof(threadFlags) +
			sizeof(nThreads) + sizeof(nForms) + sizeof(nExternals) +
			sizeof(nThunks) + sizeof(GUITableAddr) + sizeof(externalTableAddr) +
			sizeof(COMRegisterDataAddr) + sizeof(projExeNameOffset) + sizeof(projDescOffset) +
			sizeof(helpFileOffset) + sizeof(projNameOffset);
	}

	void dump(std::ostream &out)
	{
		// out << "signature:\t\t";
		// for (std::size_t i = 0; i < sizeof(signature); i++)
		// {
		// 	out << signature[i];
		// }
		// out << "\n";

		out << "runtimeBuild:\t\t" << runtimeBuild << "\n";

		out << "languageDLL:\t\t";
		for (std::size_t i = 0; i < sizeof(languageDLL); i++)
		{
			if (!languageDLL[i])
			{
				break;
			}
			out << languageDLL[i];
		}
		out << "\n";

		out << "backupLanguageDLL:\t";
		for (std::size_t i = 0; i < sizeof(backupLanguageDLL); i++)
		{
			if (!backupLanguageDLL[i])
			{
				break;
			}
			out << backupLanguageDLL[i];
		}
		out << "\n";

		out << "runtimeDLLVersion:\t" << runtimeDLLVersion << "\n";
		out << "LCID1:\t\t" << LCID1 << "\n";
		out << "LCID2:\t" << LCID2 << "\n";
		out << "subMainAddr:\t\t" << std::hex << subMainAddr << "\n";
		out << "projectInfoAddr:\t\t" << projectInfoAddr << std::dec << "\n";
		out << "MDLIntObjsFlags:\t\t" << MDLIntObjsFlags << "\n";
		out << "MDLIntObjsFlags2:\t\t" << MDLIntObjsFlags2 << "\n";
		out << "threadFlags:\t\t" << threadFlags << "\n";
		out << "nThreads:\t\t" << nThreads << "\n";
		out << "nForms:\t\t" << nForms << "\n";
		out << "nExternals:\t" << nExternals << "\n";
		out << "nThunks:\t\t" << nThunks << "\n";
		out << "GUITableAddr:\t\t" << std::hex << GUITableAddr << "\n";
		out << "externalTableAddr:" << externalTableAddr << "\n";
		out << "COMRegisterDataAddr:\t" << COMRegisterDataAddr << "\n";
		out << "projExeNameOffset:\t" << projExeNameOffset << "\n";
		out << "projDescOffset:\t\t" << projDescOffset << "\n";
		out << "helpFileOffset:\t\t" << helpFileOffset << "\n";
		out << "projNameOffset:\t\t" << projNameOffset << std::dec << "\n";
		out << "\n";
	}
};

struct VBProjInfo
{
	std::uint32_t version;                        ///< 5.00 in Hex (0x1F4), version
	std::uint32_t objectTableAddr;                ///< Object table address
	std::uint32_t null;                           ///< unused value after compilation
	std::uint32_t codeStartAddr;                  ///< etart of code address
	std::uint32_t codeEndAddr;                    ///< end of code address
	std::uint32_t dataSize;                       ///< size of VB object structures
	std::uint32_t threadSpaceAddr;                ///< eddress of address of thread object
	std::uint32_t exHandlerAddr;                  ///< VBA exception handler address
	std::uint32_t nativeCodeAddr;                 ///< .DATA section address
	std::uint8_t pathInformation[528];            ///< path and id string, <SP6
	std::uint32_t externalTableAddr;              ///< External table address
	std::uint32_t nExternals;                     ///< number of external OCX components

	VBProjInfo()
	{

	}

	std::size_t headerSize()
	{
		return
			sizeof(version) + sizeof(objectTableAddr) + sizeof(null)
			+ sizeof(codeStartAddr) + sizeof(codeEndAddr) + sizeof(dataSize)
			+ sizeof(threadSpaceAddr) + sizeof(exHandlerAddr) + sizeof(nativeCodeAddr)
			+ sizeof(pathInformation) + sizeof(externalTableAddr) + sizeof(nExternals);
	}

	void dump(std::ostream &out)
	{
		out << "version:\t\t" << version << "\n";
		out << "objectTableAddr:\t\t" << objectTableAddr << "\n";
		out << "null:\t\t\t" << null << "\n";
		out << "codeStartAddr:\t\t" << codeStartAddr << "\n";
		out << "codeEndAddr:\t\t" << codeEndAddr << "\n";
		out << "dataSize:\t\t" << dataSize << "\n";
		out << "threadSpaceAddr:\t\t" << threadSpaceAddr << "\n";
		out << "exHandlerAddr:\t\t" << exHandlerAddr << "\n";
		out << "nativeCodeAddr:\t\t" << nativeCodeAddr << "\n";
		out << "externalTableAddr:\t" << externalTableAddr << "\n";
		out << "nExternals:\t" << nExternals << "\n";
		out << "\n";
	}
};

struct VBObjectTable
{
	std::uint32_t null1;                          ///< null
	std::uint32_t execCOMAddr;                    ///< VB Project Exec COM address
	std::uint32_t projecInfo2Addr;                ///< Project Info 2 address
	std::uint32_t reserved;                       ///< reserved
	std::uint32_t null2;                          ///< null
	std::uint32_t projectObjectAddr;              ///< In-memory data address
	std::uint8_t objectGUID[16];                  ///< Object table GUID
	std::uint16_t flagsCompileState;              ///< internal compilation flags
	std::uint16_t nObjects;                       ///< number of objects
	std::uint16_t nCompiledObjects;               ///< number of compiled objects
	std::uint16_t nUsedObjects;                   ///< number of used objects
	std::uint32_t objectDescriptorsAddr;          ///< Object descriptos address
	std::uint32_t IDE1;                           ///< IDE1 internals
	std::uint32_t IDE2;                           ///< IDE2 internals
	std::uint32_t IDE3;                           ///< IDE3 internals
	std::uint32_t projectNameAddr;                ///< project name address
	std::uint32_t LCID1;                          ///< LCID
	std::uint32_t LCID2;                          ///< backup LCID
	std::uint32_t IDE4;                           ///< IDE4 internals
	std::uint32_t templateVesion;                 ///< template version

	VBObjectTable()
	{

	}

	std::size_t structureSize()
	{
		return
			sizeof(null1) + sizeof(execCOMAddr) + sizeof(projecInfo2Addr) + sizeof(reserved) +
			sizeof(null2) + sizeof(projectObjectAddr) + sizeof(objectGUID) + sizeof(flagsCompileState) +
			sizeof(nObjects) + sizeof(nCompiledObjects) + sizeof(nUsedObjects) +
			sizeof(objectDescriptorsAddr) + sizeof(IDE1) + sizeof(IDE2) + sizeof(IDE3) +
			sizeof(projectNameAddr) + sizeof(LCID1) + sizeof(LCID2) + sizeof(IDE4) +
			sizeof(templateVesion);
	}

	void dump(std::ostream &out)
	{
		out << "null1:\t\t\t" << null1 << "\n";
		out << "execCOMAddr:\t\t" << execCOMAddr << "\n";
		out << "projecInfo2Addr:\t" << projecInfo2Addr << "\n";
		out << "reserved:\t\t" << reserved << "\n";
		out << "null2:\t\t\t" << null2 << "\n";
		out << "projectObjectAddr:\t" << projectObjectAddr << "\n";
		// out << "objectGUID:\t\t" << objectGUID << "\n"; // TODO
		out << "flagsCompileState:\t\t" << flagsCompileState << "\n";
		out << "nObjects:\t\t" << nObjects << "\n";
		out << "nCompiledObjects:\t" << nCompiledObjects << "\n";
		out << "nUsedObjects:\t\t" << nUsedObjects << "\n";
		out << "objectDescriptorsAddr:\t" << objectDescriptorsAddr << "\n";
		out << "IDE1:\t\t\t" << IDE1 << "\n";
		out << "IDE2:\t\t\t" << IDE2 << "\n";
		out << "IDE3:\t\t\t" << IDE3 << "\n";
		out << "projectNameAddr:\t" << projectNameAddr << "\n";
		out << "LCID1:\t\t\t" << LCID1 << "\n";
		out << "LCID2:\t\t\t" << LCID2 << "\n";
		out << "IDE4:\t\t\t" << IDE4 << "\n";
		out << "templateVesion:\t\t" << templateVesion << "\n";
	}
};

struct VBPublicObjectDescriptor
{
	std::uint32_t objectInfoAddr;                 ///< Object info of this object address
	std::uint32_t reserved;                       ///< reserved
	std::uint32_t publicBytesAddr;                ///< public integers address
	std::uint32_t staticBytesAddr;                ///< static integers address
	std::uint32_t modulePublicAddr;               ///< public DATA section address
	std::uint32_t moduleStaticAddr;               ///< static DATA section address
	std::uint32_t objectNameAddr;                 ///< object name address
	std::uint32_t nMethods;                       ///< number of methods
	std::uint32_t methodNamesAddr;                ///< method names array address
	std::uint32_t staticVarsCopyAddr;             ///< static variables copy destionation offset
	std::uint32_t objectType;                     ///< object type flags
	std::uint32_t null;                           ///< null

	VBPublicObjectDescriptor()
	{

	}

	std::size_t structureSize()
	{
		return
			sizeof(objectInfoAddr) + sizeof(reserved) + sizeof(publicBytesAddr) +
			sizeof(staticBytesAddr) + sizeof(modulePublicAddr) + sizeof(moduleStaticAddr) +
			sizeof(objectNameAddr) + sizeof(nMethods) + sizeof(methodNamesAddr) +
			sizeof(staticVarsCopyAddr) + sizeof(objectType) + sizeof(null);
	}

	void dump(std::ostream &out)
	{
		out << "objectInfoAddr:\t\t" << objectInfoAddr << "\n";
		out << "reserved:\t\t" << reserved << "\n";
		out << "publicBytesAddr:\t" << publicBytesAddr << "\n";
		out << "staticBytesAddr:\t" << staticBytesAddr << "\n";
		out << "modulePublicAddr:\t" << modulePublicAddr << "\n";
		out << "moduleStaticAddr:\t" << moduleStaticAddr << "\n";
		out << "objectNameAddr:\t\t" << objectNameAddr << "\n";
		out << "nMethods:\t\t" << nMethods << "\n";
		out << "methodNamesAddr:\t" << methodNamesAddr << "\n";
		out << "staticVarsCopyAddr:\t" << staticVarsCopyAddr << "\n";
		out << "objectType:\t\t" << objectType << "\n";
		out << "null:\t\t\t" << null << "\n";
	}
};

struct VBExternTableEntry
{
	std::uint32_t type;                      ///< import type
	std::uint32_t importDataAddr;            ///< import data address

	VBExternTableEntry()
	{

	}

	std::size_t structureSize()
	{
		return sizeof(type) + sizeof(importDataAddr);
	}

	void dump(std::ostream &out)
	{
		out << "type:\t\t" << type << "\n";
		out << "importDataAddr:\t\t" << importDataAddr << "\n";
		out << "\n";
	}
};

struct VBExternTableEntryData
{
	std::uint32_t moduleNameAddr;            ///< mode name address
	std::uint32_t apiNameAddr;               ///< api name address

	VBExternTableEntryData()
	{

	}

	std::size_t structureSize()
	{
		return sizeof(moduleNameAddr) + sizeof(apiNameAddr);
	}

	void dump(std::ostream &out)
	{
		out << "moduleNameAddr:\t" << moduleNameAddr << "\n";
		out << "apiNameAddr:\t" << apiNameAddr << "\n";
		out << "\n";
	}
};

struct VBCOMRData
{
	std::uint32_t regInfoOffset;             ///< Registration Info offset
	std::uint32_t projNameOffset;            ///< Project/TypeLib name offset
	std::uint32_t helpFileOffset;            ///< Help file offset
	std::uint32_t projDescOffset;            ///< Project description offset
	std::uint8_t projCLSID[16];              ///< Project/TypeLib CLSID
	std::uint32_t projTlbLCID;               ///< TypeLib library LCID
	std::uint16_t unknown;                   ///< unknown
	std::uint16_t tlbVerMajor;               ///< TypeLib major version
	std::uint16_t tlbVerMinor;               ///< TypeLib minor version
	
	VBCOMRData()
	{

	}

	std::size_t structureSize()
	{
		return
			sizeof(regInfoOffset) + sizeof(projNameOffset) + sizeof(helpFileOffset) +
			sizeof(projDescOffset) + sizeof(projCLSID) + sizeof(projTlbLCID) +
			sizeof(unknown) + sizeof(tlbVerMajor) + sizeof(tlbVerMinor);
	}

	void dump(std::ostream &out)
	{
		out << std::hex;
		out << "regInfoOffset\t:" << regInfoOffset << "\n";
		out << "projNameOffset\t:" << projNameOffset << "\n";
		out << "helpFileOffset\t:" << helpFileOffset << "\n";
		out << "projDescOffset\t:" << projDescOffset << "\n";
		out << "projTlbLCID\t:" << projTlbLCID << "\n";
		out << "unknown\t\t:" << unknown << "\n";
		out << "tlbVerMajor\t:" << tlbVerMajor << "\n";
		out << "tlbVerMinor\t:" << tlbVerMinor << "\n";
		out << std::dec;
	}
};

struct VBCOMRInfo
{
	std::uint32_t ifInfoOffset;              ///< Offset to COM Interface Info
	std::uint32_t objNameOffset;             ///< Offset to object name
	std::uint32_t objDescOffset;             ///< Offset to object description
	std::uint32_t instancing;                ///< Instancing mode
	std::uint32_t objID;                     ///< Object ID within project
	std::uint8_t objCLSID[16];               ///< Object CLSID
	std::uint32_t isInterfaceFlag;           ///< Specifies whether Interface CLSID is valid
	std::uint32_t ifCLSIDOffset;             ///< Interface CLSID
	std::uint32_t eventCLSIDOffset;          ///< Event CLSID
	std::uint32_t hasEvents;                 ///< Specifies whether Event CLSID is valid
	std::uint32_t olemicsFlags;              ///< Status
	std::uint8_t classType;                  ///< Class Type
	std::uint8_t objectType;                 ///< Object Type
	std::uint16_t toolboxBitmap32;           ///< Control Bitmap ID in toobox
	std::uint16_t defaultIcon;               ///< Minimized icon of control window
	std::uint16_t isDesignerFlag;            ///< Specifies whether Designed Data offset is valid
	std::uint32_t designerDataOffset;        ///< Offset to Designed Data
	
	VBCOMRInfo()
	{

	}

	std::size_t structureSize()
	{
		return
			sizeof(ifInfoOffset) + sizeof(objNameOffset) + sizeof(objDescOffset) +
			sizeof(instancing) + sizeof(objID) + sizeof(objCLSID) + sizeof(isInterfaceFlag) +
			sizeof(ifCLSIDOffset) + sizeof(eventCLSIDOffset) + sizeof(hasEvents) +
			sizeof(olemicsFlags) + sizeof(classType) + sizeof(objectType) +
			sizeof(toolboxBitmap32) + sizeof(defaultIcon) + sizeof(isDesignerFlag) +
			sizeof(designerDataOffset);
	}

	void dump(std::ostream &out)
	{
		out << std::hex;
		out << "ifInfoOffset:\t\t" << ifInfoOffset << "\n";
		out << "objNameOffset:\t\t" << objNameOffset << "\n";
		out << "objDescOffset:\t\t" << objDescOffset << "\n";
		out << "instancing:\t\t" << instancing << "\n";
		out << "objID:\t\t" << objID << "\n";
		out << "isInterfaceFlag:\t\t" << isInterfaceFlag << "\n";
		out << "ifCLSIDOffset:\t\t" << ifCLSIDOffset << "\n";
		out << "eventCLSIDOffset:\t\t" << eventCLSIDOffset << "\n";
		out << "hasEvents:\t\t" << hasEvents << "\n";
		out << "olemicsFlags:\t\t" << olemicsFlags << "\n";
		out << "classType:\t\t" << static_cast<uint16_t>(classType) << "\n";
		out << "objectType:\t\t" << static_cast<uint16_t>(objectType) << "\n";
		out << "toolboxBitmap32:\t\t" << toolboxBitmap32 << "\n";
		out << "defaultIcon:\t\t" << defaultIcon << "\n";
		out << "isDesignerFlag:\t\t" << isDesignerFlag << "\n";
		out << "designerDataOffset:\t\t" << designerDataOffset << "\n";
	}
};

} // namespace fileformat
} // namespace retdec

#endif
