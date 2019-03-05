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

	static std::size_t structureSize()
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

	static std::size_t structureSize()
	{
		return
			sizeof(version) + sizeof(objectTableAddr) + sizeof(null)
			+ sizeof(codeStartAddr) + sizeof(codeEndAddr) + sizeof(dataSize)
			+ sizeof(threadSpaceAddr) + sizeof(exHandlerAddr) + sizeof(nativeCodeAddr)
			+ sizeof(pathInformation) + sizeof(externalTableAddr) + sizeof(nExternals);
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

	static std::size_t structureSize()
	{
		return
			sizeof(null1) + sizeof(execCOMAddr) + sizeof(projecInfo2Addr) + sizeof(reserved) +
			sizeof(null2) + sizeof(projectObjectAddr) + sizeof(objectGUID) + sizeof(flagsCompileState) +
			sizeof(nObjects) + sizeof(nCompiledObjects) + sizeof(nUsedObjects) +
			sizeof(objectDescriptorsAddr) + sizeof(IDE1) + sizeof(IDE2) + sizeof(IDE3) +
			sizeof(projectNameAddr) + sizeof(LCID1) + sizeof(LCID2) + sizeof(IDE4) +
			sizeof(templateVesion);
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

	static std::size_t structureSize()
	{
		return
			sizeof(objectInfoAddr) + sizeof(reserved) + sizeof(publicBytesAddr) +
			sizeof(staticBytesAddr) + sizeof(modulePublicAddr) + sizeof(moduleStaticAddr) +
			sizeof(objectNameAddr) + sizeof(nMethods) + sizeof(methodNamesAddr) +
			sizeof(staticVarsCopyAddr) + sizeof(objectType) + sizeof(null);
	}
};

struct VBExternTableEntry
{
	std::uint32_t type;                      ///< import type
	std::uint32_t importDataAddr;            ///< import data address

	static std::size_t structureSize()
	{
		return sizeof(type) + sizeof(importDataAddr);
	}
};

struct VBExternTableEntryData
{
	std::uint32_t moduleNameAddr;            ///< mode name address
	std::uint32_t apiNameAddr;               ///< api name address

	static std::size_t structureSize()
	{
		return sizeof(moduleNameAddr) + sizeof(apiNameAddr);
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

	static std::size_t structureSize()
	{
		return
			sizeof(regInfoOffset) + sizeof(projNameOffset) + sizeof(helpFileOffset) +
			sizeof(projDescOffset) + sizeof(projCLSID) + sizeof(projTlbLCID) +
			sizeof(unknown) + sizeof(tlbVerMajor) + sizeof(tlbVerMinor);
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

	static std::size_t structureSize()
	{
		return
			sizeof(ifInfoOffset) + sizeof(objNameOffset) + sizeof(objDescOffset) +
			sizeof(instancing) + sizeof(objID) + sizeof(objCLSID) + sizeof(isInterfaceFlag) +
			sizeof(ifCLSIDOffset) + sizeof(eventCLSIDOffset) + sizeof(hasEvents) +
			sizeof(olemicsFlags) + sizeof(classType) + sizeof(objectType) +
			sizeof(toolboxBitmap32) + sizeof(defaultIcon) + sizeof(isDesignerFlag) +
			sizeof(designerDataOffset);
	}
};

} // namespace fileformat
} // namespace retdec

#endif
