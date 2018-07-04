/**
 * @file src/fileformat/types/import_table/import_table.cpp
 * @brief Class for import table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/crypto/crypto.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/types/import_table/import_table.h"

using namespace retdec::utils;

namespace {

// Ordinal-name LUT for YARA compatible import hash computation.
// This must stay compatible with YARA's ord_lookup function

std::map<std::size_t, std::string> winsock32Map =
{
	{1, "accept"},
	{2, "bind"},
	{3, "closesocket"},
	{4, "connect"},
	{5, "getpeername"},
	{6, "getsockname"},
	{7, "getsockopt"},
	{8, "htonl"},
	{9, "htons"},
	{10, "ioctlsocket"},
	{11, "inet_addr"},
	{12, "inet_ntoa"},
	{13, "listen"},
	{14, "ntohl"},
	{15, "ntohs"},
	{16, "recv"},
	{17, "recvfrom"},
	{18, "select"},
	{19, "send"},
	{20, "sendto"},
	{21, "setsockopt"},
	{22, "shutdown"},
	{23, "socket"},
	{24, "GetAddrInfoW"},
	{25, "GetNameInfoW"},
	{26, "WSApSetPostRoutine"},
	{27, "FreeAddrInfoW"},
	{28, "WPUCompleteOverlappedRequest"},
	{29, "WSAAccept"},
	{30, "WSAAddressToStringA"},
	{31, "WSAAddressToStringW"},
	{32, "WSACloseEvent"},
	{33, "WSAConnect"},
	{34, "WSACreateEvent"},
	{35, "WSADuplicateSocketA"},
	{36, "WSADuplicateSocketW"},
	{37, "WSAEnumNameSpaceProvidersA"},
	{38, "WSAEnumNameSpaceProvidersW"},
	{39, "WSAEnumNetworkEvents"},
	{40, "WSAEnumProtocolsA"},
	{41, "WSAEnumProtocolsW"},
	{42, "WSAEventSelect"},
	{43, "WSAGetOverlappedResult"},
	{44, "WSAGetQOSByName"},
	{45, "WSAGetServiceClassInfoA"},
	{46, "WSAGetServiceClassInfoW"},
	{47, "WSAGetServiceClassNameByClassIdA"},
	{48, "WSAGetServiceClassNameByClassIdW"},
	{49, "WSAHtonl"},
	{50, "WSAHtons"},
	{51, "gethostbyaddr"},
	{52, "gethostbyname"},
	{53, "getprotobyname"},
	{54, "getprotobynumber"},
	{55, "getservbyname"},
	{56, "getservbyport"},
	{57, "gethostname"},
	{58, "WSAInstallServiceClassA"},
	{59, "WSAInstallServiceClassW"},
	{60, "WSAIoctl"},
	{61, "WSAJoinLeaf"},
	{62, "WSALookupServiceBeginA"},
	{63, "WSALookupServiceBeginW"},
	{64, "WSALookupServiceEnd"},
	{65, "WSALookupServiceNextA"},
	{66, "WSALookupServiceNextW"},
	{67, "WSANSPIoctl"},
	{68, "WSANtohl"},
	{69, "WSANtohs"},
	{70, "WSAProviderConfigChange"},
	{71, "WSARecv"},
	{72, "WSARecvDisconnect"},
	{73, "WSARecvFrom"},
	{74, "WSARemoveServiceClass"},
	{75, "WSAResetEvent"},
	{76, "WSASend"},
	{77, "WSASendDisconnect"},
	{78, "WSASendTo"},
	{79, "WSASetEvent"},
	{80, "WSASetServiceA"},
	{81, "WSASetServiceW"},
	{82, "WSASocketA"},
	{83, "WSASocketW"},
	{84, "WSAStringToAddressA"},
	{85, "WSAStringToAddressW"},
	{86, "WSAWaitForMultipleEvents"},
	{87, "WSCDeinstallProvider"},
	{88, "WSCEnableNSProvider"},
	{89, "WSCEnumProtocols"},
	{90, "WSCGetProviderPath"},
	{91, "WSCInstallNameSpace"},
	{92, "WSCInstallProvider"},
	{93, "WSCUnInstallNameSpace"},
	{94, "WSCUpdateProvider"},
	{95, "WSCWriteNameSpaceOrder"},
	{96, "WSCWriteProviderOrder"},
	{97, "freeaddrinfo"},
	{98, "getaddrinfo"},
	{99, "getnameinfo"},
	{101, "WSAAsyncSelect"},
	{102, "WSAAsyncGetHostByAddr"},
	{103, "WSAAsyncGetHostByName"},
	{104, "WSAAsyncGetProtoByNumber"},
	{105, "WSAAsyncGetProtoByName"},
	{106, "WSAAsyncGetServByPort"},
	{107, "WSAAsyncGetServByName"},
	{108, "WSACancelAsyncRequest"},
	{109, "WSASetBlockingHook"},
	{110, "WSAUnhookBlockingHook"},
	{111, "WSAGetLastError"},
	{112, "WSASetLastError"},
	{113, "WSACancelBlockingCall"},
	{114, "WSAIsBlocking"},
	{115, "WSAStartup"},
	{116, "WSACleanup"},
	{151, "__WSAFDIsSet"},
	{500, "WEP"}
};

std::map<std::size_t, std::string> oleaut32Map =
{
	{2, "SysAllocString"},
	{3, "SysReAllocString"},
	{4, "SysAllocStringLen"},
	{5, "SysReAllocStringLen"},
	{6, "SysFreeString"},
	{7, "SysStringLen"},
	{8, "VariantInit"},
	{9, "VariantClear"},
	{10, "VariantCopy"},
	{11, "VariantCopyInd"},
	{12, "VariantChangeType"},
	{13, "VariantTimeToDosDateTime"},
	{14, "DosDateTimeToVariantTime"},
	{15, "SafeArrayCreate"},
	{16, "SafeArrayDestroy"},
	{17, "SafeArrayGetDim"},
	{18, "SafeArrayGetElemsize"},
	{19, "SafeArrayGetUBound"},
	{20, "SafeArrayGetLBound"},
	{21, "SafeArrayLock"},
	{22, "SafeArrayUnlock"},
	{23, "SafeArrayAccessData"},
	{24, "SafeArrayUnaccessData"},
	{25, "SafeArrayGetElement"},
	{26, "SafeArrayPutElement"},
	{27, "SafeArrayCopy"},
	{28, "DispGetParam"},
	{29, "DispGetIDsOfNames"},
	{30, "DispInvoke"},
	{31, "CreateDispTypeInfo"},
	{32, "CreateStdDispatch"},
	{33, "RegisterActiveObject"},
	{34, "RevokeActiveObject"},
	{35, "GetActiveObject"},
	{36, "SafeArrayAllocDescriptor"},
	{37, "SafeArrayAllocData"},
	{38, "SafeArrayDestroyDescriptor"},
	{39, "SafeArrayDestroyData"},
	{40, "SafeArrayRedim"},
	{41, "SafeArrayAllocDescriptorEx"},
	{42, "SafeArrayCreateEx"},
	{43, "SafeArrayCreateVectorEx"},
	{44, "SafeArraySetRecordInfo"},
	{45, "SafeArrayGetRecordInfo"},
	{46, "VarParseNumFromStr"},
	{47, "VarNumFromParseNum"},
	{48, "VarI2FromUI1"},
	{49, "VarI2FromI4"},
	{50, "VarI2FromR4"},
	{51, "VarI2FromR8"},
	{52, "VarI2FromCy"},
	{53, "VarI2FromDate"},
	{54, "VarI2FromStr"},
	{55, "VarI2FromDisp"},
	{56, "VarI2FromBool"},
	{57, "SafeArraySetIID"},
	{58, "VarI4FromUI1"},
	{59, "VarI4FromI2"},
	{60, "VarI4FromR4"},
	{61, "VarI4FromR8"},
	{62, "VarI4FromCy"},
	{63, "VarI4FromDate"},
	{64, "VarI4FromStr"},
	{65, "VarI4FromDisp"},
	{66, "VarI4FromBool"},
	{67, "SafeArrayGetIID"},
	{68, "VarR4FromUI1"},
	{69, "VarR4FromI2"},
	{70, "VarR4FromI4"},
	{71, "VarR4FromR8"},
	{72, "VarR4FromCy"},
	{73, "VarR4FromDate"},
	{74, "VarR4FromStr"},
	{75, "VarR4FromDisp"},
	{76, "VarR4FromBool"},
	{77, "SafeArrayGetVartype"},
	{78, "VarR8FromUI1"},
	{79, "VarR8FromI2"},
	{80, "VarR8FromI4"},
	{81, "VarR8FromR4"},
	{82, "VarR8FromCy"},
	{83, "VarR8FromDate"},
	{84, "VarR8FromStr"},
	{85, "VarR8FromDisp"},
	{86, "VarR8FromBool"},
	{87, "VarFormat"},
	{88, "VarDateFromUI1"},
	{89, "VarDateFromI2"},
	{90, "VarDateFromI4"},
	{91, "VarDateFromR4"},
	{92, "VarDateFromR8"},
	{93, "VarDateFromCy"},
	{94, "VarDateFromStr"},
	{95, "VarDateFromDisp"},
	{96, "VarDateFromBool"},
	{97, "VarFormatDateTime"},
	{98, "VarCyFromUI1"},
	{99, "VarCyFromI2"},
	{100, "VarCyFromI4"},
	{101, "VarCyFromR4"},
	{102, "VarCyFromR8"},
	{103, "VarCyFromDate"},
	{104, "VarCyFromStr"},
	{105, "VarCyFromDisp"},
	{106, "VarCyFromBool"},
	{107, "VarFormatNumber"},
	{108, "VarBstrFromUI1"},
	{109, "VarBstrFromI2"},
	{110, "VarBstrFromI4"},
	{111, "VarBstrFromR4"},
	{112, "VarBstrFromR8"},
	{113, "VarBstrFromCy"},
	{114, "VarBstrFromDate"},
	{115, "VarBstrFromDisp"},
	{116, "VarBstrFromBool"},
	{117, "VarFormatPercent"},
	{118, "VarBoolFromUI1"},
	{119, "VarBoolFromI2"},
	{120, "VarBoolFromI4"},
	{121, "VarBoolFromR4"},
	{122, "VarBoolFromR8"},
	{123, "VarBoolFromDate"},
	{124, "VarBoolFromCy"},
	{125, "VarBoolFromStr"},
	{126, "VarBoolFromDisp"},
	{127, "VarFormatCurrency"},
	{128, "VarWeekdayName"},
	{129, "VarMonthName"},
	{130, "VarUI1FromI2"},
	{131, "VarUI1FromI4"},
	{132, "VarUI1FromR4"},
	{133, "VarUI1FromR8"},
	{134, "VarUI1FromCy"},
	{135, "VarUI1FromDate"},
	{136, "VarUI1FromStr"},
	{137, "VarUI1FromDisp"},
	{138, "VarUI1FromBool"},
	{139, "VarFormatFromTokens"},
	{140, "VarTokenizeFormatString"},
	{141, "VarAdd"},
	{142, "VarAnd"},
	{143, "VarDiv"},
	{144, "DllCanUnloadNow"},
	{145, "DllGetClassObject"},
	{146, "DispCallFunc"},
	{147, "VariantChangeTypeEx"},
	{148, "SafeArrayPtrOfIndex"},
	{149, "SysStringByteLen"},
	{150, "SysAllocStringByteLen"},
	{151, "DllRegisterServer"},
	{152, "VarEqv"},
	{153, "VarIdiv"},
	{154, "VarImp"},
	{155, "VarMod"},
	{156, "VarMul"},
	{157, "VarOr"},
	{158, "VarPow"},
	{159, "VarSub"},
	{160, "CreateTypeLib"},
	{161, "LoadTypeLib"},
	{162, "LoadRegTypeLib"},
	{163, "RegisterTypeLib"},
	{164, "QueryPathOfRegTypeLib"},
	{165, "LHashValOfNameSys"},
	{166, "LHashValOfNameSysA"},
	{167, "VarXor"},
	{168, "VarAbs"},
	{169, "VarFix"},
	{170, "OaBuildVersion"},
	{171, "ClearCustData"},
	{172, "VarInt"},
	{173, "VarNeg"},
	{174, "VarNot"},
	{175, "VarRound"},
	{176, "VarCmp"},
	{177, "VarDecAdd"},
	{178, "VarDecDiv"},
	{179, "VarDecMul"},
	{180, "CreateTypeLib2"},
	{181, "VarDecSub"},
	{182, "VarDecAbs"},
	{183, "LoadTypeLibEx"},
	{184, "SystemTimeToVariantTime"},
	{185, "VariantTimeToSystemTime"},
	{186, "UnRegisterTypeLib"},
	{187, "VarDecFix"},
	{188, "VarDecInt"},
	{189, "VarDecNeg"},
	{190, "VarDecFromUI1"},
	{191, "VarDecFromI2"},
	{192, "VarDecFromI4"},
	{193, "VarDecFromR4"},
	{194, "VarDecFromR8"},
	{195, "VarDecFromDate"},
	{196, "VarDecFromCy"},
	{197, "VarDecFromStr"},
	{198, "VarDecFromDisp"},
	{199, "VarDecFromBool"},
	{200, "GetErrorInfo"},
	{201, "SetErrorInfo"},
	{202, "CreateErrorInfo"},
	{203, "VarDecRound"},
	{204, "VarDecCmp"},
	{205, "VarI2FromI1"},
	{206, "VarI2FromUI2"},
	{207, "VarI2FromUI4"},
	{208, "VarI2FromDec"},
	{209, "VarI4FromI1"},
	{210, "VarI4FromUI2"},
	{211, "VarI4FromUI4"},
	{212, "VarI4FromDec"},
	{213, "VarR4FromI1"},
	{214, "VarR4FromUI2"},
	{215, "VarR4FromUI4"},
	{216, "VarR4FromDec"},
	{217, "VarR8FromI1"},
	{218, "VarR8FromUI2"},
	{219, "VarR8FromUI4"},
	{220, "VarR8FromDec"},
	{221, "VarDateFromI1"},
	{222, "VarDateFromUI2"},
	{223, "VarDateFromUI4"},
	{224, "VarDateFromDec"},
	{225, "VarCyFromI1"},
	{226, "VarCyFromUI2"},
	{227, "VarCyFromUI4"},
	{228, "VarCyFromDec"},
	{229, "VarBstrFromI1"},
	{230, "VarBstrFromUI2"},
	{231, "VarBstrFromUI4"},
	{232, "VarBstrFromDec"},
	{233, "VarBoolFromI1"},
	{234, "VarBoolFromUI2"},
	{235, "VarBoolFromUI4"},
	{236, "VarBoolFromDec"},
	{237, "VarUI1FromI1"},
	{238, "VarUI1FromUI2"},
	{239, "VarUI1FromUI4"},
	{240, "VarUI1FromDec"},
	{241, "VarDecFromI1"},
	{242, "VarDecFromUI2"},
	{243, "VarDecFromUI4"},
	{244, "VarI1FromUI1"},
	{245, "VarI1FromI2"},
	{246, "VarI1FromI4"},
	{247, "VarI1FromR4"},
	{248, "VarI1FromR8"},
	{249, "VarI1FromDate"},
	{250, "VarI1FromCy"},
	{251, "VarI1FromStr"},
	{252, "VarI1FromDisp"},
	{253, "VarI1FromBool"},
	{254, "VarI1FromUI2"},
	{255, "VarI1FromUI4"},
	{256, "VarI1FromDec"},
	{257, "VarUI2FromUI1"},
	{258, "VarUI2FromI2"},
	{259, "VarUI2FromI4"},
	{260, "VarUI2FromR4"},
	{261, "VarUI2FromR8"},
	{262, "VarUI2FromDate"},
	{263, "VarUI2FromCy"},
	{264, "VarUI2FromStr"},
	{265, "VarUI2FromDisp"},
	{266, "VarUI2FromBool"},
	{267, "VarUI2FromI1"},
	{268, "VarUI2FromUI4"},
	{269, "VarUI2FromDec"},
	{270, "VarUI4FromUI1"},
	{271, "VarUI4FromI2"},
	{272, "VarUI4FromI4"},
	{273, "VarUI4FromR4"},
	{274, "VarUI4FromR8"},
	{275, "VarUI4FromDate"},
	{276, "VarUI4FromCy"},
	{277, "VarUI4FromStr"},
	{278, "VarUI4FromDisp"},
	{279, "VarUI4FromBool"},
	{280, "VarUI4FromI1"},
	{281, "VarUI4FromUI2"},
	{282, "VarUI4FromDec"},
	{283, "BSTR_UserSize"},
	{284, "BSTR_UserMarshal"},
	{285, "BSTR_UserUnmarshal"},
	{286, "BSTR_UserFree"},
	{287, "VARIANT_UserSize"},
	{288, "VARIANT_UserMarshal"},
	{289, "VARIANT_UserUnmarshal"},
	{290, "VARIANT_UserFree"},
	{291, "LPSAFEARRAY_UserSize"},
	{292, "LPSAFEARRAY_UserMarshal"},
	{293, "LPSAFEARRAY_UserUnmarshal"},
	{294, "LPSAFEARRAY_UserFree"},
	{295, "LPSAFEARRAY_Size"},
	{296, "LPSAFEARRAY_Marshal"},
	{297, "LPSAFEARRAY_Unmarshal"},
	{298, "VarDecCmpR8"},
	{299, "VarCyAdd"},
	{300, "DllUnregisterServer"},
	{301, "OACreateTypeLib2"},
	{303, "VarCyMul"},
	{304, "VarCyMulI4"},
	{305, "VarCySub"},
	{306, "VarCyAbs"},
	{307, "VarCyFix"},
	{308, "VarCyInt"},
	{309, "VarCyNeg"},
	{310, "VarCyRound"},
	{311, "VarCyCmp"},
	{312, "VarCyCmpR8"},
	{313, "VarBstrCat"},
	{314, "VarBstrCmp"},
	{315, "VarR8Pow"},
	{316, "VarR4CmpR8"},
	{317, "VarR8Round"},
	{318, "VarCat"},
	{319, "VarDateFromUdateEx"},
	{322, "GetRecordInfoFromGuids"},
	{323, "GetRecordInfoFromTypeInfo"},
	{325, "SetVarConversionLocaleSetting"},
	{326, "GetVarConversionLocaleSetting"},
	{327, "SetOaNoCache"},
	{329, "VarCyMulI8"},
	{330, "VarDateFromUdate"},
	{331, "VarUdateFromDate"},
	{332, "GetAltMonthNames"},
	{333, "VarI8FromUI1"},
	{334, "VarI8FromI2"},
	{335, "VarI8FromR4"},
	{336, "VarI8FromR8"},
	{337, "VarI8FromCy"},
	{338, "VarI8FromDate"},
	{339, "VarI8FromStr"},
	{340, "VarI8FromDisp"},
	{341, "VarI8FromBool"},
	{342, "VarI8FromI1"},
	{343, "VarI8FromUI2"},
	{344, "VarI8FromUI4"},
	{345, "VarI8FromDec"},
	{346, "VarI2FromI8"},
	{347, "VarI2FromUI8"},
	{348, "VarI4FromI8"},
	{349, "VarI4FromUI8"},
	{360, "VarR4FromI8"},
	{361, "VarR4FromUI8"},
	{362, "VarR8FromI8"},
	{363, "VarR8FromUI8"},
	{364, "VarDateFromI8"},
	{365, "VarDateFromUI8"},
	{366, "VarCyFromI8"},
	{367, "VarCyFromUI8"},
	{368, "VarBstrFromI8"},
	{369, "VarBstrFromUI8"},
	{370, "VarBoolFromI8"},
	{371, "VarBoolFromUI8"},
	{372, "VarUI1FromI8"},
	{373, "VarUI1FromUI8"},
	{374, "VarDecFromI8"},
	{375, "VarDecFromUI8"},
	{376, "VarI1FromI8"},
	{377, "VarI1FromUI8"},
	{378, "VarUI2FromI8"},
	{379, "VarUI2FromUI8"},
	{401, "OleLoadPictureEx"},
	{402, "OleLoadPictureFileEx"},
	{411, "SafeArrayCreateVector"},
	{412, "SafeArrayCopyData"},
	{413, "VectorFromBstr"},
	{414, "BstrFromVector"},
	{415, "OleIconToCursor"},
	{416, "OleCreatePropertyFrameIndirect"},
	{417, "OleCreatePropertyFrame"},
	{418, "OleLoadPicture"},
	{419, "OleCreatePictureIndirect"},
	{420, "OleCreateFontIndirect"},
	{421, "OleTranslateColor"},
	{422, "OleLoadPictureFile"},
	{423, "OleSavePictureFile"},
	{424, "OleLoadPicturePath"},
	{425, "VarUI4FromI8"},
	{426, "VarUI4FromUI8"},
	{427, "VarI8FromUI8"},
	{428, "VarUI8FromI8"},
	{429, "VarUI8FromUI1"},
	{430, "VarUI8FromI2"},
	{431, "VarUI8FromR4"},
	{432, "VarUI8FromR8"},
	{433, "VarUI8FromCy"},
	{434, "VarUI8FromDate"},
	{435, "VarUI8FromStr"},
	{436, "VarUI8FromDisp"},
	{437, "VarUI8FromBool"},
	{438, "VarUI8FromI1"},
	{439, "VarUI8FromUI2"},
	{440, "VarUI8FromUI4"},
	{441, "VarUI8FromDec"},
	{442, "RegisterTypeLibForUser"},
	{443, "UnRegisterTypeLibForUser"}
};

/**
 * Lookup import name for given library name and ordinal number
 * @param libName library name
 * @param ordNum ordinal number
 * @return new string name
 */
std::string ordLookUp(const std::string& libName, const std::size_t& ordNum)
{
	std::string res;

	if(libName == "ws2_32.dll" || libName == "wsock32.dll")
	{
		res = mapGetValueOrDefault(winsock32Map, ordNum);
	}
	else if (libName == "oleaut32.dll")
	{
		res = mapGetValueOrDefault(oleaut32Map, ordNum);
	}

	return res.empty() ? "ord" + std::to_string(ordNum) : res;
}

} // anonymous namespace

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
ImportTable::ImportTable()
{

}

/**
 * Destructor
 */
ImportTable::~ImportTable()
{

}

/**
 * Get number of libraries which are imported
 * @return Number of libraries which are imported
 */
std::size_t ImportTable::getNumberOfLibraries() const
{
	return libraries.size();
}

/**
 * Get number of imports in import table
 * @return Number of imports in import table
 */
std::size_t ImportTable::getNumberOfImports() const
{
	return imports.size();
}

/**
 * Get number of imports from selected library
 * @param libraryIndex Index of selected library (indexed from 0)
 * @return Number of imports from selected library or 0 if library index is invalid
 */
std::size_t ImportTable::getNumberOfImportsInLibrary(std::size_t libraryIndex) const
{
	std::size_t result = 0;
	if(libraryIndex < libraries.size())
	{
		for(const auto &imp : imports)
		{
			if(imp->getLibraryIndex() == libraryIndex)
			{
				++result;
			}
		}
	}

	return result;
}

/**
 * Get number of imports from selected library
 * @param name Name of selected library
 * @return Number of imports from selected library or 0 if library was not found
 */
std::size_t ImportTable::getNumberOfImportsInLibrary(const std::string &name) const
{
	std::size_t result = 0;

	for(std::size_t i = 0, e = getNumberOfLibraries(); i < e; ++i)
	{
		if(libraries[i] == name)
		{
			result += getNumberOfImportsInLibrary(i);
		}
	}

	return result;
}

/**
 * Get number of imports from selected library
 * @param name Name of selected library (cse-insensitive)
 * @return Number of imports from selected library or 0 if library was not found
 */
std::size_t ImportTable::getNumberOfImportsInLibraryCaseInsensitive(const std::string &name) const
{
	std::size_t result = 0;

	for(std::size_t i = 0, e = getNumberOfLibraries(); i < e; ++i)
	{
		if(areEqualCaseInsensitive(libraries[i], name))
		{
			result += getNumberOfImportsInLibrary(i);
		}
	}

	return result;
}

/**
 * Get imphash as CRC32
 * @return Imphash as CRC32
 */
const std::string& ImportTable::getImphashCrc32() const
{
	return impHashCrc32;
}

/**
 * Get imphash as MD5
 * @return Imphash as MD5
 */
const std::string& ImportTable::getImphashMd5() const
{
	return impHashMd5;
}

/**
 * Get imphash as SHA256
 * @return Imphash as SHA256
 */
const std::string& ImportTable::getImphashSha256() const
{
	return impHashSha256;
}

/**
 * Get name of imported library
 * @param libraryIndex Index of selected library (indexed from 0)
 * @return Name of selected library or empty string if library index is invalid
 */
std::string ImportTable::getLibrary(std::size_t libraryIndex) const
{
	return (libraryIndex < getNumberOfLibraries()) ? libraries[libraryIndex] : "";
}

/**
 * Get selected import
 * @param importIndex Index of selected import (indexed from 0)
 * @return Pointer to selected import or @c nullptr if import index is invalid
 */
const Import* ImportTable::getImport(std::size_t importIndex) const
{
	return (importIndex < getNumberOfImports()) ? imports[importIndex].get() : nullptr;
}

/**
 * Get import by name
 * @param name Name of the import to get
 * @return Pointer to import with the specified name or @c nullptr if such import not found
 */
const Import* ImportTable::getImport(const std::string &name) const
{
	for(const auto &i : imports)
	{
		if(i->getName() == name)
		{
			return i.get();
		}
	}

	return nullptr;
}

/**
 * Get selected import
 * @param address Adress of selected import
 * @return Pointer to selected import or @c nullptr if import address is invalid
 */
const Import* ImportTable::getImportOnAddress(unsigned long long address) const
{
	for(const auto &i : imports)
	{
		if(i->getAddress() == address)
		{
			return i.get();
		}
	}

	return nullptr;
}

/**
 * Get begin imports iterator
 * @return Begin imports iterator
 */
ImportTable::importsIterator ImportTable::begin() const
{
	return imports.begin();
}

/**
 * Get end imports iterator
 * @return End imports iterator
 */
ImportTable::importsIterator ImportTable::end() const
{
	return imports.end();
}

/**
 * Compute import hashes - CRC32, MD5, SHA256.
 */
void ImportTable::computeHashes()
{
	std::vector<std::uint8_t> impHashBytes;
	for (const auto& import : imports)
	{
		if(!import->isUsedForImphash())
		{
			continue;
		}

		auto libName = toLower(getLibrary(import->getLibraryIndex()));
		auto funcName = toLower(import->getName());

		// YARA compatible name lookup
		if(funcName.empty())
		{
			unsigned long long ord;
			if(import->getOrdinalNumber(ord))
			{
				funcName = toLower(ordLookUp(libName, ord));
			}
		}

		// Cut common suffixes
		if(endsWith(libName, ".ocx")
				|| endsWith(libName, ".sys")
				|| endsWith(libName, ".dll"))
		{
			libName.erase(libName.length() - 4, 4);
		}

		if(libName.empty() || funcName.empty())
		{
			continue;
		}

		// Yara adds comma if there are multiple imports
		if(!impHashBytes.empty())
		{
			impHashBytes.push_back(static_cast<unsigned char>(','));
		}

		for(const auto c : std::string(libName + "." + funcName))
		{
			impHashBytes.push_back(static_cast<unsigned char>(c));
		}
	}

	impHashCrc32 = retdec::crypto::getCrc32(impHashBytes.data(), impHashBytes.size());
	impHashMd5 = retdec::crypto::getMd5(impHashBytes.data(), impHashBytes.size());
	impHashSha256 = retdec::crypto::getSha256(impHashBytes.data(), impHashBytes.size());
}

/**
 * Reset table and delete all records from it
 */
void ImportTable::clear()
{
	libraries.clear();
	imports.clear();
	impHashCrc32.clear();
	impHashMd5.clear();
	impHashSha256.clear();
}

/**
 * Add name of imported library
 * @param name Name of imported library
 *
 * Order in which are libraries added must be same as order of libraries import in input file
 */
void ImportTable::addLibrary(std::string name)
{
	libraries.push_back(name);
}

/**
 * Add import
 * @param import Import which will be added
 */
void ImportTable::addImport(std::unique_ptr<Import>&& import)
{
	imports.push_back(std::move(import));
}

/**
 * Find out if there are any libraries.
 * @return @c true if there are some libraries, @c false otherwise.
 */
bool ImportTable::hasLibraries() const
{
	return !libraries.empty();
}

/**
 * Find out if there is library with name @a name
 * @param name Name of selected library
 * @return @c true if there is library with name @a name, @c false otherwise
 */
bool ImportTable::hasLibrary(const std::string &name) const
{
	return hasItem(libraries, name);
}

/**
 * Find out if there is library with name @a name (case-insensitive)
 * @param name Name of selected library
 * @return @c true if there is library with name @a name, @c false otherwise
 */
bool ImportTable::hasLibraryCaseInsensitive(const std::string &name) const
{
	for(const auto &item : libraries)
	{
		if(areEqualCaseInsensitive(item, name))
		{
			return true;
		}
	}

	return false;
}

/**
 * Find out if there are any imports.
 * @return @c true if there are some imports, @c false otherwise
 */
bool ImportTable::hasImports() const
{
	return !imports.empty();
}

/**
 * Check if import with name @a name exists
 * @param name Name of import
 * @return @c true if import with name @a name exists, @c false otherwise
 */
bool ImportTable::hasImport(const std::string &name) const
{
	return getImport(name);
}

/**
 * Check if import on address exists
 * @param address Adress of import
 * @return @c true if has import on @a address, @c false otherwise
 */
bool ImportTable::hasImport(unsigned long long address) const
{
	return getImportOnAddress(address);
}

/**
 * Check if import table is empty
 * @return @c true if table does not contain any library name or import, @c false otherwise
 */
bool ImportTable::empty() const
{
	return !hasLibraries() && !hasImports();
}

/**
 * Dump information about all imports in table
 * @param dumpTable Into this parameter is stored dump of import table in an LLVM style
 */
void ImportTable::dump(std::string &dumpTable) const
{
	std::stringstream ret;

	ret << "; ------------ Imported functions ------------\n";
	ret << "; Number of libraries: " << getNumberOfLibraries() << "\n";
	ret << "; Number of imports: " << getNumberOfImports() << "\n";
	const auto crc32 = getImphashCrc32();
	const auto md5 = getImphashMd5();
	const auto sha256 = getImphashSha256();
	if(!crc32.empty())
	{
		ret << "; CRC32: " << crc32 << "\n";
	}
	if(!md5.empty())
	{
		ret << "; MD5: " << md5 << "\n";
	}
	if(!sha256.empty())
	{
		ret << "; SHA256: " << sha256 << "\n";
	}

	if(hasLibraries())
	{
		ret << ";\n";
		for(const auto &lib : libraries)
		{
			ret << "; " << lib << "\n";
		}
	}

	if(hasImports())
	{
		unsigned long long aux;
		ret << ";\n";

		for(const auto &imp : imports)
		{
			ret << "; " << std::hex << imp->getName() << " (addr: " << imp->getAddress() <<
				", ord: " << std::dec << (imp->getOrdinalNumber(aux) ? numToStr(aux, std::dec) : "-") <<
				", libId: " << (imp->getLibraryIndex() < getNumberOfLibraries() ?
				numToStr(imp->getLibraryIndex(), std::dec) : "-") << ")\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

/**
 * Dump information about selected library
 * @param libraryIndex Index of selected library (indexed from 0)
 * @param libraryDump Into this parameter is stored dump of selected library
 */
void ImportTable::dumpLibrary(std::size_t libraryIndex, std::string &libraryDump) const
{
	libraryDump.clear();
	if(libraryIndex >= getNumberOfLibraries())
	{
		return;
	}

	std::stringstream ret;
	std::vector<std::size_t> indexes;

	for(std::size_t i = 0, e = imports.size(); i < e; ++i)
	{
		if(imports[i]->getLibraryIndex() == libraryIndex)
		{
			indexes.push_back(i);
		}
	}

	ret << "; ------------ Import library ------------\n";
	ret << "; Name: " << getLibrary(libraryIndex) << "\n";
	ret << "; Number of imports: " << indexes.size() << "\n";

	if(!indexes.empty())
	{
		unsigned long long aux;
		ret << ";\n";

		for(const auto &i : indexes)
		{
			ret << "; " << std::hex << imports[i]->getName() << " (addr: " << imports[i]->getAddress() <<
				", ord: " << std::dec << (imports[i]->getOrdinalNumber(aux) ? numToStr(aux, std::dec) : "-") <<
				", libId: " << imports[i]->getLibraryIndex() << ")\n";
		}
	}

	libraryDump = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
