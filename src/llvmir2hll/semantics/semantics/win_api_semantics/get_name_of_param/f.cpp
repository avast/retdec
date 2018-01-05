/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/f.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/f.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with F.
*/
void initFuncParamNamesMap_F(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("FatalAppExitA", 1, "uAction"); // UINT
	ADD_PARAM_NAME("FatalAppExitA", 2, "lpMessageText"); // LPCSTR
	ADD_PARAM_NAME("FatalAppExitW", 1, "uAction"); // UINT
	ADD_PARAM_NAME("FatalAppExitW", 2, "lpMessageText"); // LPCWSTR
	ADD_PARAM_NAME("FatalExit", 1, "ExitCode"); // int
	ADD_PARAM_NAME("FileEncryptionStatusA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("FileEncryptionStatusA", 2, "lpStatus"); // LPDWORD
	ADD_PARAM_NAME("FileEncryptionStatusW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("FileEncryptionStatusW", 2, "lpStatus"); // LPDWORD
	ADD_PARAM_NAME("FileTimeToDosDateTime", 1, "lpFileTime"); // CONST FILETIME *
	ADD_PARAM_NAME("FileTimeToDosDateTime", 2, "lpFatDate"); // LPWORD
	ADD_PARAM_NAME("FileTimeToDosDateTime", 3, "lpFatTime"); // LPWORD
	ADD_PARAM_NAME("FileTimeToLocalFileTime", 1, "lpFileTime"); // CONST FILETIME *
	ADD_PARAM_NAME("FileTimeToLocalFileTime", 2, "lpLocalFileTime"); // LPFILETIME
	ADD_PARAM_NAME("FileTimeToSystemTime", 1, "lpFileTime"); // CONST FILETIME *
	ADD_PARAM_NAME("FileTimeToSystemTime", 2, "lpSystemTime"); // LPSYSTEMTIME
	ADD_PARAM_NAME("FillConsoleOutputAttribute", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("FillConsoleOutputAttribute", 2, "wAttribute"); // WORD
	ADD_PARAM_NAME("FillConsoleOutputAttribute", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("FillConsoleOutputAttribute", 4, "dwWriteCoord"); // COORD
	ADD_PARAM_NAME("FillConsoleOutputAttribute", 5, "lpNumberOfAttrsWritten"); // LPDWORD
	ADD_PARAM_NAME("FillConsoleOutputCharacterA", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("FillConsoleOutputCharacterA", 2, "cCharacter"); // CHAR
	ADD_PARAM_NAME("FillConsoleOutputCharacterA", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("FillConsoleOutputCharacterA", 4, "dwWriteCoord"); // COORD
	ADD_PARAM_NAME("FillConsoleOutputCharacterA", 5, "lpNumberOfCharsWritten"); // LPDWORD
	ADD_PARAM_NAME("FillConsoleOutputCharacterW", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("FillConsoleOutputCharacterW", 2, "cCharacter"); // WCHAR
	ADD_PARAM_NAME("FillConsoleOutputCharacterW", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("FillConsoleOutputCharacterW", 4, "dwWriteCoord"); // COORD
	ADD_PARAM_NAME("FillConsoleOutputCharacterW", 5, "lpNumberOfCharsWritten"); // LPDWORD
	ADD_PARAM_NAME("FillPath", 1, "hdc"); // HDC
	ADD_PARAM_NAME("FillRect", 1, "hDC"); // HDC
	ADD_PARAM_NAME("FillRect", 2, "lprc"); // CONST RECT *
	ADD_PARAM_NAME("FillRect", 3, "hbr"); // HBRUSH
	ADD_PARAM_NAME("FillRgn", 1, "hdc"); // HDC
	ADD_PARAM_NAME("FillRgn", 2, "hrgn"); // HRGN
	ADD_PARAM_NAME("FillRgn", 3, "hbr"); // HBRUSH
	ADD_PARAM_NAME("FindActCtxSectionGuid", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FindActCtxSectionGuid", 2, "lpExtensionGuid"); // const GUID *
	ADD_PARAM_NAME("FindActCtxSectionGuid", 3, "ulSectionId"); // ULONG
	ADD_PARAM_NAME("FindActCtxSectionGuid", 4, "lpGuidToFind"); // const GUID *
	ADD_PARAM_NAME("FindActCtxSectionGuid", 5, "ReturnedData"); // PACTCTX_SECTION_KEYED_DATA
	ADD_PARAM_NAME("FindActCtxSectionStringA", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FindActCtxSectionStringA", 2, "lpExtensionGuid"); // const GUID *
	ADD_PARAM_NAME("FindActCtxSectionStringA", 3, "ulSectionId"); // ULONG
	ADD_PARAM_NAME("FindActCtxSectionStringA", 4, "lpStringToFind"); // LPCSTR
	ADD_PARAM_NAME("FindActCtxSectionStringA", 5, "ReturnedData"); // PACTCTX_SECTION_KEYED_DATA
	ADD_PARAM_NAME("FindActCtxSectionStringW", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FindActCtxSectionStringW", 2, "lpExtensionGuid"); // const GUID *
	ADD_PARAM_NAME("FindActCtxSectionStringW", 3, "ulSectionId"); // ULONG
	ADD_PARAM_NAME("FindActCtxSectionStringW", 4, "lpStringToFind"); // LPCWSTR
	ADD_PARAM_NAME("FindActCtxSectionStringW", 5, "ReturnedData"); // PACTCTX_SECTION_KEYED_DATA
	ADD_PARAM_NAME("FindAtomA", 1, "lpString"); // LPCSTR
	ADD_PARAM_NAME("FindAtomW", 1, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("FindCertsByIssuer", 1, "pCertChains"); // PCERT_CHAIN
	ADD_PARAM_NAME("FindCertsByIssuer", 2, "pcbCertChains"); // DWORD *
	ADD_PARAM_NAME("FindCertsByIssuer", 3, "pcCertChains"); // DWORD *
	ADD_PARAM_NAME("FindCertsByIssuer", 4, "pbEncodedIssuerName"); // BYTE *
	ADD_PARAM_NAME("FindCertsByIssuer", 5, "cbEncodedIssuerName"); // DWORD
	ADD_PARAM_NAME("FindCertsByIssuer", 6, "pwszPurpose"); // LPCWSTR
	ADD_PARAM_NAME("FindCertsByIssuer", 7, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("FindClose", 1, "hFindFile"); // HANDLE
	ADD_PARAM_NAME("FindCloseChangeNotification", 1, "hChangeHandle"); // HANDLE
	ADD_PARAM_NAME("FindClosePrinterChangeNotification", 1, "hChange"); // HANDLE
	ADD_PARAM_NAME("FindFirstChangeNotificationA", 1, "lpPathName"); // LPCSTR
	ADD_PARAM_NAME("FindFirstChangeNotificationA", 2, "bWatchSubtree"); // WINBOOL
	ADD_PARAM_NAME("FindFirstChangeNotificationA", 3, "dwNotifyFilter"); // DWORD
	ADD_PARAM_NAME("FindFirstChangeNotificationW", 1, "lpPathName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstChangeNotificationW", 2, "bWatchSubtree"); // WINBOOL
	ADD_PARAM_NAME("FindFirstChangeNotificationW", 3, "dwNotifyFilter"); // DWORD
	ADD_PARAM_NAME("FindFirstFileA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("FindFirstFileA", 2, "lpFindFileData"); // LPWIN32_FIND_DATAA
	ADD_PARAM_NAME("FindFirstFileExA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("FindFirstFileExA", 2, "fInfoLevelId"); // FINDEX_INFO_LEVELS
	ADD_PARAM_NAME("FindFirstFileExA", 3, "lpFindFileData"); // LPVOID
	ADD_PARAM_NAME("FindFirstFileExA", 4, "fSearchOp"); // FINDEX_SEARCH_OPS
	ADD_PARAM_NAME("FindFirstFileExA", 5, "lpSearchFilter"); // LPVOID
	ADD_PARAM_NAME("FindFirstFileExA", 6, "dwAdditionalFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstFileExW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstFileExW", 2, "fInfoLevelId"); // FINDEX_INFO_LEVELS
	ADD_PARAM_NAME("FindFirstFileExW", 3, "lpFindFileData"); // LPVOID
	ADD_PARAM_NAME("FindFirstFileExW", 4, "fSearchOp"); // FINDEX_SEARCH_OPS
	ADD_PARAM_NAME("FindFirstFileExW", 5, "lpSearchFilter"); // LPVOID
	ADD_PARAM_NAME("FindFirstFileExW", 6, "dwAdditionalFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstFileNameTransactedW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstFileNameTransactedW", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstFileNameTransactedW", 3, "StringLength"); // LPDWORD
	ADD_PARAM_NAME("FindFirstFileNameTransactedW", 4, "LinkName"); // PWCHAR
	ADD_PARAM_NAME("FindFirstFileNameTransactedW", 5, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("FindFirstFileNameW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstFileNameW", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstFileNameW", 3, "StringLength"); // LPDWORD
	ADD_PARAM_NAME("FindFirstFileNameW", 4, "LinkName"); // PWCHAR
	ADD_PARAM_NAME("FindFirstFileTransactedA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("FindFirstFileTransactedA", 2, "fInfoLevelId"); // FINDEX_INFO_LEVELS
	ADD_PARAM_NAME("FindFirstFileTransactedA", 3, "lpFindFileData"); // LPVOID
	ADD_PARAM_NAME("FindFirstFileTransactedA", 4, "fSearchOp"); // FINDEX_SEARCH_OPS
	ADD_PARAM_NAME("FindFirstFileTransactedA", 5, "lpSearchFilter"); // LPVOID
	ADD_PARAM_NAME("FindFirstFileTransactedA", 6, "dwAdditionalFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstFileTransactedA", 7, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("FindFirstFileTransactedW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstFileTransactedW", 2, "fInfoLevelId"); // FINDEX_INFO_LEVELS
	ADD_PARAM_NAME("FindFirstFileTransactedW", 3, "lpFindFileData"); // LPVOID
	ADD_PARAM_NAME("FindFirstFileTransactedW", 4, "fSearchOp"); // FINDEX_SEARCH_OPS
	ADD_PARAM_NAME("FindFirstFileTransactedW", 5, "lpSearchFilter"); // LPVOID
	ADD_PARAM_NAME("FindFirstFileTransactedW", 6, "dwAdditionalFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstFileTransactedW", 7, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("FindFirstFileW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstFileW", 2, "lpFindFileData"); // LPWIN32_FIND_DATAW
	ADD_PARAM_NAME("FindFirstFreeAce", 1, "pAcl"); // PACL
	ADD_PARAM_NAME("FindFirstFreeAce", 2, "pAce"); // LPVOID *
	ADD_PARAM_NAME("FindFirstPrinterChangeNotification", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("FindFirstPrinterChangeNotification", 2, "fdwFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstPrinterChangeNotification", 3, "fdwOptions"); // DWORD
	ADD_PARAM_NAME("FindFirstPrinterChangeNotification", 4, "pPrinterNotifyOptions"); // LPVOID
	ADD_PARAM_NAME("FindFirstStreamTransactedW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstStreamTransactedW", 2, "InfoLevel"); // STREAM_INFO_LEVELS
	ADD_PARAM_NAME("FindFirstStreamTransactedW", 3, "lpFindStreamData"); // LPVOID
	ADD_PARAM_NAME("FindFirstStreamTransactedW", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstStreamTransactedW", 5, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("FindFirstStreamW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstStreamW", 2, "InfoLevel"); // STREAM_INFO_LEVELS
	ADD_PARAM_NAME("FindFirstStreamW", 3, "lpFindStreamData"); // LPVOID
	ADD_PARAM_NAME("FindFirstStreamW", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FindFirstVolumeA", 1, "lpszVolumeName"); // LPSTR
	ADD_PARAM_NAME("FindFirstVolumeA", 2, "cchBufferLength"); // DWORD
	ADD_PARAM_NAME("FindFirstVolumeMountPointA", 1, "lpszRootPathName"); // LPCSTR
	ADD_PARAM_NAME("FindFirstVolumeMountPointA", 2, "lpszVolumeMountPoint"); // LPSTR
	ADD_PARAM_NAME("FindFirstVolumeMountPointA", 3, "cchBufferLength"); // DWORD
	ADD_PARAM_NAME("FindFirstVolumeMountPointW", 1, "lpszRootPathName"); // LPCWSTR
	ADD_PARAM_NAME("FindFirstVolumeMountPointW", 2, "lpszVolumeMountPoint"); // LPWSTR
	ADD_PARAM_NAME("FindFirstVolumeMountPointW", 3, "cchBufferLength"); // DWORD
	ADD_PARAM_NAME("FindFirstVolumeW", 1, "lpszVolumeName"); // LPWSTR
	ADD_PARAM_NAME("FindFirstVolumeW", 2, "cchBufferLength"); // DWORD
	ADD_PARAM_NAME("FindNLSString", 1, "Locale"); // LCID
	ADD_PARAM_NAME("FindNLSString", 2, "dwFindNLSStringFlags"); // DWORD
	ADD_PARAM_NAME("FindNLSString", 3, "lpStringSource"); // LPCWSTR
	ADD_PARAM_NAME("FindNLSString", 4, "cchSource"); // int
	ADD_PARAM_NAME("FindNLSString", 5, "lpStringValue"); // LPCWSTR
	ADD_PARAM_NAME("FindNLSString", 6, "cchValue"); // int
	ADD_PARAM_NAME("FindNLSString", 7, "pcchFound"); // LPINT
	ADD_PARAM_NAME("FindNLSStringEx", 1, "lpLocaleName"); // LPCWSTR
	ADD_PARAM_NAME("FindNLSStringEx", 2, "dwFindNLSStringFlags"); // DWORD
	ADD_PARAM_NAME("FindNLSStringEx", 3, "lpStringSource"); // LPCWSTR
	ADD_PARAM_NAME("FindNLSStringEx", 4, "cchSource"); // int
	ADD_PARAM_NAME("FindNLSStringEx", 5, "lpStringValue"); // LPCWSTR
	ADD_PARAM_NAME("FindNLSStringEx", 6, "cchValue"); // int
	ADD_PARAM_NAME("FindNLSStringEx", 7, "pcchFound"); // LPINT
	ADD_PARAM_NAME("FindNLSStringEx", 8, "lpVersionInformation"); // LPNLSVERSIONINFO
	ADD_PARAM_NAME("FindNLSStringEx", 9, "lpReserved"); // LPVOID
	ADD_PARAM_NAME("FindNLSStringEx", 10, "lParam"); // LPARAM
	ADD_PARAM_NAME("FindNextChangeNotification", 1, "hChangeHandle"); // HANDLE
	ADD_PARAM_NAME("FindNextFileA", 1, "hFindFile"); // HANDLE
	ADD_PARAM_NAME("FindNextFileA", 2, "lpFindFileData"); // LPWIN32_FIND_DATAA
	ADD_PARAM_NAME("FindNextFileNameW", 1, "hFindStream"); // HANDLE
	ADD_PARAM_NAME("FindNextFileNameW", 2, "StringLength"); // LPDWORD
	ADD_PARAM_NAME("FindNextFileNameW", 3, "LinkName"); // PWCHAR
	ADD_PARAM_NAME("FindNextFileW", 1, "hFindFile"); // HANDLE
	ADD_PARAM_NAME("FindNextFileW", 2, "lpFindFileData"); // LPWIN32_FIND_DATAW
	ADD_PARAM_NAME("FindNextPrinterChangeNotification", 1, "hChange"); // HANDLE
	ADD_PARAM_NAME("FindNextPrinterChangeNotification", 2, "pdwChange"); // PDWORD
	ADD_PARAM_NAME("FindNextPrinterChangeNotification", 3, "pPrinterNotifyOptions"); // LPVOID
	ADD_PARAM_NAME("FindNextPrinterChangeNotification", 4, "ppPrinterNotifyInfo"); // LPVOID *
	ADD_PARAM_NAME("FindNextStreamW", 1, "hFindStream"); // HANDLE
	ADD_PARAM_NAME("FindNextStreamW", 2, "lpFindStreamData"); // LPVOID
	ADD_PARAM_NAME("FindNextVolumeA", 1, "hFindVolume"); // HANDLE
	ADD_PARAM_NAME("FindNextVolumeA", 2, "lpszVolumeName"); // LPSTR
	ADD_PARAM_NAME("FindNextVolumeA", 3, "cchBufferLength"); // DWORD
	ADD_PARAM_NAME("FindNextVolumeMountPointA", 1, "hFindVolumeMountPoint"); // HANDLE
	ADD_PARAM_NAME("FindNextVolumeMountPointA", 2, "lpszVolumeMountPoint"); // LPSTR
	ADD_PARAM_NAME("FindNextVolumeMountPointA", 3, "cchBufferLength"); // DWORD
	ADD_PARAM_NAME("FindNextVolumeMountPointW", 1, "hFindVolumeMountPoint"); // HANDLE
	ADD_PARAM_NAME("FindNextVolumeMountPointW", 2, "lpszVolumeMountPoint"); // LPWSTR
	ADD_PARAM_NAME("FindNextVolumeMountPointW", 3, "cchBufferLength"); // DWORD
	ADD_PARAM_NAME("FindNextVolumeW", 1, "hFindVolume"); // HANDLE
	ADD_PARAM_NAME("FindNextVolumeW", 2, "lpszVolumeName"); // LPWSTR
	ADD_PARAM_NAME("FindNextVolumeW", 3, "cchBufferLength"); // DWORD
	ADD_PARAM_NAME("FindResourceA", 1, "hModule"); // HMODULE
	ADD_PARAM_NAME("FindResourceA", 2, "lpName"); // LPCSTR
	ADD_PARAM_NAME("FindResourceA", 3, "lpType"); // LPCSTR
	ADD_PARAM_NAME("FindResourceExA", 1, "hModule"); // HMODULE
	ADD_PARAM_NAME("FindResourceExA", 2, "lpType"); // LPCSTR
	ADD_PARAM_NAME("FindResourceExA", 3, "lpName"); // LPCSTR
	ADD_PARAM_NAME("FindResourceExA", 4, "wLanguage"); // WORD
	ADD_PARAM_NAME("FindResourceExW", 1, "hModule"); // HMODULE
	ADD_PARAM_NAME("FindResourceExW", 2, "lpType"); // LPCWSTR
	ADD_PARAM_NAME("FindResourceExW", 3, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("FindResourceExW", 4, "wLanguage"); // WORD
	ADD_PARAM_NAME("FindResourceW", 1, "hModule"); // HMODULE
	ADD_PARAM_NAME("FindResourceW", 2, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("FindResourceW", 3, "lpType"); // LPCWSTR
	ADD_PARAM_NAME("FindVolumeClose", 1, "hFindVolume"); // HANDLE
	ADD_PARAM_NAME("FindVolumeMountPointClose", 1, "hFindVolumeMountPoint"); // HANDLE
	ADD_PARAM_NAME("FindWindowA", 1, "lpClassName"); // LPCSTR
	ADD_PARAM_NAME("FindWindowA", 2, "lpWindowName"); // LPCSTR
	ADD_PARAM_NAME("FindWindowExA", 1, "hWndParent"); // HWND
	ADD_PARAM_NAME("FindWindowExA", 2, "hWndChildAfter"); // HWND
	ADD_PARAM_NAME("FindWindowExA", 3, "lpszClass"); // LPCSTR
	ADD_PARAM_NAME("FindWindowExA", 4, "lpszWindow"); // LPCSTR
	ADD_PARAM_NAME("FindWindowExW", 1, "hWndParent"); // HWND
	ADD_PARAM_NAME("FindWindowExW", 2, "hWndChildAfter"); // HWND
	ADD_PARAM_NAME("FindWindowExW", 3, "lpszClass"); // LPCWSTR
	ADD_PARAM_NAME("FindWindowExW", 4, "lpszWindow"); // LPCWSTR
	ADD_PARAM_NAME("FindWindowW", 1, "lpClassName"); // LPCWSTR
	ADD_PARAM_NAME("FindWindowW", 2, "lpWindowName"); // LPCWSTR
	ADD_PARAM_NAME("FixBrushOrgEx", 1, "hdc"); // HDC
	ADD_PARAM_NAME("FixBrushOrgEx", 2, "x"); // int
	ADD_PARAM_NAME("FixBrushOrgEx", 3, "y"); // int
	ADD_PARAM_NAME("FixBrushOrgEx", 4, "ptl"); // LPPOINT
	ADD_PARAM_NAME("FlashWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("FlashWindow", 2, "bInvert"); // WINBOOL
	ADD_PARAM_NAME("FlashWindowEx", 1, "pfwi"); // PFLASHWINFO
	ADD_PARAM_NAME("FlattenPath", 1, "hdc"); // HDC
	ADD_PARAM_NAME("FloodFill", 1, "hdc"); // HDC
	ADD_PARAM_NAME("FloodFill", 2, "x"); // int
	ADD_PARAM_NAME("FloodFill", 3, "y"); // int
	ADD_PARAM_NAME("FloodFill", 4, "color"); // COLORREF
	ADD_PARAM_NAME("FlsAlloc", 1, "lpCallback"); // PFLS_CALLBACK_FUNCTION
	ADD_PARAM_NAME("FlsFree", 1, "dwFlsIndex"); // DWORD
	ADD_PARAM_NAME("FlsGetValue", 1, "dwFlsIndex"); // DWORD
	ADD_PARAM_NAME("FlsSetValue", 1, "dwFlsIndex"); // DWORD
	ADD_PARAM_NAME("FlsSetValue", 2, "lpFlsData"); // PVOID
	ADD_PARAM_NAME("FlushConsoleInputBuffer", 1, "hConsoleInput"); // HANDLE
	ADD_PARAM_NAME("FlushFileBuffers", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("FlushInstructionCache", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("FlushInstructionCache", 2, "lpBaseAddress"); // LPCVOID
	ADD_PARAM_NAME("FlushInstructionCache", 3, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("FlushPrinter", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("FlushPrinter", 2, "pBuf"); // LPVOID
	ADD_PARAM_NAME("FlushPrinter", 3, "cbBuf"); // DWORD
	ADD_PARAM_NAME("FlushPrinter", 4, "pcWritten"); // LPDWORD
	ADD_PARAM_NAME("FlushPrinter", 5, "cSleep"); // DWORD
	ADD_PARAM_NAME("FlushViewOfFile", 1, "lpBaseAddress"); // LPCVOID
	ADD_PARAM_NAME("FlushViewOfFile", 2, "dwNumberOfBytesToFlush"); // SIZE_T
	ADD_PARAM_NAME("FoldStringA", 1, "dwMapFlags"); // DWORD
	ADD_PARAM_NAME("FoldStringA", 2, "lpSrcStr"); // LPCSTR
	ADD_PARAM_NAME("FoldStringA", 3, "cchSrc"); // int
	ADD_PARAM_NAME("FoldStringA", 4, "lpDestStr"); // LPSTR
	ADD_PARAM_NAME("FoldStringA", 5, "cchDest"); // int
	ADD_PARAM_NAME("FoldStringW", 1, "dwMapFlags"); // DWORD
	ADD_PARAM_NAME("FoldStringW", 2, "lpSrcStr"); // LPCWSTR
	ADD_PARAM_NAME("FoldStringW", 3, "cchSrc"); // int
	ADD_PARAM_NAME("FoldStringW", 4, "lpDestStr"); // LPWSTR
	ADD_PARAM_NAME("FoldStringW", 5, "cchDest"); // int
	ADD_PARAM_NAME("FormatMessageA", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FormatMessageA", 2, "lpSource"); // LPCVOID
	ADD_PARAM_NAME("FormatMessageA", 3, "dwMessageId"); // DWORD
	ADD_PARAM_NAME("FormatMessageA", 4, "dwLanguageId"); // DWORD
	ADD_PARAM_NAME("FormatMessageA", 5, "lpBuffer"); // LPSTR
	ADD_PARAM_NAME("FormatMessageA", 6, "nSize"); // DWORD
	ADD_PARAM_NAME("FormatMessageW", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("FormatMessageW", 2, "lpSource"); // LPCVOID
	ADD_PARAM_NAME("FormatMessageW", 3, "dwMessageId"); // DWORD
	ADD_PARAM_NAME("FormatMessageW", 4, "dwLanguageId"); // DWORD
	ADD_PARAM_NAME("FormatMessageW", 5, "lpBuffer"); // LPWSTR
	ADD_PARAM_NAME("FormatMessageW", 6, "nSize"); // DWORD
	ADD_PARAM_NAME("FrameRect", 1, "hDC"); // HDC
	ADD_PARAM_NAME("FrameRect", 2, "lprc"); // CONST RECT *
	ADD_PARAM_NAME("FrameRect", 3, "hbr"); // HBRUSH
	ADD_PARAM_NAME("FrameRgn", 1, "hdc"); // HDC
	ADD_PARAM_NAME("FrameRgn", 2, "hrgn"); // HRGN
	ADD_PARAM_NAME("FrameRgn", 3, "hbr"); // HBRUSH
	ADD_PARAM_NAME("FrameRgn", 4, "w"); // int
	ADD_PARAM_NAME("FrameRgn", 5, "h"); // int
	ADD_PARAM_NAME("FreeEncryptionCertificateHashList", 1, "pHashes"); // PENCRYPTION_CERTIFICATE_HASH_LIST
	ADD_PARAM_NAME("FreeEnvironmentStringsA", 1, "lpszEnvironmentBlock"); // LPCH
	ADD_PARAM_NAME("FreeEnvironmentStringsW", 1, "lpszEnvironmentBlock"); // LPWCH
	ADD_PARAM_NAME("FreeLibrary", 1, "hLibModule"); // HMODULE
	ADD_PARAM_NAME("FreeLibraryAndExitThread", 1, "hLibModule"); // HMODULE
	ADD_PARAM_NAME("FreeLibraryAndExitThread", 2, "dwExitCode"); // DWORD
	ADD_PARAM_NAME("FreeLibraryWhenCallbackReturns", 1, "pci"); // PTP_CALLBACK_INSTANCE
	ADD_PARAM_NAME("FreeLibraryWhenCallbackReturns", 2, "mod"); // HMODULE
	ADD_PARAM_NAME("FreePrinterNotifyInfo", 1, "pPrinterNotifyInfo"); // PPRINTER_NOTIFY_INFO
	ADD_PARAM_NAME("FreeResource", 1, "hResData"); // HGLOBAL
	ADD_PARAM_NAME("FreeSid", 1, "pSid"); // PSID
	ADD_PARAM_NAME("FreeUserPhysicalPages", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("FreeUserPhysicalPages", 2, "NumberOfPages"); // PULONG_PTR
	ADD_PARAM_NAME("FreeUserPhysicalPages", 3, "PageArray"); // PULONG_PTR
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
