/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/w.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/w.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with W.
*/
void initFuncParamNamesMap_W(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("WICConvertBitmapSource", 1, "dstFormat"); // REFWICPixelFormatGUID
	ADD_PARAM_NAME("WICConvertBitmapSource", 2, "pISrc"); // IWICBitmapSource *
	ADD_PARAM_NAME("WICConvertBitmapSource", 3, "ppIDst"); // IWICBitmapSource * *
	ADD_PARAM_NAME("WINNLSEnableIME", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("WINNLSEnableIME", 2, "bFlag"); // WINBOOL
	ADD_PARAM_NAME("WINNLSGetEnableStatus", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("WINNLSGetIMEHotkey", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("WNetAddConnection2A", 1, "lpNetResource"); // LPNETRESOURCEA
	ADD_PARAM_NAME("WNetAddConnection2A", 2, "lpPassword"); // LPCSTR
	ADD_PARAM_NAME("WNetAddConnection2A", 3, "lpUserName"); // LPCSTR
	ADD_PARAM_NAME("WNetAddConnection2A", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WNetAddConnection2W", 1, "lpNetResource"); // LPNETRESOURCEW
	ADD_PARAM_NAME("WNetAddConnection2W", 2, "lpPassword"); // LPCWSTR
	ADD_PARAM_NAME("WNetAddConnection2W", 3, "lpUserName"); // LPCWSTR
	ADD_PARAM_NAME("WNetAddConnection2W", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WNetAddConnection3A", 1, "hwndOwner"); // HWND
	ADD_PARAM_NAME("WNetAddConnection3A", 2, "lpNetResource"); // LPNETRESOURCEA
	ADD_PARAM_NAME("WNetAddConnection3A", 3, "lpPassword"); // LPCSTR
	ADD_PARAM_NAME("WNetAddConnection3A", 4, "lpUserName"); // LPCSTR
	ADD_PARAM_NAME("WNetAddConnection3A", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WNetAddConnection3W", 1, "hwndOwner"); // HWND
	ADD_PARAM_NAME("WNetAddConnection3W", 2, "lpNetResource"); // LPNETRESOURCEW
	ADD_PARAM_NAME("WNetAddConnection3W", 3, "lpPassword"); // LPCWSTR
	ADD_PARAM_NAME("WNetAddConnection3W", 4, "lpUserName"); // LPCWSTR
	ADD_PARAM_NAME("WNetAddConnection3W", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WNetAddConnectionA", 1, "lpRemoteName"); // LPCSTR
	ADD_PARAM_NAME("WNetAddConnectionA", 2, "lpPassword"); // LPCSTR
	ADD_PARAM_NAME("WNetAddConnectionA", 3, "lpLocalName"); // LPCSTR
	ADD_PARAM_NAME("WNetAddConnectionW", 1, "lpRemoteName"); // LPCWSTR
	ADD_PARAM_NAME("WNetAddConnectionW", 2, "lpPassword"); // LPCWSTR
	ADD_PARAM_NAME("WNetAddConnectionW", 3, "lpLocalName"); // LPCWSTR
	ADD_PARAM_NAME("WNetCancelConnection2A", 1, "lpName"); // LPCSTR
	ADD_PARAM_NAME("WNetCancelConnection2A", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WNetCancelConnection2A", 3, "fForce"); // WINBOOL
	ADD_PARAM_NAME("WNetCancelConnection2W", 1, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("WNetCancelConnection2W", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WNetCancelConnection2W", 3, "fForce"); // WINBOOL
	ADD_PARAM_NAME("WNetCancelConnectionA", 1, "lpName"); // LPCSTR
	ADD_PARAM_NAME("WNetCancelConnectionA", 2, "fForce"); // WINBOOL
	ADD_PARAM_NAME("WNetCancelConnectionW", 1, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("WNetCancelConnectionW", 2, "fForce"); // WINBOOL
	ADD_PARAM_NAME("WNetCloseEnum", 1, "hEnum"); // HANDLE
	ADD_PARAM_NAME("WNetConnectionDialog", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("WNetConnectionDialog", 2, "dwType"); // DWORD
	ADD_PARAM_NAME("WNetConnectionDialog1A", 1, "lpConnDlgStruct"); // LPCONNECTDLGSTRUCTA
	ADD_PARAM_NAME("WNetConnectionDialog1W", 1, "lpConnDlgStruct"); // LPCONNECTDLGSTRUCTW
	ADD_PARAM_NAME("WNetDisconnectDialog", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("WNetDisconnectDialog", 2, "dwType"); // DWORD
	ADD_PARAM_NAME("WNetDisconnectDialog1A", 1, "lpConnDlgStruct"); // LPDISCDLGSTRUCTA
	ADD_PARAM_NAME("WNetDisconnectDialog1W", 1, "lpConnDlgStruct"); // LPDISCDLGSTRUCTW
	ADD_PARAM_NAME("WNetEnumResourceA", 1, "hEnum"); // HANDLE
	ADD_PARAM_NAME("WNetEnumResourceA", 2, "lpcCount"); // LPDWORD
	ADD_PARAM_NAME("WNetEnumResourceA", 3, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WNetEnumResourceA", 4, "lpBufferSize"); // LPDWORD
	ADD_PARAM_NAME("WNetEnumResourceW", 1, "hEnum"); // HANDLE
	ADD_PARAM_NAME("WNetEnumResourceW", 2, "lpcCount"); // LPDWORD
	ADD_PARAM_NAME("WNetEnumResourceW", 3, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WNetEnumResourceW", 4, "lpBufferSize"); // LPDWORD
	ADD_PARAM_NAME("WNetGetConnectionA", 1, "lpLocalName"); // LPCSTR
	ADD_PARAM_NAME("WNetGetConnectionA", 2, "lpRemoteName"); // LPSTR
	ADD_PARAM_NAME("WNetGetConnectionA", 3, "lpnLength"); // LPDWORD
	ADD_PARAM_NAME("WNetGetConnectionW", 1, "lpLocalName"); // LPCWSTR
	ADD_PARAM_NAME("WNetGetConnectionW", 2, "lpRemoteName"); // LPWSTR
	ADD_PARAM_NAME("WNetGetConnectionW", 3, "lpnLength"); // LPDWORD
	ADD_PARAM_NAME("WNetGetLastErrorA", 1, "lpError"); // LPDWORD
	ADD_PARAM_NAME("WNetGetLastErrorA", 2, "lpErrorBuf"); // LPSTR
	ADD_PARAM_NAME("WNetGetLastErrorA", 3, "nErrorBufSize"); // DWORD
	ADD_PARAM_NAME("WNetGetLastErrorA", 4, "lpNameBuf"); // LPSTR
	ADD_PARAM_NAME("WNetGetLastErrorA", 5, "nNameBufSize"); // DWORD
	ADD_PARAM_NAME("WNetGetLastErrorW", 1, "lpError"); // LPDWORD
	ADD_PARAM_NAME("WNetGetLastErrorW", 2, "lpErrorBuf"); // LPWSTR
	ADD_PARAM_NAME("WNetGetLastErrorW", 3, "nErrorBufSize"); // DWORD
	ADD_PARAM_NAME("WNetGetLastErrorW", 4, "lpNameBuf"); // LPWSTR
	ADD_PARAM_NAME("WNetGetLastErrorW", 5, "nNameBufSize"); // DWORD
	ADD_PARAM_NAME("WNetGetNetworkInformationA", 1, "lpProvider"); // LPCSTR
	ADD_PARAM_NAME("WNetGetNetworkInformationA", 2, "lpNetInfoStruct"); // LPNETINFOSTRUCT
	ADD_PARAM_NAME("WNetGetNetworkInformationW", 1, "lpProvider"); // LPCWSTR
	ADD_PARAM_NAME("WNetGetNetworkInformationW", 2, "lpNetInfoStruct"); // LPNETINFOSTRUCT
	ADD_PARAM_NAME("WNetGetProviderNameA", 1, "dwNetType"); // DWORD
	ADD_PARAM_NAME("WNetGetProviderNameA", 2, "lpProviderName"); // LPSTR
	ADD_PARAM_NAME("WNetGetProviderNameA", 3, "lpBufferSize"); // LPDWORD
	ADD_PARAM_NAME("WNetGetProviderNameW", 1, "dwNetType"); // DWORD
	ADD_PARAM_NAME("WNetGetProviderNameW", 2, "lpProviderName"); // LPWSTR
	ADD_PARAM_NAME("WNetGetProviderNameW", 3, "lpBufferSize"); // LPDWORD
	ADD_PARAM_NAME("WNetGetResourceInformationA", 1, "lpNetResource"); // LPNETRESOURCEA
	ADD_PARAM_NAME("WNetGetResourceInformationA", 2, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WNetGetResourceInformationA", 3, "lpcbBuffer"); // LPDWORD
	ADD_PARAM_NAME("WNetGetResourceInformationA", 4, "lplpSystem"); // LPSTR *
	ADD_PARAM_NAME("WNetGetResourceInformationW", 1, "lpNetResource"); // LPNETRESOURCEW
	ADD_PARAM_NAME("WNetGetResourceInformationW", 2, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WNetGetResourceInformationW", 3, "lpcbBuffer"); // LPDWORD
	ADD_PARAM_NAME("WNetGetResourceInformationW", 4, "lplpSystem"); // LPWSTR *
	ADD_PARAM_NAME("WNetGetResourceParentA", 1, "lpNetResource"); // LPNETRESOURCEA
	ADD_PARAM_NAME("WNetGetResourceParentA", 2, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WNetGetResourceParentA", 3, "lpcbBuffer"); // LPDWORD
	ADD_PARAM_NAME("WNetGetResourceParentW", 1, "lpNetResource"); // LPNETRESOURCEW
	ADD_PARAM_NAME("WNetGetResourceParentW", 2, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WNetGetResourceParentW", 3, "lpcbBuffer"); // LPDWORD
	ADD_PARAM_NAME("WNetGetUniversalNameA", 1, "lpLocalPath"); // LPCSTR
	ADD_PARAM_NAME("WNetGetUniversalNameA", 2, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("WNetGetUniversalNameA", 3, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WNetGetUniversalNameA", 4, "lpBufferSize"); // LPDWORD
	ADD_PARAM_NAME("WNetGetUniversalNameW", 1, "lpLocalPath"); // LPCWSTR
	ADD_PARAM_NAME("WNetGetUniversalNameW", 2, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("WNetGetUniversalNameW", 3, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WNetGetUniversalNameW", 4, "lpBufferSize"); // LPDWORD
	ADD_PARAM_NAME("WNetGetUserA", 1, "lpName"); // LPCSTR
	ADD_PARAM_NAME("WNetGetUserA", 2, "lpUserName"); // LPSTR
	ADD_PARAM_NAME("WNetGetUserA", 3, "lpnLength"); // LPDWORD
	ADD_PARAM_NAME("WNetGetUserW", 1, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("WNetGetUserW", 2, "lpUserName"); // LPWSTR
	ADD_PARAM_NAME("WNetGetUserW", 3, "lpnLength"); // LPDWORD
	ADD_PARAM_NAME("WNetOpenEnumA", 1, "dwScope"); // DWORD
	ADD_PARAM_NAME("WNetOpenEnumA", 2, "dwType"); // DWORD
	ADD_PARAM_NAME("WNetOpenEnumA", 3, "dwUsage"); // DWORD
	ADD_PARAM_NAME("WNetOpenEnumA", 4, "lpNetResource"); // LPNETRESOURCEA
	ADD_PARAM_NAME("WNetOpenEnumA", 5, "lphEnum"); // LPHANDLE
	ADD_PARAM_NAME("WNetOpenEnumW", 1, "dwScope"); // DWORD
	ADD_PARAM_NAME("WNetOpenEnumW", 2, "dwType"); // DWORD
	ADD_PARAM_NAME("WNetOpenEnumW", 3, "dwUsage"); // DWORD
	ADD_PARAM_NAME("WNetOpenEnumW", 4, "lpNetResource"); // LPNETRESOURCEW
	ADD_PARAM_NAME("WNetOpenEnumW", 5, "lphEnum"); // LPHANDLE
	ADD_PARAM_NAME("WNetRestoreConnectionA", 1, "hwndParent"); // HWND
	ADD_PARAM_NAME("WNetRestoreConnectionA", 2, "lpDevice"); // LPCSTR
	ADD_PARAM_NAME("WNetRestoreConnectionW", 1, "hwndParent"); // HWND
	ADD_PARAM_NAME("WNetRestoreConnectionW", 2, "lpDevice"); // LPCWSTR
	ADD_PARAM_NAME("WNetUseConnectionA", 1, "hwndOwner"); // HWND
	ADD_PARAM_NAME("WNetUseConnectionA", 2, "lpNetResource"); // LPNETRESOURCEA
	ADD_PARAM_NAME("WNetUseConnectionA", 3, "lpPassword"); // LPCSTR
	ADD_PARAM_NAME("WNetUseConnectionA", 4, "lpUserID"); // LPCSTR
	ADD_PARAM_NAME("WNetUseConnectionA", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WNetUseConnectionA", 6, "lpAccessName"); // LPSTR
	ADD_PARAM_NAME("WNetUseConnectionA", 7, "lpBufferSize"); // LPDWORD
	ADD_PARAM_NAME("WNetUseConnectionA", 8, "lpResult"); // LPDWORD
	ADD_PARAM_NAME("WNetUseConnectionW", 1, "hwndOwner"); // HWND
	ADD_PARAM_NAME("WNetUseConnectionW", 2, "lpNetResource"); // LPNETRESOURCEW
	ADD_PARAM_NAME("WNetUseConnectionW", 3, "lpPassword"); // LPCWSTR
	ADD_PARAM_NAME("WNetUseConnectionW", 4, "lpUserID"); // LPCWSTR
	ADD_PARAM_NAME("WNetUseConnectionW", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WNetUseConnectionW", 6, "lpAccessName"); // LPWSTR
	ADD_PARAM_NAME("WNetUseConnectionW", 7, "lpBufferSize"); // LPDWORD
	ADD_PARAM_NAME("WNetUseConnectionW", 8, "lpResult"); // LPDWORD
	ADD_PARAM_NAME("WSARecvEx", 1, "s"); // SOCKET
	ADD_PARAM_NAME("WSARecvEx", 2, "buf"); // char *
	ADD_PARAM_NAME("WSARecvEx", 3, "len"); // int
	ADD_PARAM_NAME("WSARecvEx", 4, "flags"); // int *
	ADD_PARAM_NAME("WTHelperCertCheckValidSignature", 1, "pProvData"); // CRYPT_PROVIDER_DATA *
	ADD_PARAM_NAME("WTHelperCertIsSelfSigned", 1, "dwEncoding"); // DWORD
	ADD_PARAM_NAME("WTHelperCertIsSelfSigned", 2, "pCert"); // CERT_INFO *
	ADD_PARAM_NAME("WTHelperGetProvCertFromChain", 1, "pSgnr"); // CRYPT_PROVIDER_SGNR *
	ADD_PARAM_NAME("WTHelperGetProvCertFromChain", 2, "idxCert"); // DWORD
	ADD_PARAM_NAME("WTHelperGetProvPrivateDataFromChain", 1, "pProvData"); // CRYPT_PROVIDER_DATA *
	ADD_PARAM_NAME("WTHelperGetProvPrivateDataFromChain", 2, "pgProviderID"); // GUID *
	ADD_PARAM_NAME("WTHelperGetProvSignerFromChain", 1, "pProvData"); // CRYPT_PROVIDER_DATA *
	ADD_PARAM_NAME("WTHelperGetProvSignerFromChain", 2, "idxSigner"); // DWORD
	ADD_PARAM_NAME("WTHelperGetProvSignerFromChain", 3, "fCounterSigner"); // WINBOOL
	ADD_PARAM_NAME("WTHelperGetProvSignerFromChain", 4, "idxCounterSigner"); // DWORD
	ADD_PARAM_NAME("WTHelperProvDataFromStateData", 1, "hStateData"); // HANDLE
	ADD_PARAM_NAME("WaitCommEvent", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("WaitCommEvent", 2, "lpEvtMask"); // LPDWORD
	ADD_PARAM_NAME("WaitCommEvent", 3, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("WaitForDebugEvent", 1, "lpDebugEvent"); // LPDEBUG_EVENT
	ADD_PARAM_NAME("WaitForDebugEvent", 2, "dwMilliseconds"); // DWORD
	ADD_PARAM_NAME("WaitForInputIdle", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("WaitForInputIdle", 2, "dwMilliseconds"); // DWORD
	ADD_PARAM_NAME("WaitForMultipleObjects", 1, "nCount"); // DWORD
	ADD_PARAM_NAME("WaitForMultipleObjects", 2, "lpHandles"); // CONST HANDLE *
	ADD_PARAM_NAME("WaitForMultipleObjects", 3, "bWaitAll"); // WINBOOL
	ADD_PARAM_NAME("WaitForMultipleObjects", 4, "dwMilliseconds"); // DWORD
	ADD_PARAM_NAME("WaitForMultipleObjectsEx", 1, "nCount"); // DWORD
	ADD_PARAM_NAME("WaitForMultipleObjectsEx", 2, "lpHandles"); // CONST HANDLE *
	ADD_PARAM_NAME("WaitForMultipleObjectsEx", 3, "bWaitAll"); // WINBOOL
	ADD_PARAM_NAME("WaitForMultipleObjectsEx", 4, "dwMilliseconds"); // DWORD
	ADD_PARAM_NAME("WaitForMultipleObjectsEx", 5, "bAlertable"); // WINBOOL
	ADD_PARAM_NAME("WaitForPrinterChange", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("WaitForPrinterChange", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("WaitForSingleObject", 1, "hHandle"); // HANDLE
	ADD_PARAM_NAME("WaitForSingleObject", 2, "dwMilliseconds"); // DWORD
	ADD_PARAM_NAME("WaitForSingleObjectEx", 1, "hHandle"); // HANDLE
	ADD_PARAM_NAME("WaitForSingleObjectEx", 2, "dwMilliseconds"); // DWORD
	ADD_PARAM_NAME("WaitForSingleObjectEx", 3, "bAlertable"); // WINBOOL
	ADD_PARAM_NAME("WaitForThreadpoolIoCallbacks", 1, "pio"); // PTP_IO
	ADD_PARAM_NAME("WaitForThreadpoolIoCallbacks", 2, "fCancelPendingCallbacks"); // WINBOOL
	ADD_PARAM_NAME("WaitForThreadpoolTimerCallbacks", 1, "pti"); // PTP_TIMER
	ADD_PARAM_NAME("WaitForThreadpoolTimerCallbacks", 2, "fCancelPendingCallbacks"); // WINBOOL
	ADD_PARAM_NAME("WaitForThreadpoolWaitCallbacks", 1, "pwa"); // PTP_WAIT
	ADD_PARAM_NAME("WaitForThreadpoolWaitCallbacks", 2, "fCancelPendingCallbacks"); // WINBOOL
	ADD_PARAM_NAME("WaitForThreadpoolWorkCallbacks", 1, "pwk"); // PTP_WORK
	ADD_PARAM_NAME("WaitForThreadpoolWorkCallbacks", 2, "fCancelPendingCallbacks"); // WINBOOL
	ADD_PARAM_NAME("WaitNamedPipeA", 1, "lpNamedPipeName"); // LPCSTR
	ADD_PARAM_NAME("WaitNamedPipeA", 2, "nTimeOut"); // DWORD
	ADD_PARAM_NAME("WaitNamedPipeW", 1, "lpNamedPipeName"); // LPCWSTR
	ADD_PARAM_NAME("WaitNamedPipeW", 2, "nTimeOut"); // DWORD
	ADD_PARAM_NAME("WakeAllConditionVariable", 1, "ConditionVariable"); // PCONDITION_VARIABLE
	ADD_PARAM_NAME("WakeConditionVariable", 1, "ConditionVariable"); // PCONDITION_VARIABLE
	ADD_PARAM_NAME("WideCharToMultiByte", 1, "CodePage"); // UINT
	ADD_PARAM_NAME("WideCharToMultiByte", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WideCharToMultiByte", 3, "lpWideCharStr"); // LPCWSTR
	ADD_PARAM_NAME("WideCharToMultiByte", 4, "cchWideChar"); // int
	ADD_PARAM_NAME("WideCharToMultiByte", 5, "lpMultiByteStr"); // LPSTR
	ADD_PARAM_NAME("WideCharToMultiByte", 6, "cbMultiByte"); // int
	ADD_PARAM_NAME("WideCharToMultiByte", 7, "lpDefaultChar"); // LPCSTR
	ADD_PARAM_NAME("WideCharToMultiByte", 8, "lpUsedDefaultChar"); // LPBOOL
	ADD_PARAM_NAME("WidenPath", 1, "hdc"); // HDC
	ADD_PARAM_NAME("WinExec", 1, "lpCmdLine"); // LPCSTR
	ADD_PARAM_NAME("WinExec", 2, "uCmdShow"); // UINT
	ADD_PARAM_NAME("WinHelpA", 1, "hWndMain"); // HWND
	ADD_PARAM_NAME("WinHelpA", 2, "lpszHelp"); // LPCSTR
	ADD_PARAM_NAME("WinHelpA", 3, "uCommand"); // UINT
	ADD_PARAM_NAME("WinHelpA", 4, "dwData"); // ULONG_PTR
	ADD_PARAM_NAME("WinHelpW", 1, "hWndMain"); // HWND
	ADD_PARAM_NAME("WinHelpW", 2, "lpszHelp"); // LPCWSTR
	ADD_PARAM_NAME("WinHelpW", 3, "uCommand"); // UINT
	ADD_PARAM_NAME("WinHelpW", 4, "dwData"); // ULONG_PTR
	ADD_PARAM_NAME("WinHttpAddRequestHeaders", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpAddRequestHeaders", 2, "pwszHeaders"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpAddRequestHeaders", 3, "dwHeadersLength"); // DWORD
	ADD_PARAM_NAME("WinHttpAddRequestHeaders", 4, "dwModifiers"); // DWORD
	ADD_PARAM_NAME("WinHttpCloseHandle", 1, "hInternet"); // HINTERNET
	ADD_PARAM_NAME("WinHttpConnect", 1, "hSession"); // HINTERNET
	ADD_PARAM_NAME("WinHttpConnect", 2, "pswzServerName"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpConnect", 3, "nServerPort"); // INTERNET_PORT
	ADD_PARAM_NAME("WinHttpConnect", 4, "dwReserved"); // DWORD
	ADD_PARAM_NAME("WinHttpCrackUrl", 1, "pwszUrl"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpCrackUrl", 2, "dwUrlLength"); // DWORD
	ADD_PARAM_NAME("WinHttpCrackUrl", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WinHttpCrackUrl", 4, "lpUrlComponents"); // LPURL_COMPONENTS
	ADD_PARAM_NAME("WinHttpCreateUrl", 1, "lpUrlComponents"); // LPURL_COMPONENTS
	ADD_PARAM_NAME("WinHttpCreateUrl", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WinHttpCreateUrl", 3, "pwszUrl"); // LPWSTR
	ADD_PARAM_NAME("WinHttpCreateUrl", 4, "lpdwUrlLength"); // LPDWORD
	ADD_PARAM_NAME("WinHttpDetectAutoProxyConfigUrl", 1, "dwAutoDetectFlags"); // DWORD
	ADD_PARAM_NAME("WinHttpGetDefaultProxyConfiguration", 1, "pProxyInfo"); // WINHTTP_PROXY_INFO *
	ADD_PARAM_NAME("WinHttpGetIEProxyConfigForCurrentUser", 1, "pProxyConfig"); // WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *
	ADD_PARAM_NAME("WinHttpGetProxyForUrl", 1, "hSession"); // HINTERNET
	ADD_PARAM_NAME("WinHttpGetProxyForUrl", 2, "lpcwszUrl"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpGetProxyForUrl", 3, "pAutoProxyOptions"); // WINHTTP_AUTOPROXY_OPTIONS *
	ADD_PARAM_NAME("WinHttpGetProxyForUrl", 4, "pProxyInfo"); // WINHTTP_PROXY_INFO *
	ADD_PARAM_NAME("WinHttpOpen", 1, "pwszUserAgent"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpOpen", 2, "dwAccessType"); // DWORD
	ADD_PARAM_NAME("WinHttpOpen", 3, "pwszProxyName"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpOpen", 4, "pwszProxyBypass"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpOpen", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("WinHttpOpenRequest", 1, "hConnect"); // HINTERNET
	ADD_PARAM_NAME("WinHttpOpenRequest", 2, "pwszVerb"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpOpenRequest", 3, "pwszObjectName"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpOpenRequest", 4, "pwszVersion"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpOpenRequest", 5, "pwszReferrer"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpOpenRequest", 6, "ppwszAcceptTypes"); // LPCWSTR *
	ADD_PARAM_NAME("WinHttpOpenRequest", 7, "dwFlags"); // DWORD
	// ADD_PARAM_NAME("WinHttpQueryAuthParams", 1, "?"); // ?
	ADD_PARAM_NAME("WinHttpQueryAuthSchemes", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpQueryAuthSchemes", 2, "lpdwSupportedSchemes"); // LPDWORD
	ADD_PARAM_NAME("WinHttpQueryAuthSchemes", 3, "lpdwFirstScheme"); // LPDWORD
	ADD_PARAM_NAME("WinHttpQueryAuthSchemes", 4, "pdwAuthTarget"); // LPDWORD
	ADD_PARAM_NAME("WinHttpQueryDataAvailable", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpQueryDataAvailable", 2, "lpdwNumberOfBytesAvailable"); // LPDWORD
	ADD_PARAM_NAME("WinHttpQueryHeaders", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpQueryHeaders", 2, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("WinHttpQueryHeaders", 3, "pwszName"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpQueryHeaders", 4, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WinHttpQueryHeaders", 5, "lpdwBufferLength"); // LPDWORD
	ADD_PARAM_NAME("WinHttpQueryHeaders", 6, "lpdwIndex"); // LPDWORD
	ADD_PARAM_NAME("WinHttpQueryOption", 1, "hInternet"); // HINTERNET
	ADD_PARAM_NAME("WinHttpQueryOption", 2, "dwOption"); // DWORD
	ADD_PARAM_NAME("WinHttpQueryOption", 3, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WinHttpQueryOption", 4, "lpdwBufferLength"); // LPDWORD
	ADD_PARAM_NAME("WinHttpReadData", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpReadData", 2, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WinHttpReadData", 3, "dwNumberOfBytesToRead"); // DWORD
	ADD_PARAM_NAME("WinHttpReadData", 4, "lpdwNumberOfBytesRead"); // LPDWORD
	ADD_PARAM_NAME("WinHttpReceiveResponse", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpReceiveResponse", 2, "lpReserved"); // LPVOID
	ADD_PARAM_NAME("WinHttpSendRequest", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpSendRequest", 2, "pwszHeaders"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpSendRequest", 3, "dwHeadersLength"); // DWORD
	ADD_PARAM_NAME("WinHttpSendRequest", 4, "lpOptional"); // LPVOID
	ADD_PARAM_NAME("WinHttpSendRequest", 5, "dwOptionalLength"); // DWORD
	ADD_PARAM_NAME("WinHttpSendRequest", 6, "dwTotalLength"); // DWORD
	ADD_PARAM_NAME("WinHttpSendRequest", 7, "dwContext"); // DWORD_PTR
	ADD_PARAM_NAME("WinHttpSetCredentials", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpSetCredentials", 2, "AuthTargets"); // DWORD
	ADD_PARAM_NAME("WinHttpSetCredentials", 3, "AuthScheme"); // DWORD
	ADD_PARAM_NAME("WinHttpSetCredentials", 4, "pwszUserName"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpSetCredentials", 5, "pwszPassword"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpSetCredentials", 6, "pAuthParams"); // LPVOID
	ADD_PARAM_NAME("WinHttpSetDefaultProxyConfiguration", 1, "pProxyInfo"); // WINHTTP_PROXY_INFO *
	ADD_PARAM_NAME("WinHttpSetOption", 1, "hInternet"); // HINTERNET
	ADD_PARAM_NAME("WinHttpSetOption", 2, "dwOption"); // DWORD
	ADD_PARAM_NAME("WinHttpSetOption", 3, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("WinHttpSetOption", 4, "dwBufferLength"); // DWORD
	ADD_PARAM_NAME("WinHttpSetStatusCallback", 1, "hInternet"); // HINTERNET
	ADD_PARAM_NAME("WinHttpSetStatusCallback", 2, "lpfnInternetCallback"); // WINHTTP_STATUS_CALLBACK
	ADD_PARAM_NAME("WinHttpSetStatusCallback", 3, "dwNotificationFlags"); // DWORD
	ADD_PARAM_NAME("WinHttpSetStatusCallback", 4, "dwReserved"); // DWORD_PTR
	ADD_PARAM_NAME("WinHttpSetTimeouts", 1, "hInternet"); // HINTERNET
	ADD_PARAM_NAME("WinHttpSetTimeouts", 2, "dwResolveTimeout"); // int
	ADD_PARAM_NAME("WinHttpSetTimeouts", 3, "dwConnectTimeout"); // int
	ADD_PARAM_NAME("WinHttpSetTimeouts", 4, "dwSendTimeout"); // int
	ADD_PARAM_NAME("WinHttpSetTimeouts", 5, "dwReceiveTimeout"); // int
	ADD_PARAM_NAME("WinHttpTimeFromSystemTime", 1, "LPWSTR"); // CONST SYSTEMTIME *
	ADD_PARAM_NAME("WinHttpTimeToSystemTime", 1, "pwszTime"); // LPCWSTR
	ADD_PARAM_NAME("WinHttpTimeToSystemTime", 2, "pst"); // SYSTEMTIME *
	ADD_PARAM_NAME("WinHttpWriteData", 1, "hRequest"); // HINTERNET
	ADD_PARAM_NAME("WinHttpWriteData", 2, "lpBuffer"); // LPCVOID
	ADD_PARAM_NAME("WinHttpWriteData", 3, "dwNumberOfBytesToWrite"); // DWORD
	ADD_PARAM_NAME("WinHttpWriteData", 4, "lpdwNumberOfBytesWritten"); // LPDWORD
	ADD_PARAM_NAME("WinMain", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("WinMain", 2, "hPrevInstance"); // HINSTANCE
	ADD_PARAM_NAME("WinMain", 3, "lpCmdLine"); // LPSTR
	ADD_PARAM_NAME("WinMain", 4, "nShowCmd"); // int
	ADD_PARAM_NAME("WinUsb_AbortPipe", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_AbortPipe", 2, "PipeID"); // UCHAR
	ADD_PARAM_NAME("WinUsb_ControlTransfer", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_ControlTransfer", 2, "SetupPacket"); // WINUSB_SETUP_PACKET
	ADD_PARAM_NAME("WinUsb_ControlTransfer", 3, "Buffer"); // PUCHAR
	ADD_PARAM_NAME("WinUsb_ControlTransfer", 4, "BufferLength"); // ULONG
	ADD_PARAM_NAME("WinUsb_ControlTransfer", 5, "LengthTransferred"); // PULONG
	ADD_PARAM_NAME("WinUsb_ControlTransfer", 6, "Overlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("WinUsb_FlushPipe", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_FlushPipe", 2, "PipeID"); // UCHAR
	ADD_PARAM_NAME("WinUsb_Free", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_GetAssociatedInterface", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_GetAssociatedInterface", 2, "AssociatedInterfaceIndex"); // UCHAR
	ADD_PARAM_NAME("WinUsb_GetAssociatedInterface", 3, "AssociatedInterfaceHandle"); // PWINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_GetCurrentAlternateSetting", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_GetCurrentAlternateSetting", 2, "AlternateSetting"); // PUCHAR
	ADD_PARAM_NAME("WinUsb_GetDescriptor", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_GetDescriptor", 2, "DescriptorType"); // UCHAR
	ADD_PARAM_NAME("WinUsb_GetDescriptor", 3, "Index"); // UCHAR
	ADD_PARAM_NAME("WinUsb_GetDescriptor", 4, "LanguageID"); // USHORT
	ADD_PARAM_NAME("WinUsb_GetDescriptor", 5, "Buffer"); // PUCHAR
	ADD_PARAM_NAME("WinUsb_GetDescriptor", 6, "BufferLength"); // ULONG
	ADD_PARAM_NAME("WinUsb_GetDescriptor", 7, "LengthTransferred"); // PULONG
	ADD_PARAM_NAME("WinUsb_GetOverlappedResult", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_GetOverlappedResult", 2, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("WinUsb_GetOverlappedResult", 3, "lpNumberOfBytesTransferred"); // LPDWORD
	ADD_PARAM_NAME("WinUsb_GetOverlappedResult", 4, "bWait"); // WINBOOL
	ADD_PARAM_NAME("WinUsb_GetPipePolicy", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_GetPipePolicy", 2, "PipeID"); // UCHAR
	ADD_PARAM_NAME("WinUsb_GetPipePolicy", 3, "PolicyType"); // ULONG
	ADD_PARAM_NAME("WinUsb_GetPipePolicy", 4, "ValueLength"); // PULONG
	ADD_PARAM_NAME("WinUsb_GetPipePolicy", 5, "Value"); // PVOID
	ADD_PARAM_NAME("WinUsb_GetPowerPolicy", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_GetPowerPolicy", 2, "PolicyType"); // ULONG
	ADD_PARAM_NAME("WinUsb_GetPowerPolicy", 3, "ValueLength"); // PULONG
	ADD_PARAM_NAME("WinUsb_GetPowerPolicy", 4, "Value"); // PVOID
	ADD_PARAM_NAME("WinUsb_Initialize", 1, "DeviceHandle"); // HANDLE
	ADD_PARAM_NAME("WinUsb_Initialize", 2, "InterfaceHandle"); // PWINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_QueryDeviceInformation", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_QueryDeviceInformation", 2, "InformationType"); // ULONG
	ADD_PARAM_NAME("WinUsb_QueryDeviceInformation", 3, "BufferLength"); // PULONG
	ADD_PARAM_NAME("WinUsb_QueryDeviceInformation", 4, "Buffer"); // PVOID
	ADD_PARAM_NAME("WinUsb_QueryInterfaceSettings", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_QueryInterfaceSettings", 2, "AlternateSettingNumber"); // UCHAR
	ADD_PARAM_NAME("WinUsb_QueryInterfaceSettings", 3, "UsbAltInterfaceDescriptor"); // PUSB_INTERFACE_DESCRIPTOR
	ADD_PARAM_NAME("WinUsb_QueryPipe", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_QueryPipe", 2, "AlternateInterfaceNumber"); // UCHAR
	ADD_PARAM_NAME("WinUsb_QueryPipe", 3, "PipeIndex"); // UCHAR
	ADD_PARAM_NAME("WinUsb_QueryPipe", 4, "PipeInformation"); // PWINUSB_PIPE_INFORMATION
	ADD_PARAM_NAME("WinUsb_ReadPipe", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_ReadPipe", 2, "PipeID"); // UCHAR
	ADD_PARAM_NAME("WinUsb_ReadPipe", 3, "Buffer"); // PUCHAR
	ADD_PARAM_NAME("WinUsb_ReadPipe", 4, "BufferLength"); // ULONG
	ADD_PARAM_NAME("WinUsb_ReadPipe", 5, "LengthTransferred"); // PULONG
	ADD_PARAM_NAME("WinUsb_ReadPipe", 6, "Overlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("WinUsb_ResetPipe", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_ResetPipe", 2, "PipeID"); // UCHAR
	ADD_PARAM_NAME("WinUsb_SetCurrentAlternateInterface", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_SetCurrentAlternateInterface", 2, "AlternateSetting"); // UCHAR
	ADD_PARAM_NAME("WinUsb_SetPipePolicy", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_SetPipePolicy", 2, "PipeID"); // UCHAR
	ADD_PARAM_NAME("WinUsb_SetPipePolicy", 3, "PolicyType"); // ULONG
	ADD_PARAM_NAME("WinUsb_SetPipePolicy", 4, "ValueLength"); // ULONG
	ADD_PARAM_NAME("WinUsb_SetPipePolicy", 5, "Value"); // PVOID
	ADD_PARAM_NAME("WinUsb_SetPowerPolicy", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_SetPowerPolicy", 2, "PolicyType"); // ULONG
	ADD_PARAM_NAME("WinUsb_SetPowerPolicy", 3, "ValueLength"); // ULONG
	ADD_PARAM_NAME("WinUsb_SetPowerPolicy", 4, "Value"); // PVOID
	ADD_PARAM_NAME("WinUsb_WritePipe", 1, "InterfaceHandle"); // WINUSB_INTERFACE_HANDLE
	ADD_PARAM_NAME("WinUsb_WritePipe", 2, "PipeID"); // UCHAR
	ADD_PARAM_NAME("WinUsb_WritePipe", 3, "Buffer"); // PUCHAR
	ADD_PARAM_NAME("WinUsb_WritePipe", 4, "BufferLength"); // ULONG
	ADD_PARAM_NAME("WinUsb_WritePipe", 5, "LengthTransferred"); // PULONG
	ADD_PARAM_NAME("WinUsb_WritePipe", 6, "Overlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("WinVerifyTrust", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("WinVerifyTrust", 2, "pgActionID"); // GUID *
	ADD_PARAM_NAME("WinVerifyTrust", 3, "pWVTData"); // LPVOID
	ADD_PARAM_NAME("WinVerifyTrustEx", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("WinVerifyTrustEx", 2, "pgActionID"); // GUID *
	ADD_PARAM_NAME("WinVerifyTrustEx", 3, "pWinTrustData"); // WINTRUST_DATA *
	ADD_PARAM_NAME("WindowFromDC", 1, "hDC"); // HDC
	ADD_PARAM_NAME("WindowFromPoint", 1, "Point"); // POINT
	ADD_PARAM_NAME("WintrustAddActionID", 1, "pgActionID"); // GUID *
	ADD_PARAM_NAME("WintrustAddActionID", 2, "fdwFlags"); // DWORD
	ADD_PARAM_NAME("WintrustAddActionID", 3, "psProvInfo"); // CRYPT_REGISTER_ACTIONID *
	ADD_PARAM_NAME("WintrustAddDefaultForUsage", 1, "pszUsageOID"); // const char *
	ADD_PARAM_NAME("WintrustAddDefaultForUsage", 2, "psDefUsage"); // CRYPT_PROVIDER_REGDEFUSAGE *
	ADD_PARAM_NAME("WintrustGetDefaultForUsage", 1, "dwAction"); // DWORD
	ADD_PARAM_NAME("WintrustGetDefaultForUsage", 2, "pszUsageOID"); // const char *
	ADD_PARAM_NAME("WintrustGetDefaultForUsage", 3, "psUsage"); // CRYPT_PROVIDER_DEFUSAGE *
	ADD_PARAM_NAME("WintrustGetRegPolicyFlags", 1, "pdwPolicyFlags"); // DWORD *
	ADD_PARAM_NAME("WintrustLoadFunctionPointers", 1, "pgActionID"); // GUID *
	ADD_PARAM_NAME("WintrustLoadFunctionPointers", 2, "pPfns"); // CRYPT_PROVIDER_FUNCTIONS *
	ADD_PARAM_NAME("WintrustRemoveActionID", 1, "pgActionID"); // GUID *
	ADD_PARAM_NAME("WintrustSetDefaultIncludePEPageHashes", 1, "fIncludePEPageHashes"); // WINBOOL
	ADD_PARAM_NAME("WintrustSetRegPolicyFlags", 1, "dwPolicyFlags"); // DWORD
	ADD_PARAM_NAME("WlxActivateUserShell", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxActivateUserShell", 2, "pszDesktopName"); // PWSTR
	ADD_PARAM_NAME("WlxActivateUserShell", 3, "pszMprLogonScript"); // PWSTR
	ADD_PARAM_NAME("WlxActivateUserShell", 4, "pEnvironment"); // PVOID
	ADD_PARAM_NAME("WlxDisconnectNotify", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxDisplayLockedNotice", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxDisplaySASNotice", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxDisplayStatusMessage", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxDisplayStatusMessage", 2, "hDesktop"); // HDESK
	ADD_PARAM_NAME("WlxDisplayStatusMessage", 3, "dwOptions"); // DWORD
	ADD_PARAM_NAME("WlxDisplayStatusMessage", 4, "pTitle"); // PWSTR
	ADD_PARAM_NAME("WlxDisplayStatusMessage", 5, "pMessage"); // PWSTR
	ADD_PARAM_NAME("WlxGetConsoleSwitchCredentials", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxGetConsoleSwitchCredentials", 2, "pCredInfo"); // PVOID
	ADD_PARAM_NAME("WlxGetStatusMessage", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxGetStatusMessage", 2, "pdwOptions"); // DWORD *
	ADD_PARAM_NAME("WlxGetStatusMessage", 3, "pMessage"); // PWSTR
	ADD_PARAM_NAME("WlxGetStatusMessage", 4, "dwBufferSize"); // DWORD
	ADD_PARAM_NAME("WlxInitialize", 1, "lpWinsta"); // LPWSTR
	ADD_PARAM_NAME("WlxInitialize", 2, "hWlx"); // HANDLE
	ADD_PARAM_NAME("WlxInitialize", 3, "pvReserved"); // PVOID
	ADD_PARAM_NAME("WlxInitialize", 4, "pWinlogonFunctions"); // PVOID
	ADD_PARAM_NAME("WlxInitialize", 5, "pWlxContext"); // PVOID *
	ADD_PARAM_NAME("WlxIsLockOk", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxIsLogoffOk", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxLoggedOnSAS", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxLoggedOnSAS", 2, "dwSasType"); // DWORD
	ADD_PARAM_NAME("WlxLoggedOnSAS", 3, "pReserved"); // PVOID
	ADD_PARAM_NAME("WlxLoggedOutSAS", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxLoggedOutSAS", 2, "dwSasType"); // DWORD
	ADD_PARAM_NAME("WlxLoggedOutSAS", 3, "pAuthenticationId"); // PLUID
	ADD_PARAM_NAME("WlxLoggedOutSAS", 4, "pLogonSid"); // PSID
	ADD_PARAM_NAME("WlxLoggedOutSAS", 5, "pdwOptions"); // PDWORD
	ADD_PARAM_NAME("WlxLoggedOutSAS", 6, "phToken"); // PHANDLE
	ADD_PARAM_NAME("WlxLoggedOutSAS", 7, "pNprNotifyInfo"); // PWLX_MPR_NOTIFY_INFO
	ADD_PARAM_NAME("WlxLoggedOutSAS", 8, "pProfile"); // PVOID *
	ADD_PARAM_NAME("WlxLogoff", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxNegotiate", 1, "dwWinlogonVersion"); // DWORD
	ADD_PARAM_NAME("WlxNegotiate", 2, "pdwDllVersion"); // PDWORD
	ADD_PARAM_NAME("WlxNetworkProviderLoad", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxNetworkProviderLoad", 2, "pNprNotifyInfo"); // PWLX_MPR_NOTIFY_INFO
	ADD_PARAM_NAME("WlxReconnectNotify", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxRemoveStatusMessage", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxScreenSaverNotify", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxScreenSaverNotify", 2, "pSecure"); // WINBOOL *
	ADD_PARAM_NAME("WlxShutdown", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxShutdown", 2, "ShutdownType"); // DWORD
	ADD_PARAM_NAME("WlxStartApplication", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxStartApplication", 2, "pszDesktopName"); // PWSTR
	ADD_PARAM_NAME("WlxStartApplication", 3, "pEnvironment"); // PVOID
	ADD_PARAM_NAME("WlxStartApplication", 4, "pszCmdLine"); // PWSTR
	ADD_PARAM_NAME("WlxWkstaLockedSAS", 1, "pWlxContext"); // PVOID
	ADD_PARAM_NAME("WlxWkstaLockedSAS", 2, "dwSasType"); // DWORD
	ADD_PARAM_NAME("Wow64DisableWow64FsRedirection", 1, "OldValue"); // PVOID *
	ADD_PARAM_NAME("Wow64EnableWow64FsRedirection", 1, "Wow64FsEnableRedirection"); // BOOLEAN
	ADD_PARAM_NAME("Wow64GetThreadContext", 1, "hThread"); // HANDLE
	ADD_PARAM_NAME("Wow64GetThreadContext", 2, "lpContext"); // PWOW64_CONTEXT
	ADD_PARAM_NAME("Wow64RevertWow64FsRedirection", 1, "OlValue"); // PVOID
	ADD_PARAM_NAME("Wow64SetThreadContext", 1, "hThread"); // HANDLE
	ADD_PARAM_NAME("Wow64SetThreadContext", 2, "lpContext"); // const WOW64_CONTEXT *
	ADD_PARAM_NAME("Wow64SuspendThread", 1, "hThread"); // HANDLE
	ADD_PARAM_NAME("Wow64Win32ApiEntry", 1, "dwFuncNumber"); // DWORD
	ADD_PARAM_NAME("Wow64Win32ApiEntry", 2, "dwFlag"); // DWORD
	ADD_PARAM_NAME("Wow64Win32ApiEntry", 3, "dwRes"); // DWORD
	ADD_PARAM_NAME("WriteConsoleA", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleA", 2, "lpBuffer"); // CONST VOID *
	ADD_PARAM_NAME("WriteConsoleA", 3, "nNumberOfCharsToWrite"); // DWORD
	ADD_PARAM_NAME("WriteConsoleA", 4, "lpNumberOfCharsWritten"); // LPDWORD
	ADD_PARAM_NAME("WriteConsoleA", 5, "lpReserved"); // LPVOID
	ADD_PARAM_NAME("WriteConsoleInputA", 1, "hConsoleInput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleInputA", 2, "lpBuffer"); // CONST INPUT_RECORD *
	ADD_PARAM_NAME("WriteConsoleInputA", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("WriteConsoleInputA", 4, "lpNumberOfEventsWritten"); // LPDWORD
	ADD_PARAM_NAME("WriteConsoleInputW", 1, "hConsoleInput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleInputW", 2, "lpBuffer"); // CONST INPUT_RECORD *
	ADD_PARAM_NAME("WriteConsoleInputW", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("WriteConsoleInputW", 4, "lpNumberOfEventsWritten"); // LPDWORD
	ADD_PARAM_NAME("WriteConsoleOutputA", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleOutputA", 2, "lpBuffer"); // CONST CHAR_INFO *
	ADD_PARAM_NAME("WriteConsoleOutputA", 3, "dwBufferSize"); // COORD
	ADD_PARAM_NAME("WriteConsoleOutputA", 4, "dwBufferCoord"); // COORD
	ADD_PARAM_NAME("WriteConsoleOutputA", 5, "lpWriteRegion"); // PSMALL_RECT
	ADD_PARAM_NAME("WriteConsoleOutputAttribute", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleOutputAttribute", 2, "lpAttribute"); // CONST WORD *
	ADD_PARAM_NAME("WriteConsoleOutputAttribute", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("WriteConsoleOutputAttribute", 4, "dwWriteCoord"); // COORD
	ADD_PARAM_NAME("WriteConsoleOutputAttribute", 5, "lpNumberOfAttrsWritten"); // LPDWORD
	ADD_PARAM_NAME("WriteConsoleOutputCharacterA", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleOutputCharacterA", 2, "lpCharacter"); // LPCSTR
	ADD_PARAM_NAME("WriteConsoleOutputCharacterA", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("WriteConsoleOutputCharacterA", 4, "dwWriteCoord"); // COORD
	ADD_PARAM_NAME("WriteConsoleOutputCharacterA", 5, "lpNumberOfCharsWritten"); // LPDWORD
	ADD_PARAM_NAME("WriteConsoleOutputCharacterW", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleOutputCharacterW", 2, "lpCharacter"); // LPCWSTR
	ADD_PARAM_NAME("WriteConsoleOutputCharacterW", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("WriteConsoleOutputCharacterW", 4, "dwWriteCoord"); // COORD
	ADD_PARAM_NAME("WriteConsoleOutputCharacterW", 5, "lpNumberOfCharsWritten"); // LPDWORD
	ADD_PARAM_NAME("WriteConsoleOutputW", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleOutputW", 2, "lpBuffer"); // CONST CHAR_INFO *
	ADD_PARAM_NAME("WriteConsoleOutputW", 3, "dwBufferSize"); // COORD
	ADD_PARAM_NAME("WriteConsoleOutputW", 4, "dwBufferCoord"); // COORD
	ADD_PARAM_NAME("WriteConsoleOutputW", 5, "lpWriteRegion"); // PSMALL_RECT
	ADD_PARAM_NAME("WriteConsoleW", 1, "hConsoleOutput"); // HANDLE
	ADD_PARAM_NAME("WriteConsoleW", 2, "lpBuffer"); // CONST VOID *
	ADD_PARAM_NAME("WriteConsoleW", 3, "nNumberOfCharsToWrite"); // DWORD
	ADD_PARAM_NAME("WriteConsoleW", 4, "lpNumberOfCharsWritten"); // LPDWORD
	ADD_PARAM_NAME("WriteConsoleW", 5, "lpReserved"); // LPVOID
	ADD_PARAM_NAME("WriteEncryptedFileRaw", 1, "pfImportCallback"); // PFE_IMPORT_FUNC
	ADD_PARAM_NAME("WriteEncryptedFileRaw", 2, "pvCallbackContext"); // PVOID
	ADD_PARAM_NAME("WriteEncryptedFileRaw", 3, "pvContext"); // PVOID
	ADD_PARAM_NAME("WriteFile", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("WriteFile", 2, "lpBuffer"); // LPCVOID
	ADD_PARAM_NAME("WriteFile", 3, "nNumberOfBytesToWrite"); // DWORD
	ADD_PARAM_NAME("WriteFile", 4, "lpNumberOfBytesWritten"); // LPDWORD
	ADD_PARAM_NAME("WriteFile", 5, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("WriteFileEx", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("WriteFileEx", 2, "lpBuffer"); // LPCVOID
	ADD_PARAM_NAME("WriteFileEx", 3, "nNumberOfBytesToWrite"); // DWORD
	ADD_PARAM_NAME("WriteFileEx", 4, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("WriteFileEx", 5, "lpCompletionRoutine"); // LPOVERLAPPED_COMPLETION_ROUTINE
	ADD_PARAM_NAME("WriteFileGather", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("WriteFileGather", 2, "aSegmentArray"); // FILE_SEGMENT_ELEMENT []
	ADD_PARAM_NAME("WriteFileGather", 3, "nNumberOfBytesToWrite"); // DWORD
	ADD_PARAM_NAME("WriteFileGather", 4, "lpReserved"); // LPDWORD
	ADD_PARAM_NAME("WriteFileGather", 5, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("WritePrinter", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("WritePrinter", 2, "pBuf"); // LPVOID
	ADD_PARAM_NAME("WritePrinter", 3, "cbBuf"); // DWORD
	ADD_PARAM_NAME("WritePrinter", 4, "pcWritten"); // LPDWORD
	ADD_PARAM_NAME("WritePrivateProfileSectionA", 1, "lpAppName"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileSectionA", 2, "lpString"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileSectionA", 3, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileSectionW", 1, "lpAppName"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileSectionW", 2, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileSectionW", 3, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileStringA", 1, "lpAppName"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileStringA", 2, "lpKeyName"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileStringA", 3, "lpString"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileStringA", 4, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileStringW", 1, "lpAppName"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileStringW", 2, "lpKeyName"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileStringW", 3, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileStringW", 4, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileStructA", 1, "lpszSection"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileStructA", 2, "lpszKey"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileStructA", 3, "lpStruct"); // LPVOID
	ADD_PARAM_NAME("WritePrivateProfileStructA", 4, "uSizeStruct"); // UINT
	ADD_PARAM_NAME("WritePrivateProfileStructA", 5, "szFile"); // LPCSTR
	ADD_PARAM_NAME("WritePrivateProfileStructW", 1, "lpszSection"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileStructW", 2, "lpszKey"); // LPCWSTR
	ADD_PARAM_NAME("WritePrivateProfileStructW", 3, "lpStruct"); // LPVOID
	ADD_PARAM_NAME("WritePrivateProfileStructW", 4, "uSizeStruct"); // UINT
	ADD_PARAM_NAME("WritePrivateProfileStructW", 5, "szFile"); // LPCWSTR
	ADD_PARAM_NAME("WriteProcessMemory", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("WriteProcessMemory", 2, "lpBaseAddress"); // LPVOID
	ADD_PARAM_NAME("WriteProcessMemory", 3, "lpBuffer"); // LPCVOID
	ADD_PARAM_NAME("WriteProcessMemory", 4, "nSize"); // SIZE_T
	ADD_PARAM_NAME("WriteProcessMemory", 5, "lpNumberOfBytesWritten"); // SIZE_T *
	ADD_PARAM_NAME("WriteProfileSectionA", 1, "lpAppName"); // LPCSTR
	ADD_PARAM_NAME("WriteProfileSectionA", 2, "lpString"); // LPCSTR
	ADD_PARAM_NAME("WriteProfileSectionW", 1, "lpAppName"); // LPCWSTR
	ADD_PARAM_NAME("WriteProfileSectionW", 2, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("WriteProfileStringA", 1, "lpAppName"); // LPCSTR
	ADD_PARAM_NAME("WriteProfileStringA", 2, "lpKeyName"); // LPCSTR
	ADD_PARAM_NAME("WriteProfileStringA", 3, "lpString"); // LPCSTR
	ADD_PARAM_NAME("WriteProfileStringW", 1, "lpAppName"); // LPCWSTR
	ADD_PARAM_NAME("WriteProfileStringW", 2, "lpKeyName"); // LPCWSTR
	ADD_PARAM_NAME("WriteProfileStringW", 3, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("WriteTapemark", 1, "hDevice"); // HANDLE
	ADD_PARAM_NAME("WriteTapemark", 2, "dwTapemarkType"); // DWORD
	ADD_PARAM_NAME("WriteTapemark", 3, "dwTapemarkCount"); // DWORD
	ADD_PARAM_NAME("WriteTapemark", 4, "bImmediate"); // WINBOOL

	ADD_PARAM_NAME("wWinMain", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("wWinMain", 2, "hPrevInstance"); // HINSTANCE
	ADD_PARAM_NAME("wWinMain", 3, "lpCmdLine"); // LPWSTR
	ADD_PARAM_NAME("wWinMain", 4, "nShowCmd"); // int
	ADD_PARAM_NAME("wglCopyContext", 1, "hglrc"); // HGLRC
	ADD_PARAM_NAME("wglCopyContext", 2, "hglrc"); // HGLRC
	ADD_PARAM_NAME("wglCopyContext", 3, "mask"); // UINT
	ADD_PARAM_NAME("wglCreateContext", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglCreateLayerContext", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglCreateLayerContext", 2, "iLayerPlane"); // int
	ADD_PARAM_NAME("wglDeleteContext", 1, "hglrc"); // HGLRC
	ADD_PARAM_NAME("wglDescribeLayerPlane", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglDescribeLayerPlane", 2, "iPixelFormat"); // int
	ADD_PARAM_NAME("wglDescribeLayerPlane", 3, "iLayerPlane"); // int
	ADD_PARAM_NAME("wglDescribeLayerPlane", 4, "nBytes"); // UINT
	ADD_PARAM_NAME("wglDescribeLayerPlane", 5, "plpd"); // LPLAYERPLANEDESCRIPTOR
	ADD_PARAM_NAME("wglGetLayerPaletteEntries", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglGetLayerPaletteEntries", 2, "iLayerPlane"); // int
	ADD_PARAM_NAME("wglGetLayerPaletteEntries", 3, "iStart"); // int
	ADD_PARAM_NAME("wglGetLayerPaletteEntries", 4, "cEntries"); // int
	ADD_PARAM_NAME("wglGetLayerPaletteEntries", 5, "pcr"); // COLORREF *
	ADD_PARAM_NAME("wglGetProcAddress", 1, "lpszProc"); // LPCSTR
	ADD_PARAM_NAME("wglMakeCurrent", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglMakeCurrent", 2, "hglrc"); // HGLRC
	ADD_PARAM_NAME("wglRealizeLayerPalette", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglRealizeLayerPalette", 2, "iLayerPlane"); // int
	ADD_PARAM_NAME("wglRealizeLayerPalette", 3, "bRealize"); // WINBOOL
	ADD_PARAM_NAME("wglSetLayerPaletteEntries", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglSetLayerPaletteEntries", 2, "iLayerPlane"); // int
	ADD_PARAM_NAME("wglSetLayerPaletteEntries", 3, "iStart"); // int
	ADD_PARAM_NAME("wglSetLayerPaletteEntries", 4, "cEntries"); // int
	ADD_PARAM_NAME("wglSetLayerPaletteEntries", 5, "pcr"); // const COLORREF *
	ADD_PARAM_NAME("wglShareLists", 1, "hglrc"); // HGLRC
	ADD_PARAM_NAME("wglShareLists", 2, "hglrc"); // HGLRC
	ADD_PARAM_NAME("wglSwapLayerBuffers", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglSwapLayerBuffers", 2, "fuPlanes"); // UINT
	// ADD_PARAM_NAME("wglSwapMultipleBuffers", 1, "?"); // ?
	ADD_PARAM_NAME("wglUseFontBitmapsA", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglUseFontBitmapsA", 2, "first"); // DWORD
	ADD_PARAM_NAME("wglUseFontBitmapsA", 3, "count"); // DWORD
	ADD_PARAM_NAME("wglUseFontBitmapsA", 4, "listBase"); // DWORD
	ADD_PARAM_NAME("wglUseFontBitmapsW", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglUseFontBitmapsW", 2, "first"); // DWORD
	ADD_PARAM_NAME("wglUseFontBitmapsW", 3, "count"); // DWORD
	ADD_PARAM_NAME("wglUseFontBitmapsW", 4, "listBase"); // DWORD
	ADD_PARAM_NAME("wglUseFontOutlinesA", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglUseFontOutlinesA", 2, "first"); // DWORD
	ADD_PARAM_NAME("wglUseFontOutlinesA", 3, "count"); // DWORD
	ADD_PARAM_NAME("wglUseFontOutlinesA", 4, "listBase"); // DWORD
	ADD_PARAM_NAME("wglUseFontOutlinesA", 5, "deviation"); // FLOAT
	ADD_PARAM_NAME("wglUseFontOutlinesA", 6, "extrusion"); // FLOAT
	ADD_PARAM_NAME("wglUseFontOutlinesA", 7, "format"); // int
	ADD_PARAM_NAME("wglUseFontOutlinesA", 8, "lpgmf"); // LPGLYPHMETRICSFLOAT
	ADD_PARAM_NAME("wglUseFontOutlinesW", 1, "hdc"); // HDC
	ADD_PARAM_NAME("wglUseFontOutlinesW", 2, "first"); // DWORD
	ADD_PARAM_NAME("wglUseFontOutlinesW", 3, "count"); // DWORD
	ADD_PARAM_NAME("wglUseFontOutlinesW", 4, "listBase"); // DWORD
	ADD_PARAM_NAME("wglUseFontOutlinesW", 5, "deviation"); // FLOAT
	ADD_PARAM_NAME("wglUseFontOutlinesW", 6, "extrusion"); // FLOAT
	ADD_PARAM_NAME("wglUseFontOutlinesW", 7, "format"); // int
	ADD_PARAM_NAME("wglUseFontOutlinesW", 8, "lpgmf"); // LPGLYPHMETRICSFLOAT

	ADD_PARAM_NAME("wsprintfA", 1, "lpOut"); // LPSTR
	ADD_PARAM_NAME("wsprintfA", 2, "lpFmt"); // LPCSTR
	ADD_PARAM_NAME("wsprintfW", 1, "lpOut"); // LPWSTR
	ADD_PARAM_NAME("wsprintfW", 2, "lpFmt"); // LPCWSTR
	ADD_PARAM_NAME("wvsprintfA", 1, "lpOut"); // LPSTR
	ADD_PARAM_NAME("wvsprintfA", 2, "lpFmt"); // LPCTSTR
	ADD_PARAM_NAME("wvsprintfW", 1, "lpOut"); // LPWSTR
	ADD_PARAM_NAME("wvsprintfW", 2, "lpFmt"); // LPCWSTR
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
