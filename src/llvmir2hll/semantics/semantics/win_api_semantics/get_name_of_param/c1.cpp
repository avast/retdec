/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/c1.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/c1.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with C
*        (first part).
*/
void initFuncParamNamesMap_C1(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("CallMsgFilterA", 1, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("CallMsgFilterA", 2, "nCode"); // int
	ADD_PARAM_NAME("CallMsgFilterW", 1, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("CallMsgFilterW", 2, "nCode"); // int
	ADD_PARAM_NAME("CallNamedPipeA", 1, "lpNamedPipeName"); // LPCSTR
	ADD_PARAM_NAME("CallNamedPipeA", 2, "lpInBuffer"); // LPVOID
	ADD_PARAM_NAME("CallNamedPipeA", 3, "nInBufferSize"); // DWORD
	ADD_PARAM_NAME("CallNamedPipeA", 4, "lpOutBuffer"); // LPVOID
	ADD_PARAM_NAME("CallNamedPipeA", 5, "nOutBufferSize"); // DWORD
	ADD_PARAM_NAME("CallNamedPipeA", 6, "lpBytesRead"); // LPDWORD
	ADD_PARAM_NAME("CallNamedPipeA", 7, "nTimeOut"); // DWORD
	ADD_PARAM_NAME("CallNamedPipeW", 1, "lpNamedPipeName"); // LPCWSTR
	ADD_PARAM_NAME("CallNamedPipeW", 2, "lpInBuffer"); // LPVOID
	ADD_PARAM_NAME("CallNamedPipeW", 3, "nInBufferSize"); // DWORD
	ADD_PARAM_NAME("CallNamedPipeW", 4, "lpOutBuffer"); // LPVOID
	ADD_PARAM_NAME("CallNamedPipeW", 5, "nOutBufferSize"); // DWORD
	ADD_PARAM_NAME("CallNamedPipeW", 6, "lpBytesRead"); // LPDWORD
	ADD_PARAM_NAME("CallNamedPipeW", 7, "nTimeOut"); // DWORD
	ADD_PARAM_NAME("CallNextHookEx", 1, "hhk"); // HHOOK
	ADD_PARAM_NAME("CallNextHookEx", 2, "nCode"); // int
	ADD_PARAM_NAME("CallNextHookEx", 3, "wParam"); // WPARAM
	ADD_PARAM_NAME("CallNextHookEx", 4, "lParam"); // LPARAM
	ADD_PARAM_NAME("CallRouterFindFirstPrinterChangeNotification", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("CallRouterFindFirstPrinterChangeNotification", 2, "fdwFlags"); // DWORD
	ADD_PARAM_NAME("CallRouterFindFirstPrinterChangeNotification", 3, "fdwOptions"); // DWORD
	ADD_PARAM_NAME("CallRouterFindFirstPrinterChangeNotification", 4, "hNotify"); // HANDLE
	ADD_PARAM_NAME("CallRouterFindFirstPrinterChangeNotification", 5, "pPrinterNotifyOptions"); // PPRINTER_NOTIFY_OPTIONS
	ADD_PARAM_NAME("CallWindowProcA", 1, "lpPrevWndFunc"); // WNDPROC
	ADD_PARAM_NAME("CallWindowProcA", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("CallWindowProcA", 3, "Msg"); // UINT
	ADD_PARAM_NAME("CallWindowProcA", 4, "wParam"); // WPARAM
	ADD_PARAM_NAME("CallWindowProcA", 5, "lParam"); // LPARAM
	ADD_PARAM_NAME("CallWindowProcW", 1, "lpPrevWndFunc"); // WNDPROC
	ADD_PARAM_NAME("CallWindowProcW", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("CallWindowProcW", 3, "Msg"); // UINT
	ADD_PARAM_NAME("CallWindowProcW", 4, "wParam"); // WPARAM
	ADD_PARAM_NAME("CallWindowProcW", 5, "lParam"); // LPARAM
	ADD_PARAM_NAME("CallbackMayRunLong", 1, "pci"); // PTP_CALLBACK_INSTANCE
	ADD_PARAM_NAME("CancelDC", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CancelDeviceWakeupRequest", 1, "hDevice"); // HANDLE
	ADD_PARAM_NAME("CancelIo", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("CancelIoEx", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("CancelIoEx", 2, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("CancelSynchronousIo", 1, "hThread"); // HANDLE
	ADD_PARAM_NAME("CancelThreadpoolIo", 1, "pio"); // PTP_IO
	ADD_PARAM_NAME("CancelTimerQueueTimer", 1, "TimerQueue"); // HANDLE
	ADD_PARAM_NAME("CancelTimerQueueTimer", 2, "Timer"); // HANDLE
	ADD_PARAM_NAME("CancelWaitableTimer", 1, "hTimer"); // HANDLE
	ADD_PARAM_NAME("CascadeWindows", 1, "hwndParent"); // HWND
	ADD_PARAM_NAME("CascadeWindows", 2, "wHow"); // UINT
	ADD_PARAM_NAME("CascadeWindows", 3, "lpRect"); // CONST RECT *
	ADD_PARAM_NAME("CascadeWindows", 4, "cKids"); // UINT
	ADD_PARAM_NAME("CascadeWindows", 5, "lpKids"); // const HWND *
	ADD_PARAM_NAME("CertAddCRLContextToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddCRLContextToStore", 2, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertAddCRLContextToStore", 3, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddCRLContextToStore", 4, "ppStoreContext"); // PCCRL_CONTEXT *
	ADD_PARAM_NAME("CertAddCRLLinkToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddCRLLinkToStore", 2, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertAddCRLLinkToStore", 3, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddCRLLinkToStore", 4, "ppStoreContext"); // PCCRL_CONTEXT *
	ADD_PARAM_NAME("CertAddCTLContextToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddCTLContextToStore", 2, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertAddCTLContextToStore", 3, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddCTLContextToStore", 4, "ppStoreContext"); // PCCTL_CONTEXT *
	ADD_PARAM_NAME("CertAddCTLLinkToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddCTLLinkToStore", 2, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertAddCTLLinkToStore", 3, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddCTLLinkToStore", 4, "ppStoreContext"); // PCCTL_CONTEXT *
	ADD_PARAM_NAME("CertAddCertificateContextToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddCertificateContextToStore", 2, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertAddCertificateContextToStore", 3, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddCertificateContextToStore", 4, "ppStoreContext"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CertAddCertificateLinkToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddCertificateLinkToStore", 2, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertAddCertificateLinkToStore", 3, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddCertificateLinkToStore", 4, "ppStoreContext"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CertAddEncodedCRLToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddEncodedCRLToStore", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCRLToStore", 3, "pbCrlEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertAddEncodedCRLToStore", 4, "cbCrlEncoded"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCRLToStore", 5, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCRLToStore", 6, "ppCrlContext"); // PCCRL_CONTEXT *
	ADD_PARAM_NAME("CertAddEncodedCTLToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddEncodedCTLToStore", 2, "dwMsgAndCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCTLToStore", 3, "pbCtlEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertAddEncodedCTLToStore", 4, "cbCtlEncoded"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCTLToStore", 5, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCTLToStore", 6, "ppCtlContext"); // PCCTL_CONTEXT *
	ADD_PARAM_NAME("CertAddEncodedCertificateToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddEncodedCertificateToStore", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCertificateToStore", 3, "pbCertEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertAddEncodedCertificateToStore", 4, "cbCertEncoded"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCertificateToStore", 5, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCertificateToStore", 6, "ppCertContext"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CertAddEncodedCertificateToSystemStoreA", 1, "szCertStoreName"); // LPCSTR
	ADD_PARAM_NAME("CertAddEncodedCertificateToSystemStoreA", 2, "pbCertEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertAddEncodedCertificateToSystemStoreA", 3, "cbCertEncoded"); // DWORD
	ADD_PARAM_NAME("CertAddEncodedCertificateToSystemStoreW", 1, "szCertStoreName"); // LPCWSTR
	ADD_PARAM_NAME("CertAddEncodedCertificateToSystemStoreW", 2, "pbCertEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertAddEncodedCertificateToSystemStoreW", 3, "cbCertEncoded"); // DWORD
	ADD_PARAM_NAME("CertAddEnhancedKeyUsageIdentifier", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertAddEnhancedKeyUsageIdentifier", 2, "pszUsageIdentifier"); // LPCSTR
	ADD_PARAM_NAME("CertAddRefServerOcspResponse", 1, "hServerOcspResponse"); // HCERT_SERVER_OCSP_RESPONSE
	ADD_PARAM_NAME("CertAddRefServerOcspResponseContext", 1, "pServerOcspResponseContext"); // PCCERT_SERVER_OCSP_RESPONSE_CONTEXT
	ADD_PARAM_NAME("CertAddSerializedElementToStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddSerializedElementToStore", 2, "pbElement"); // const BYTE *
	ADD_PARAM_NAME("CertAddSerializedElementToStore", 3, "cbElement"); // DWORD
	ADD_PARAM_NAME("CertAddSerializedElementToStore", 4, "dwAddDisposition"); // DWORD
	ADD_PARAM_NAME("CertAddSerializedElementToStore", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertAddSerializedElementToStore", 6, "dwContextTypeFlags"); // DWORD
	ADD_PARAM_NAME("CertAddSerializedElementToStore", 7, "pdwContextType"); // DWORD *
	ADD_PARAM_NAME("CertAddSerializedElementToStore", 8, "ppvContext"); // const void * *
	ADD_PARAM_NAME("CertAddStoreToCollection", 1, "hCollectionStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddStoreToCollection", 2, "hSiblingStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertAddStoreToCollection", 3, "dwUpdateFlags"); // DWORD
	ADD_PARAM_NAME("CertAddStoreToCollection", 4, "dwPriority"); // DWORD
	ADD_PARAM_NAME("CertAlgIdToOID", 1, "dwAlgId"); // DWORD
	ADD_PARAM_NAME("CertCloseServerOcspResponse", 1, "hServerOcspResponse"); // HCERT_SERVER_OCSP_RESPONSE
	ADD_PARAM_NAME("CertCloseServerOcspResponse", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertCloseStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertCloseStore", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertCompareCertificate", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertCompareCertificate", 2, "pCertId1"); // PCERT_INFO
	ADD_PARAM_NAME("CertCompareCertificate", 3, "pCertId2"); // PCERT_INFO
	ADD_PARAM_NAME("CertCompareCertificateName", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertCompareCertificateName", 2, "pCertName1"); // PCERT_NAME_BLOB
	ADD_PARAM_NAME("CertCompareCertificateName", 3, "pCertName2"); // PCERT_NAME_BLOB
	ADD_PARAM_NAME("CertCompareIntegerBlob", 1, "pInt1"); // PCRYPT_INTEGER_BLOB
	ADD_PARAM_NAME("CertCompareIntegerBlob", 2, "pInt2"); // PCRYPT_INTEGER_BLOB
	ADD_PARAM_NAME("CertComparePublicKeyInfo", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertComparePublicKeyInfo", 2, "pPublicKey1"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CertComparePublicKeyInfo", 3, "pPublicKey2"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CertControlStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertControlStore", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertControlStore", 3, "dwCtrlType"); // DWORD
	ADD_PARAM_NAME("CertControlStore", 4, "pvCtrlPara"); // void const *
	ADD_PARAM_NAME("CertCreateCRLContext", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertCreateCRLContext", 2, "pbCrlEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertCreateCRLContext", 3, "cbCrlEncoded"); // DWORD
	ADD_PARAM_NAME("CertCreateCTLContext", 1, "dwMsgAndCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertCreateCTLContext", 2, "pbCtlEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertCreateCTLContext", 3, "cbCtlEncoded"); // DWORD
	ADD_PARAM_NAME("CertCreateCTLEntryFromCertificateContextProperties", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertCreateCTLEntryFromCertificateContextProperties", 2, "cOptAttr"); // DWORD
	ADD_PARAM_NAME("CertCreateCTLEntryFromCertificateContextProperties", 3, "rgOptAttr"); // PCRYPT_ATTRIBUTE
	ADD_PARAM_NAME("CertCreateCTLEntryFromCertificateContextProperties", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertCreateCTLEntryFromCertificateContextProperties", 5, "pvReserved"); // void *
	ADD_PARAM_NAME("CertCreateCTLEntryFromCertificateContextProperties", 6, "pCtlEntry"); // PCTL_ENTRY
	ADD_PARAM_NAME("CertCreateCTLEntryFromCertificateContextProperties", 7, "pcbCtlEntry"); // DWORD *
	ADD_PARAM_NAME("CertCreateCertificateChainEngine", 1, "pConfig"); // PCERT_CHAIN_ENGINE_CONFIG
	ADD_PARAM_NAME("CertCreateCertificateChainEngine", 2, "phChainEngine"); // HCERTCHAINENGINE *
	ADD_PARAM_NAME("CertCreateCertificateContext", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertCreateCertificateContext", 2, "pbCertEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertCreateCertificateContext", 3, "cbCertEncoded"); // DWORD
	ADD_PARAM_NAME("CertCreateContext", 1, "dwContextType"); // DWORD
	ADD_PARAM_NAME("CertCreateContext", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CertCreateContext", 3, "pbEncoded"); // const BYTE *
	ADD_PARAM_NAME("CertCreateContext", 4, "cbEncoded"); // DWORD
	ADD_PARAM_NAME("CertCreateContext", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertCreateContext", 6, "pCreatePara"); // PCERT_CREATE_CONTEXT_PARA
	ADD_PARAM_NAME("CertCreateSelfSignCertificate", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CertCreateSelfSignCertificate", 2, "pSubjectIssuerBlob"); // PCERT_NAME_BLOB
	ADD_PARAM_NAME("CertCreateSelfSignCertificate", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertCreateSelfSignCertificate", 4, "pKeyProvInfo"); // PCRYPT_KEY_PROV_INFO
	ADD_PARAM_NAME("CertCreateSelfSignCertificate", 5, "pSignatureAlgorithm"); // PCRYPT_ALGORITHM_IDENTIFIER
	ADD_PARAM_NAME("CertCreateSelfSignCertificate", 6, "pStartTime"); // PSYSTEMTIME
	ADD_PARAM_NAME("CertCreateSelfSignCertificate", 7, "pEndTime"); // PSYSTEMTIME
	ADD_PARAM_NAME("CertCreateSelfSignCertificate", 8, "pExtensions"); // PCERT_EXTENSIONS
	ADD_PARAM_NAME("CertDeleteCRLFromStore", 1, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertDeleteCTLFromStore", 1, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertDeleteCertificateFromStore", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertDuplicateCRLContext", 1, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertDuplicateCTLContext", 1, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertDuplicateCertificateChain", 1, "pChainContext"); // PCCERT_CHAIN_CONTEXT
	ADD_PARAM_NAME("CertDuplicateCertificateContext", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertDuplicateStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertEnumCRLContextProperties", 1, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertEnumCRLContextProperties", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertEnumCRLsInStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertEnumCRLsInStore", 2, "pPrevCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertEnumCTLContextProperties", 1, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertEnumCTLContextProperties", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertEnumCTLsInStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertEnumCTLsInStore", 2, "pPrevCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertEnumCertificateContextProperties", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertEnumCertificateContextProperties", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertEnumCertificatesInStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertEnumCertificatesInStore", 2, "pPrevCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertEnumPhysicalStore", 1, "pvSystemStore"); // const void *
	ADD_PARAM_NAME("CertEnumPhysicalStore", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertEnumPhysicalStore", 3, "pvArg"); // void *
	ADD_PARAM_NAME("CertEnumPhysicalStore", 4, "pfnEnum"); // PFN_CERT_ENUM_PHYSICAL_STORE
	ADD_PARAM_NAME("CertEnumSubjectInSortedCTL", 1, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertEnumSubjectInSortedCTL", 2, "ppvNextSubject"); // void * *
	ADD_PARAM_NAME("CertEnumSubjectInSortedCTL", 3, "pSubjectIdentifier"); // PCRYPT_DER_BLOB
	ADD_PARAM_NAME("CertEnumSubjectInSortedCTL", 4, "pEncodedAttributes"); // PCRYPT_DER_BLOB
	ADD_PARAM_NAME("CertEnumSystemStore", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertEnumSystemStore", 2, "pvSystemStoreLocationPara"); // void *
	ADD_PARAM_NAME("CertEnumSystemStore", 3, "pvArg"); // void *
	ADD_PARAM_NAME("CertEnumSystemStore", 4, "pfnEnum"); // PFN_CERT_ENUM_SYSTEM_STORE
	ADD_PARAM_NAME("CertEnumSystemStoreLocation", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertEnumSystemStoreLocation", 2, "pvArg"); // void *
	ADD_PARAM_NAME("CertEnumSystemStoreLocation", 3, "pfnEnum"); // PFN_CERT_ENUM_SYSTEM_STORE_LOCATION
	ADD_PARAM_NAME("CertFindAttribute", 1, "pszObjId"); // LPCSTR
	ADD_PARAM_NAME("CertFindAttribute", 2, "cAttr"); // DWORD
	ADD_PARAM_NAME("CertFindAttribute", 3, "rgAttr"); // CRYPT_ATTRIBUTE []
	ADD_PARAM_NAME("CertFindCRLInStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertFindCRLInStore", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertFindCRLInStore", 3, "dwFindFlags"); // DWORD
	ADD_PARAM_NAME("CertFindCRLInStore", 4, "dwFindType"); // DWORD
	ADD_PARAM_NAME("CertFindCRLInStore", 5, "pvFindPara"); // const void *
	ADD_PARAM_NAME("CertFindCRLInStore", 6, "pPrevCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertFindCTLInStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertFindCTLInStore", 2, "dwMsgAndCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertFindCTLInStore", 3, "dwFindFlags"); // DWORD
	ADD_PARAM_NAME("CertFindCTLInStore", 4, "dwFindType"); // DWORD
	ADD_PARAM_NAME("CertFindCTLInStore", 5, "pvFindPara"); // const void *
	ADD_PARAM_NAME("CertFindCTLInStore", 6, "pPrevCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertFindCertificateInCRL", 1, "pCert"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertFindCertificateInCRL", 2, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertFindCertificateInCRL", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertFindCertificateInCRL", 4, "pvReserved"); // void *
	ADD_PARAM_NAME("CertFindCertificateInCRL", 5, "ppCrlEntry"); // PCRL_ENTRY *
	ADD_PARAM_NAME("CertFindCertificateInStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertFindCertificateInStore", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertFindCertificateInStore", 3, "dwFindFlags"); // DWORD
	ADD_PARAM_NAME("CertFindCertificateInStore", 4, "dwFindType"); // DWORD
	ADD_PARAM_NAME("CertFindCertificateInStore", 5, "pvFindPara"); // const void *
	ADD_PARAM_NAME("CertFindCertificateInStore", 6, "pPrevCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertFindChainInStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertFindChainInStore", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertFindChainInStore", 3, "dwFindFlags"); // DWORD
	ADD_PARAM_NAME("CertFindChainInStore", 4, "dwFindType"); // DWORD
	ADD_PARAM_NAME("CertFindChainInStore", 5, "pvFindPara"); // const void *
	ADD_PARAM_NAME("CertFindChainInStore", 6, "pPrevChainContext"); // PCCERT_CHAIN_CONTEXT
	ADD_PARAM_NAME("CertFindExtension", 1, "pszObjId"); // LPCSTR
	ADD_PARAM_NAME("CertFindExtension", 2, "cExtensions"); // DWORD
	ADD_PARAM_NAME("CertFindExtension", 3, "rgExtensions"); // CERT_EXTENSION []
	ADD_PARAM_NAME("CertFindRDNAttr", 1, "pszObjId"); // LPCSTR
	ADD_PARAM_NAME("CertFindRDNAttr", 2, "pName"); // PCERT_NAME_INFO
	ADD_PARAM_NAME("CertFindSubjectInCTL", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CertFindSubjectInCTL", 2, "dwSubjectType"); // DWORD
	ADD_PARAM_NAME("CertFindSubjectInCTL", 3, "pvSubject"); // void *
	ADD_PARAM_NAME("CertFindSubjectInCTL", 4, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertFindSubjectInCTL", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertFindSubjectInSortedCTL", 1, "pSubjectIdentifier"); // PCRYPT_DATA_BLOB
	ADD_PARAM_NAME("CertFindSubjectInSortedCTL", 2, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertFindSubjectInSortedCTL", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertFindSubjectInSortedCTL", 4, "pvReserved"); // void *
	ADD_PARAM_NAME("CertFindSubjectInSortedCTL", 5, "pEncodedAttributes"); // PCRYPT_DER_BLOB
	ADD_PARAM_NAME("CertFreeCRLContext", 1, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertFreeCTLContext", 1, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertFreeCertificateChain", 1, "pChainContext"); // PCCERT_CHAIN_CONTEXT
	ADD_PARAM_NAME("CertFreeCertificateChainEngine", 1, "hChainEngine"); // HCERTCHAINENGINE
	ADD_PARAM_NAME("CertFreeCertificateChainList", 1, "prgpSelection"); // PCCERT_CHAIN_CONTEXT *
	ADD_PARAM_NAME("CertFreeCertificateContext", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertFreeServerOcspResponseContext", 1, "pServerOcspResponseContext"); // PCCERT_SERVER_OCSP_RESPONSE_CONTEXT
	ADD_PARAM_NAME("CertGetCRLContextProperty", 1, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertGetCRLContextProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertGetCRLContextProperty", 3, "pvData"); // void *
	ADD_PARAM_NAME("CertGetCRLContextProperty", 4, "pcbData"); // DWORD *
	ADD_PARAM_NAME("CertGetCRLFromStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertGetCRLFromStore", 2, "pIssuerContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertGetCRLFromStore", 3, "pPrevCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertGetCRLFromStore", 4, "pdwFlags"); // DWORD *
	ADD_PARAM_NAME("CertGetCTLContextProperty", 1, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertGetCTLContextProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertGetCTLContextProperty", 3, "pvData"); // void *
	ADD_PARAM_NAME("CertGetCTLContextProperty", 4, "pcbData"); // DWORD *
	ADD_PARAM_NAME("CertGetCertificateChain", 1, "hChainEngine"); // HCERTCHAINENGINE
	ADD_PARAM_NAME("CertGetCertificateChain", 2, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertGetCertificateChain", 3, "pTime"); // LPFILETIME
	ADD_PARAM_NAME("CertGetCertificateChain", 4, "hAdditionalStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertGetCertificateChain", 5, "pChainPara"); // PCERT_CHAIN_PARA
	ADD_PARAM_NAME("CertGetCertificateChain", 6, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertGetCertificateChain", 7, "pvReserved"); // LPVOID
	ADD_PARAM_NAME("CertGetCertificateChain", 8, "ppChainContext"); // PCCERT_CHAIN_CONTEXT *
	ADD_PARAM_NAME("CertGetCertificateContextProperty", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertGetCertificateContextProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertGetCertificateContextProperty", 3, "pvData"); // void *
	ADD_PARAM_NAME("CertGetCertificateContextProperty", 4, "pcbData"); // DWORD *
	ADD_PARAM_NAME("CertGetEnhancedKeyUsage", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertGetEnhancedKeyUsage", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertGetEnhancedKeyUsage", 3, "pUsage"); // PCERT_ENHKEY_USAGE
	ADD_PARAM_NAME("CertGetEnhancedKeyUsage", 4, "pcbUsage"); // DWORD *
	ADD_PARAM_NAME("CertGetIntendedKeyUsage", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertGetIntendedKeyUsage", 2, "pCertInfo"); // PCERT_INFO
	ADD_PARAM_NAME("CertGetIntendedKeyUsage", 3, "pbKeyUsage"); // BYTE *
	ADD_PARAM_NAME("CertGetIntendedKeyUsage", 4, "cbKeyUsage"); // DWORD
	ADD_PARAM_NAME("CertGetIssuerCertificateFromStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertGetIssuerCertificateFromStore", 2, "pSubjectContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertGetIssuerCertificateFromStore", 3, "pPrevIssuerContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertGetIssuerCertificateFromStore", 4, "pdwFlags"); // DWORD *
	ADD_PARAM_NAME("CertGetNameStringA", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertGetNameStringA", 2, "dwType"); // DWORD
	ADD_PARAM_NAME("CertGetNameStringA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertGetNameStringA", 4, "pvTypePara"); // void *
	ADD_PARAM_NAME("CertGetNameStringA", 5, "pszNameString"); // LPSTR
	ADD_PARAM_NAME("CertGetNameStringA", 6, "cchNameString"); // DWORD
	ADD_PARAM_NAME("CertGetNameStringW", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertGetNameStringW", 2, "dwType"); // DWORD
	ADD_PARAM_NAME("CertGetNameStringW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertGetNameStringW", 4, "pvTypePara"); // void *
	ADD_PARAM_NAME("CertGetNameStringW", 5, "pszNameString"); // LPWSTR
	ADD_PARAM_NAME("CertGetNameStringW", 6, "cchNameString"); // DWORD
	ADD_PARAM_NAME("CertGetPublicKeyLength", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertGetPublicKeyLength", 2, "pPublicKey"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CertGetServerOcspResponseContext", 1, "hServerOcspResponse"); // HCERT_SERVER_OCSP_RESPONSE
	ADD_PARAM_NAME("CertGetServerOcspResponseContext", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertGetServerOcspResponseContext", 3, "pvReserved"); // LPVOID
	ADD_PARAM_NAME("CertGetStoreProperty", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertGetStoreProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertGetStoreProperty", 3, "pvData"); // void *
	ADD_PARAM_NAME("CertGetStoreProperty", 4, "pcbData"); // DWORD *
	ADD_PARAM_NAME("CertGetSubjectCertificateFromStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertGetSubjectCertificateFromStore", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertGetSubjectCertificateFromStore", 3, "pCertId"); // PCERT_INFO
	ADD_PARAM_NAME("CertGetValidUsages", 1, "cCerts"); // DWORD
	ADD_PARAM_NAME("CertGetValidUsages", 2, "rghCerts"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CertGetValidUsages", 3, "cNumOIDs"); // int *
	ADD_PARAM_NAME("CertGetValidUsages", 4, "rghOIDs"); // LPSTR *
	ADD_PARAM_NAME("CertGetValidUsages", 5, "pcbOIDs"); // DWORD *
	ADD_PARAM_NAME("CertIsRDNAttrsInCertificateName", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertIsRDNAttrsInCertificateName", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertIsRDNAttrsInCertificateName", 3, "pCertName"); // PCERT_NAME_BLOB
	ADD_PARAM_NAME("CertIsRDNAttrsInCertificateName", 4, "pRDN"); // PCERT_RDN
	ADD_PARAM_NAME("CertIsValidCRLForCertificate", 1, "pCert"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertIsValidCRLForCertificate", 2, "pCrl"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertIsValidCRLForCertificate", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertIsValidCRLForCertificate", 4, "pvReserved"); // void *
	ADD_PARAM_NAME("CertNameToStrA", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertNameToStrA", 2, "pName"); // PCERT_NAME_BLOB
	ADD_PARAM_NAME("CertNameToStrA", 3, "dwStrType"); // DWORD
	ADD_PARAM_NAME("CertNameToStrA", 4, "psz"); // LPSTR
	ADD_PARAM_NAME("CertNameToStrA", 5, "csz"); // DWORD
	ADD_PARAM_NAME("CertNameToStrW", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertNameToStrW", 2, "pName"); // PCERT_NAME_BLOB
	ADD_PARAM_NAME("CertNameToStrW", 3, "dwStrType"); // DWORD
	ADD_PARAM_NAME("CertNameToStrW", 4, "psz"); // LPWSTR
	ADD_PARAM_NAME("CertNameToStrW", 5, "csz"); // DWORD
	ADD_PARAM_NAME("CertOIDToAlgId", 1, "pszObjId"); // LPCSTR
	ADD_PARAM_NAME("CertOpenServerOcspResponse", 1, "pChainContext"); // PCCERT_CHAIN_CONTEXT
	ADD_PARAM_NAME("CertOpenServerOcspResponse", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertOpenServerOcspResponse", 3, "pvReserved"); // LPVOID
	ADD_PARAM_NAME("CertOpenStore", 1, "lpszStoreProvider"); // LPCSTR
	ADD_PARAM_NAME("CertOpenStore", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CertOpenStore", 3, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CertOpenStore", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertOpenStore", 5, "pvPara"); // const void *
	ADD_PARAM_NAME("CertOpenSystemStoreA", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CertOpenSystemStoreA", 2, "szSubsystemProtocol"); // LPCSTR
	ADD_PARAM_NAME("CertOpenSystemStoreW", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CertOpenSystemStoreW", 2, "szSubsystemProtocol"); // LPCWSTR
	ADD_PARAM_NAME("CertRDNValueToStrA", 1, "dwValueType"); // DWORD
	ADD_PARAM_NAME("CertRDNValueToStrA", 2, "pValue"); // PCERT_RDN_VALUE_BLOB
	ADD_PARAM_NAME("CertRDNValueToStrA", 3, "psz"); // LPSTR
	ADD_PARAM_NAME("CertRDNValueToStrA", 4, "csz"); // DWORD
	ADD_PARAM_NAME("CertRDNValueToStrW", 1, "dwValueType"); // DWORD
	ADD_PARAM_NAME("CertRDNValueToStrW", 2, "pValue"); // PCERT_RDN_VALUE_BLOB
	ADD_PARAM_NAME("CertRDNValueToStrW", 3, "psz"); // LPWSTR
	ADD_PARAM_NAME("CertRDNValueToStrW", 4, "csz"); // DWORD
	ADD_PARAM_NAME("CertRegisterPhysicalStore", 1, "pvSystemStore"); // const void *
	ADD_PARAM_NAME("CertRegisterPhysicalStore", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertRegisterPhysicalStore", 3, "pwszStoreName"); // LPCWSTR
	ADD_PARAM_NAME("CertRegisterPhysicalStore", 4, "pStoreInfo"); // PCERT_PHYSICAL_STORE_INFO
	ADD_PARAM_NAME("CertRegisterPhysicalStore", 5, "pvReserved"); // void *
	ADD_PARAM_NAME("CertRegisterSystemStore", 1, "pvSystemStore"); // const void *
	ADD_PARAM_NAME("CertRegisterSystemStore", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertRegisterSystemStore", 3, "pStoreInfo"); // PCERT_SYSTEM_STORE_INFO
	ADD_PARAM_NAME("CertRegisterSystemStore", 4, "pvReserved"); // void *
	ADD_PARAM_NAME("CertRemoveEnhancedKeyUsageIdentifier", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertRemoveEnhancedKeyUsageIdentifier", 2, "pszUsageIdentifier"); // LPCSTR
	ADD_PARAM_NAME("CertRemoveStoreFromCollection", 1, "hCollectionStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertRemoveStoreFromCollection", 2, "hSiblingStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertResyncCertificateChainEngine", 1, "hChainEngine"); // HCERTCHAINENGINE
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 2, "lpszLogoOrBiometricType"); // LPCSTR
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 3, "dwRetrievalFlags"); // DWORD
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 4, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 6, "pvReserved"); // void *
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 7, "ppbData"); // BYTE * *
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 8, "pcbData"); // DWORD *
	ADD_PARAM_NAME("CertRetrieveLogoOrBiometricInfo", 9, "ppwszMimeType"); // LPWSTR *
	ADD_PARAM_NAME("CertSaveStore", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertSaveStore", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CertSaveStore", 3, "dwSaveAs"); // DWORD
	ADD_PARAM_NAME("CertSaveStore", 4, "dwSaveTo"); // DWORD
	ADD_PARAM_NAME("CertSaveStore", 5, "pvSaveToPara"); // void *
	ADD_PARAM_NAME("CertSaveStore", 6, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSelectCertificateChains", 1, "pSelectionContext"); // LPCGUID
	ADD_PARAM_NAME("CertSelectCertificateChains", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSelectCertificateChains", 3, "pChainParameters"); // PCCERT_SELECT_CHAIN_PARA
	ADD_PARAM_NAME("CertSelectCertificateChains", 4, "cCriteria"); // DWORD
	ADD_PARAM_NAME("CertSelectCertificateChains", 5, "rgpCriteria"); // PCCERT_SELECT_CRITERIA
	ADD_PARAM_NAME("CertSelectCertificateChains", 6, "hStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertSelectCertificateChains", 7, "pcSelection"); // PDWORD
	ADD_PARAM_NAME("CertSelectCertificateChains", 8, "pprgpSelection"); // PCCERT_CHAIN_CONTEXT * *
	ADD_PARAM_NAME("CertSerializeCRLStoreElement", 1, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertSerializeCRLStoreElement", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSerializeCRLStoreElement", 3, "pbElement"); // BYTE *
	ADD_PARAM_NAME("CertSerializeCRLStoreElement", 4, "pcbElement"); // DWORD *
	ADD_PARAM_NAME("CertSerializeCTLStoreElement", 1, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertSerializeCTLStoreElement", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSerializeCTLStoreElement", 3, "pbElement"); // BYTE *
	ADD_PARAM_NAME("CertSerializeCTLStoreElement", 4, "pcbElement"); // DWORD *
	ADD_PARAM_NAME("CertSerializeCertificateStoreElement", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertSerializeCertificateStoreElement", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSerializeCertificateStoreElement", 3, "pbElement"); // BYTE *
	ADD_PARAM_NAME("CertSerializeCertificateStoreElement", 4, "pcbElement"); // DWORD *
	ADD_PARAM_NAME("CertSetCRLContextProperty", 1, "pCrlContext"); // PCCRL_CONTEXT
	ADD_PARAM_NAME("CertSetCRLContextProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertSetCRLContextProperty", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSetCRLContextProperty", 4, "pvData"); // const void *
	ADD_PARAM_NAME("CertSetCTLContextProperty", 1, "pCtlContext"); // PCCTL_CONTEXT
	ADD_PARAM_NAME("CertSetCTLContextProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertSetCTLContextProperty", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSetCTLContextProperty", 4, "pvData"); // const void *
	ADD_PARAM_NAME("CertSetCertificateContextPropertiesFromCTLEntry", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertSetCertificateContextPropertiesFromCTLEntry", 2, "pCtlEntry"); // PCTL_ENTRY
	ADD_PARAM_NAME("CertSetCertificateContextPropertiesFromCTLEntry", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSetCertificateContextProperty", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertSetCertificateContextProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertSetCertificateContextProperty", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSetCertificateContextProperty", 4, "pvData"); // const void *
	ADD_PARAM_NAME("CertSetEnhancedKeyUsage", 1, "pCertContext"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertSetEnhancedKeyUsage", 2, "pUsage"); // PCERT_ENHKEY_USAGE
	ADD_PARAM_NAME("CertSetStoreProperty", 1, "hCertStore"); // HCERTSTORE
	ADD_PARAM_NAME("CertSetStoreProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CertSetStoreProperty", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertSetStoreProperty", 4, "pvData"); // const void *
	ADD_PARAM_NAME("CertStrToNameA", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertStrToNameA", 2, "pszX500"); // LPCSTR
	ADD_PARAM_NAME("CertStrToNameA", 3, "dwStrType"); // DWORD
	ADD_PARAM_NAME("CertStrToNameA", 4, "pvReserved"); // void *
	ADD_PARAM_NAME("CertStrToNameA", 5, "pbEncoded"); // BYTE *
	ADD_PARAM_NAME("CertStrToNameA", 6, "pcbEncoded"); // DWORD *
	ADD_PARAM_NAME("CertStrToNameA", 7, "ppszError"); // LPCSTR *
	ADD_PARAM_NAME("CertStrToNameW", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertStrToNameW", 2, "pszX500"); // LPCWSTR
	ADD_PARAM_NAME("CertStrToNameW", 3, "dwStrType"); // DWORD
	ADD_PARAM_NAME("CertStrToNameW", 4, "pvReserved"); // void *
	ADD_PARAM_NAME("CertStrToNameW", 5, "pbEncoded"); // BYTE *
	ADD_PARAM_NAME("CertStrToNameW", 6, "pcbEncoded"); // DWORD *
	ADD_PARAM_NAME("CertStrToNameW", 7, "ppszError"); // LPCWSTR *
	ADD_PARAM_NAME("CertUnregisterPhysicalStore", 1, "pvSystemStore"); // const void *
	ADD_PARAM_NAME("CertUnregisterPhysicalStore", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertUnregisterPhysicalStore", 3, "pwszStoreName"); // LPCWSTR
	ADD_PARAM_NAME("CertUnregisterSystemStore", 1, "pvSystemStore"); // const void *
	ADD_PARAM_NAME("CertUnregisterSystemStore", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertVerifyCRLRevocation", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CertVerifyCRLRevocation", 2, "pCertId"); // PCERT_INFO
	ADD_PARAM_NAME("CertVerifyCRLRevocation", 3, "cCrlInfo"); // DWORD
	ADD_PARAM_NAME("CertVerifyCRLRevocation", 4, "rgpCrlInfo"); // PCRL_INFO []
	ADD_PARAM_NAME("CertVerifyCRLTimeValidity", 1, "pTimeToVerify"); // LPFILETIME
	ADD_PARAM_NAME("CertVerifyCRLTimeValidity", 2, "pCrlInfo"); // PCRL_INFO
	ADD_PARAM_NAME("CertVerifyCTLUsage", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CertVerifyCTLUsage", 2, "dwSubjectType"); // DWORD
	ADD_PARAM_NAME("CertVerifyCTLUsage", 3, "pvSubject"); // void *
	ADD_PARAM_NAME("CertVerifyCTLUsage", 4, "pSubjectUsage"); // PCTL_USAGE
	ADD_PARAM_NAME("CertVerifyCTLUsage", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertVerifyCTLUsage", 6, "pVerifyUsagePara"); // PCTL_VERIFY_USAGE_PARA
	ADD_PARAM_NAME("CertVerifyCTLUsage", 7, "pVerifyUsageStatus"); // PCTL_VERIFY_USAGE_STATUS
	ADD_PARAM_NAME("CertVerifyCertificateChainPolicy", 1, "pszPolicyOID"); // LPCSTR
	ADD_PARAM_NAME("CertVerifyCertificateChainPolicy", 2, "pChainContext"); // PCCERT_CHAIN_CONTEXT
	ADD_PARAM_NAME("CertVerifyCertificateChainPolicy", 3, "pPolicyPara"); // PCERT_CHAIN_POLICY_PARA
	ADD_PARAM_NAME("CertVerifyCertificateChainPolicy", 4, "pPolicyStatus"); // PCERT_CHAIN_POLICY_STATUS
	ADD_PARAM_NAME("CertVerifyRevocation", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CertVerifyRevocation", 2, "dwRevType"); // DWORD
	ADD_PARAM_NAME("CertVerifyRevocation", 3, "cContext"); // DWORD
	ADD_PARAM_NAME("CertVerifyRevocation", 4, "rgpvContext"); // PVOID []
	ADD_PARAM_NAME("CertVerifyRevocation", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CertVerifyRevocation", 6, "pRevPara"); // PCERT_REVOCATION_PARA
	ADD_PARAM_NAME("CertVerifyRevocation", 7, "pRevStatus"); // PCERT_REVOCATION_STATUS
	ADD_PARAM_NAME("CertVerifySubjectCertificateContext", 1, "pSubject"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertVerifySubjectCertificateContext", 2, "pIssuer"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CertVerifySubjectCertificateContext", 3, "pdwFlags"); // DWORD *
	ADD_PARAM_NAME("CertVerifyTimeValidity", 1, "pTimeToVerify"); // LPFILETIME
	ADD_PARAM_NAME("CertVerifyTimeValidity", 2, "pCertInfo"); // PCERT_INFO
	ADD_PARAM_NAME("CertVerifyValidityNesting", 1, "pSubjectInfo"); // PCERT_INFO
	ADD_PARAM_NAME("CertVerifyValidityNesting", 2, "pIssuerInfo"); // PCERT_INFO
	ADD_PARAM_NAME("ChangeClipboardChain", 1, "hWndRemove"); // HWND
	ADD_PARAM_NAME("ChangeClipboardChain", 2, "hWndNewNext"); // HWND
	ADD_PARAM_NAME("ChangeDisplaySettingsA", 1, "lpDevMode"); // LPDEVMODEA
	ADD_PARAM_NAME("ChangeDisplaySettingsA", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("ChangeDisplaySettingsExA", 1, "lpszDeviceName"); // LPCSTR
	ADD_PARAM_NAME("ChangeDisplaySettingsExA", 2, "lpDevMode"); // LPDEVMODEA
	ADD_PARAM_NAME("ChangeDisplaySettingsExA", 3, "hWnd"); // HWND
	ADD_PARAM_NAME("ChangeDisplaySettingsExA", 4, "dwflags"); // DWORD
	ADD_PARAM_NAME("ChangeDisplaySettingsExA", 5, "lParam"); // LPVOID
	ADD_PARAM_NAME("ChangeDisplaySettingsExW", 1, "lpszDeviceName"); // LPCWSTR
	ADD_PARAM_NAME("ChangeDisplaySettingsExW", 2, "lpDevMode"); // LPDEVMODEW
	ADD_PARAM_NAME("ChangeDisplaySettingsExW", 3, "hWnd"); // HWND
	ADD_PARAM_NAME("ChangeDisplaySettingsExW", 4, "dwflags"); // DWORD
	ADD_PARAM_NAME("ChangeDisplaySettingsExW", 5, "lParam"); // LPVOID
	ADD_PARAM_NAME("ChangeDisplaySettingsW", 1, "lpDevMode"); // LPDEVMODEW
	ADD_PARAM_NAME("ChangeDisplaySettingsW", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("ChangeMenuA", 1, "hMenu"); // HMENU
	ADD_PARAM_NAME("ChangeMenuA", 2, "cmd"); // UINT
	ADD_PARAM_NAME("ChangeMenuA", 3, "lpszNewItem"); // LPCSTR
	ADD_PARAM_NAME("ChangeMenuA", 4, "cmdInsert"); // UINT
	ADD_PARAM_NAME("ChangeMenuA", 5, "flags"); // UINT
	ADD_PARAM_NAME("ChangeMenuW", 1, "hMenu"); // HMENU
	ADD_PARAM_NAME("ChangeMenuW", 2, "cmd"); // UINT
	ADD_PARAM_NAME("ChangeMenuW", 3, "lpszNewItem"); // LPCWSTR
	ADD_PARAM_NAME("ChangeMenuW", 4, "cmdInsert"); // UINT
	ADD_PARAM_NAME("ChangeMenuW", 5, "flags"); // UINT
	ADD_PARAM_NAME("ChangeServiceConfig2A", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("ChangeServiceConfig2A", 2, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("ChangeServiceConfig2A", 3, "lpInfo"); // LPVOID
	ADD_PARAM_NAME("ChangeServiceConfig2W", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("ChangeServiceConfig2W", 2, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("ChangeServiceConfig2W", 3, "lpInfo"); // LPVOID
	ADD_PARAM_NAME("ChangeServiceConfigA", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("ChangeServiceConfigA", 2, "dwServiceType"); // DWORD
	ADD_PARAM_NAME("ChangeServiceConfigA", 3, "dwStartType"); // DWORD
	ADD_PARAM_NAME("ChangeServiceConfigA", 4, "dwErrorControl"); // DWORD
	ADD_PARAM_NAME("ChangeServiceConfigA", 5, "lpBinaryPathName"); // LPCSTR
	ADD_PARAM_NAME("ChangeServiceConfigA", 6, "lpLoadOrderGroup"); // LPCSTR
	ADD_PARAM_NAME("ChangeServiceConfigA", 7, "lpdwTagId"); // LPDWORD
	ADD_PARAM_NAME("ChangeServiceConfigA", 8, "lpDependencies"); // LPCSTR
	ADD_PARAM_NAME("ChangeServiceConfigA", 9, "lpServiceStartName"); // LPCSTR
	ADD_PARAM_NAME("ChangeServiceConfigA", 10, "lpPassword"); // LPCSTR
	ADD_PARAM_NAME("ChangeServiceConfigA", 11, "lpDisplayName"); // LPCSTR
	ADD_PARAM_NAME("ChangeServiceConfigW", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("ChangeServiceConfigW", 2, "dwServiceType"); // DWORD
	ADD_PARAM_NAME("ChangeServiceConfigW", 3, "dwStartType"); // DWORD
	ADD_PARAM_NAME("ChangeServiceConfigW", 4, "dwErrorControl"); // DWORD
	ADD_PARAM_NAME("ChangeServiceConfigW", 5, "lpBinaryPathName"); // LPCWSTR
	ADD_PARAM_NAME("ChangeServiceConfigW", 6, "lpLoadOrderGroup"); // LPCWSTR
	ADD_PARAM_NAME("ChangeServiceConfigW", 7, "lpdwTagId"); // LPDWORD
	ADD_PARAM_NAME("ChangeServiceConfigW", 8, "lpDependencies"); // LPCWSTR
	ADD_PARAM_NAME("ChangeServiceConfigW", 9, "lpServiceStartName"); // LPCWSTR
	ADD_PARAM_NAME("ChangeServiceConfigW", 10, "lpPassword"); // LPCWSTR
	ADD_PARAM_NAME("ChangeServiceConfigW", 11, "lpDisplayName"); // LPCWSTR
	ADD_PARAM_NAME("ChangeTimerQueueTimer", 1, "TimerQueue"); // HANDLE
	ADD_PARAM_NAME("ChangeTimerQueueTimer", 2, "Timer"); // HANDLE
	ADD_PARAM_NAME("ChangeTimerQueueTimer", 3, "DueTime"); // ULONG
	ADD_PARAM_NAME("ChangeTimerQueueTimer", 4, "Period"); // ULONG
	ADD_PARAM_NAME("CharLowerA", 1, "lpsz"); // LPSTR
	ADD_PARAM_NAME("CharLowerBuffA", 1, "lpsz"); // LPSTR
	ADD_PARAM_NAME("CharLowerBuffA", 2, "cchLength"); // DWORD
	ADD_PARAM_NAME("CharLowerBuffW", 1, "lpsz"); // LPWSTR
	ADD_PARAM_NAME("CharLowerBuffW", 2, "cchLength"); // DWORD
	ADD_PARAM_NAME("CharLowerW", 1, "lpsz"); // LPWSTR
	ADD_PARAM_NAME("CharNextA", 1, "lpsz"); // LPCSTR
	ADD_PARAM_NAME("CharNextExA", 1, "CodePage"); // WORD
	ADD_PARAM_NAME("CharNextExA", 2, "lpCurrentChar"); // LPCSTR
	ADD_PARAM_NAME("CharNextExA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CharNextW", 1, "lpsz"); // LPCWSTR
	ADD_PARAM_NAME("CharPrevA", 1, "lpszStart"); // LPCSTR
	ADD_PARAM_NAME("CharPrevA", 2, "lpszCurrent"); // LPCSTR
	ADD_PARAM_NAME("CharPrevExA", 1, "CodePage"); // WORD
	ADD_PARAM_NAME("CharPrevExA", 2, "lpStart"); // LPCSTR
	ADD_PARAM_NAME("CharPrevExA", 3, "lpCurrentChar"); // LPCSTR
	ADD_PARAM_NAME("CharPrevExA", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CharPrevW", 1, "lpszStart"); // LPCWSTR
	ADD_PARAM_NAME("CharPrevW", 2, "lpszCurrent"); // LPCWSTR
	ADD_PARAM_NAME("CharToOemA", 1, "lpszSrc"); // LPCSTR
	ADD_PARAM_NAME("CharToOemA", 2, "lpszDst"); // LPSTR
	ADD_PARAM_NAME("CharToOemBuffA", 1, "lpszSrc"); // LPCSTR
	ADD_PARAM_NAME("CharToOemBuffA", 2, "lpszDst"); // LPSTR
	ADD_PARAM_NAME("CharToOemBuffA", 3, "cchDstLength"); // DWORD
	ADD_PARAM_NAME("CharToOemBuffW", 1, "lpszSrc"); // LPCWSTR
	ADD_PARAM_NAME("CharToOemBuffW", 2, "lpszDst"); // LPSTR
	ADD_PARAM_NAME("CharToOemBuffW", 3, "cchDstLength"); // DWORD
	ADD_PARAM_NAME("CharToOemW", 1, "lpszSrc"); // LPCWSTR
	ADD_PARAM_NAME("CharToOemW", 2, "lpszDst"); // LPSTR
	ADD_PARAM_NAME("CharUpperA", 1, "lpsz"); // LPSTR
	ADD_PARAM_NAME("CharUpperBuffA", 1, "lpsz"); // LPSTR
	ADD_PARAM_NAME("CharUpperBuffA", 2, "cchLength"); // DWORD
	ADD_PARAM_NAME("CharUpperBuffW", 1, "lpsz"); // LPWSTR
	ADD_PARAM_NAME("CharUpperBuffW", 2, "cchLength"); // DWORD
	ADD_PARAM_NAME("CharUpperW", 1, "lpsz"); // LPWSTR
	ADD_PARAM_NAME("CheckColorsInGamut", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CheckColorsInGamut", 2, "lpRGBTriple"); // LPVOID
	ADD_PARAM_NAME("CheckColorsInGamut", 3, "dlpBuffer"); // LPVOID
	ADD_PARAM_NAME("CheckColorsInGamut", 4, "nCount"); // DWORD
	ADD_PARAM_NAME("CheckDlgButton", 1, "hDlg"); // HWND
	ADD_PARAM_NAME("CheckDlgButton", 2, "nIDButton"); // int
	ADD_PARAM_NAME("CheckDlgButton", 3, "uCheck"); // UINT
	ADD_PARAM_NAME("CheckMenuItem", 1, "hMenu"); // HMENU
	ADD_PARAM_NAME("CheckMenuItem", 2, "uIDCheckItem"); // UINT
	ADD_PARAM_NAME("CheckMenuItem", 3, "uCheck"); // UINT
	ADD_PARAM_NAME("CheckMenuRadioItem", 1, "hmenu"); // HMENU
	ADD_PARAM_NAME("CheckMenuRadioItem", 2, "first"); // UINT
	ADD_PARAM_NAME("CheckMenuRadioItem", 3, "last"); // UINT
	ADD_PARAM_NAME("CheckMenuRadioItem", 4, "check"); // UINT
	ADD_PARAM_NAME("CheckMenuRadioItem", 5, "flags"); // UINT
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3A", 1, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3A", 2, "lpOemName"); // LPSTR
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3A", 3, "OemNameSize"); // DWORD
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3A", 4, "pbNameContainsSpaces"); // PBOOL
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3A", 5, "pbNameLegal"); // PBOOL
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3W", 1, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3W", 2, "lpOemName"); // LPSTR
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3W", 3, "OemNameSize"); // DWORD
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3W", 4, "pbNameContainsSpaces"); // PBOOL
	ADD_PARAM_NAME("CheckNameLegalDOS8Dot3W", 5, "pbNameLegal"); // PBOOL
	ADD_PARAM_NAME("CheckRadioButton", 1, "hDlg"); // HWND
	ADD_PARAM_NAME("CheckRadioButton", 2, "nIDFirstButton"); // int
	ADD_PARAM_NAME("CheckRadioButton", 3, "nIDLastButton"); // int
	ADD_PARAM_NAME("CheckRadioButton", 4, "nIDCheckButton"); // int
	ADD_PARAM_NAME("CheckRemoteDebuggerPresent", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("CheckRemoteDebuggerPresent", 2, "pbDebuggerPresent"); // PBOOL
	ADD_PARAM_NAME("CheckTokenMembership", 1, "TokenHandle"); // HANDLE
	ADD_PARAM_NAME("CheckTokenMembership", 2, "SidToCheck"); // PSID
	ADD_PARAM_NAME("CheckTokenMembership", 3, "IsMember"); // PBOOL
	ADD_PARAM_NAME("ChildWindowFromPoint", 1, "hWndParent"); // HWND
	ADD_PARAM_NAME("ChildWindowFromPoint", 2, "Point"); // POINT
	ADD_PARAM_NAME("ChildWindowFromPointEx", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("ChildWindowFromPointEx", 2, "pt"); // POINT
	ADD_PARAM_NAME("ChildWindowFromPointEx", 3, "flags"); // UINT
	ADD_PARAM_NAME("ChoosePixelFormat", 1, "hdc"); // HDC
	ADD_PARAM_NAME("ChoosePixelFormat", 2, "ppfd"); // CONST PIXELFORMATDESCRIPTOR *
	ADD_PARAM_NAME("Chord", 1, "hdc"); // HDC
	ADD_PARAM_NAME("Chord", 2, "x1"); // int
	ADD_PARAM_NAME("Chord", 3, "y1"); // int
	ADD_PARAM_NAME("Chord", 4, "x2"); // int
	ADD_PARAM_NAME("Chord", 5, "y2"); // int
	ADD_PARAM_NAME("Chord", 6, "x3"); // int
	ADD_PARAM_NAME("Chord", 7, "y3"); // int
	ADD_PARAM_NAME("Chord", 8, "x4"); // int
	ADD_PARAM_NAME("Chord", 9, "y4"); // int
	ADD_PARAM_NAME("ClearCommBreak", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("ClearCommError", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("ClearCommError", 2, "lpErrors"); // LPDWORD
	ADD_PARAM_NAME("ClearCommError", 3, "lpStat"); // LPCOMSTAT
	ADD_PARAM_NAME("ClearEventLogA", 1, "hEventLog"); // HANDLE
	ADD_PARAM_NAME("ClearEventLogA", 2, "lpBackupFileName"); // LPCSTR
	ADD_PARAM_NAME("ClearEventLogW", 1, "hEventLog"); // HANDLE
	ADD_PARAM_NAME("ClearEventLogW", 2, "lpBackupFileName"); // LPCWSTR
	ADD_PARAM_NAME("ClientToScreen", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("ClientToScreen", 2, "lpPoint"); // LPPOINT
	ADD_PARAM_NAME("ClipCursor", 1, "lpRect"); // CONST RECT *
	ADD_PARAM_NAME("CloseDesktop", 1, "hDesktop"); // HDESK
	ADD_PARAM_NAME("CloseEncryptedFileRaw", 1, "pvContext"); // PVOID
	ADD_PARAM_NAME("CloseEnhMetaFile", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CloseEventLog", 1, "hEventLog"); // HANDLE
	ADD_PARAM_NAME("CloseFigure", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CloseGestureInfoHandle", 1, "hGestureInfo"); // HGESTUREINFO
	ADD_PARAM_NAME("CloseHandle", 1, "hObject"); // HANDLE
	ADD_PARAM_NAME("CloseMetaFile", 1, "hdc"); // HDC
	ADD_PARAM_NAME("ClosePrinter", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("ClosePrinterToken", 1, "hToken"); // HANDLE
	ADD_PARAM_NAME("ClosePrivateNamespace", 1, "Handle"); // HANDLE
	ADD_PARAM_NAME("ClosePrivateNamespace", 2, "Flags"); // ULONG
	ADD_PARAM_NAME("CloseServiceHandle", 1, "hSCObject"); // SC_HANDLE
	ADD_PARAM_NAME("CloseSpoolFileHandle", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("CloseSpoolFileHandle", 2, "hSpoolFile"); // HANDLE
	ADD_PARAM_NAME("CloseThreadpool", 1, "ptpp"); // PTP_POOL
	ADD_PARAM_NAME("CloseThreadpoolCleanupGroup", 1, "ptpcg"); // PTP_CLEANUP_GROUP
	ADD_PARAM_NAME("CloseThreadpoolCleanupGroupMembers", 1, "ptpcg"); // PTP_CLEANUP_GROUP
	ADD_PARAM_NAME("CloseThreadpoolCleanupGroupMembers", 2, "fCancelPendingCallbacks"); // WINBOOL
	ADD_PARAM_NAME("CloseThreadpoolCleanupGroupMembers", 3, "pvCleanupContext"); // PVOID
	ADD_PARAM_NAME("CloseThreadpoolIo", 1, "pio"); // PTP_IO
	ADD_PARAM_NAME("CloseThreadpoolTimer", 1, "pti"); // PTP_TIMER
	ADD_PARAM_NAME("CloseThreadpoolWait", 1, "pwa"); // PTP_WAIT
	ADD_PARAM_NAME("CloseThreadpoolWork", 1, "pwk"); // PTP_WORK
	ADD_PARAM_NAME("CloseTouchInputHandle", 1, "hTouchInput"); // HANDLE
	ADD_PARAM_NAME("CloseWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("CloseWindowStation", 1, "hWinSta"); // HWINSTA
	ADD_PARAM_NAME("ColorCorrectPalette", 1, "hdc"); // HDC
	ADD_PARAM_NAME("ColorCorrectPalette", 2, "hPal"); // HPALETTE
	ADD_PARAM_NAME("ColorCorrectPalette", 3, "deFirst"); // DWORD
	ADD_PARAM_NAME("ColorCorrectPalette", 4, "num"); // DWORD
	ADD_PARAM_NAME("ColorMatchToTarget", 1, "hdc"); // HDC
	ADD_PARAM_NAME("ColorMatchToTarget", 2, "hdcTarget"); // HDC
	ADD_PARAM_NAME("ColorMatchToTarget", 3, "action"); // DWORD
	ADD_PARAM_NAME("CombineRgn", 1, "hrgnDst"); // HRGN
	ADD_PARAM_NAME("CombineRgn", 2, "hrgnSrc1"); // HRGN
	ADD_PARAM_NAME("CombineRgn", 3, "hrgnSrc2"); // HRGN
	ADD_PARAM_NAME("CombineRgn", 4, "iMode"); // int
	ADD_PARAM_NAME("CombineTransform", 1, "lpxfOut"); // LPXFORM
	ADD_PARAM_NAME("CombineTransform", 2, "lpxf1"); // CONST XFORM *
	ADD_PARAM_NAME("CombineTransform", 3, "lpxf2"); // CONST XFORM *
	ADD_PARAM_NAME("CommConfigDialogA", 1, "lpszName"); // LPCSTR
	ADD_PARAM_NAME("CommConfigDialogA", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("CommConfigDialogA", 3, "lpCC"); // LPCOMMCONFIG
	ADD_PARAM_NAME("CommConfigDialogW", 1, "lpszName"); // LPCWSTR
	ADD_PARAM_NAME("CommConfigDialogW", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("CommConfigDialogW", 3, "lpCC"); // LPCOMMCONFIG
	ADD_PARAM_NAME("CommitSpoolData", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("CommitSpoolData", 2, "hSpoolFile"); // HANDLE
	ADD_PARAM_NAME("CommitSpoolData", 3, "cbCommit"); // DWORD
	ADD_PARAM_NAME("CompareFileTime", 1, "lpFileTime1"); // CONST FILETIME *
	ADD_PARAM_NAME("CompareFileTime", 2, "lpFileTime2"); // CONST FILETIME *
	ADD_PARAM_NAME("CompareStringA", 1, "Locale"); // LCID
	ADD_PARAM_NAME("CompareStringA", 2, "dwCmpFlags"); // DWORD
	ADD_PARAM_NAME("CompareStringA", 3, "lpString1"); // LPCSTR
	ADD_PARAM_NAME("CompareStringA", 4, "cchCount1"); // int
	ADD_PARAM_NAME("CompareStringA", 5, "lpString2"); // LPCSTR
	ADD_PARAM_NAME("CompareStringA", 6, "cchCount2"); // int
	ADD_PARAM_NAME("CompareStringEx", 1, "lpLocaleName"); // LPCWSTR
	ADD_PARAM_NAME("CompareStringEx", 2, "dwCmpFlags"); // DWORD
	ADD_PARAM_NAME("CompareStringEx", 3, "lpString1"); // LPCWSTR
	ADD_PARAM_NAME("CompareStringEx", 4, "cchCount1"); // int
	ADD_PARAM_NAME("CompareStringEx", 5, "lpString2"); // LPCWSTR
	ADD_PARAM_NAME("CompareStringEx", 6, "cchCount2"); // int
	ADD_PARAM_NAME("CompareStringEx", 7, "lpVersionInformation"); // LPNLSVERSIONINFO
	ADD_PARAM_NAME("CompareStringEx", 8, "lpReserved"); // LPVOID
	ADD_PARAM_NAME("CompareStringEx", 9, "lParam"); // LPARAM
	ADD_PARAM_NAME("CompareStringOrdinal", 1, "lpString1"); // LPCWSTR
	ADD_PARAM_NAME("CompareStringOrdinal", 2, "cchCount1"); // int
	ADD_PARAM_NAME("CompareStringOrdinal", 3, "lpString2"); // LPCWSTR
	ADD_PARAM_NAME("CompareStringOrdinal", 4, "cchCount2"); // int
	ADD_PARAM_NAME("CompareStringOrdinal", 5, "bIgnoreCase"); // WINBOOL
	ADD_PARAM_NAME("CompareStringW", 1, "Locale"); // LCID
	ADD_PARAM_NAME("CompareStringW", 2, "dwCmpFlags"); // DWORD
	ADD_PARAM_NAME("CompareStringW", 3, "lpString1"); // LPCWSTR
	ADD_PARAM_NAME("CompareStringW", 4, "cchCount1"); // int
	ADD_PARAM_NAME("CompareStringW", 5, "lpString2"); // LPCWSTR
	ADD_PARAM_NAME("CompareStringW", 6, "cchCount2"); // int
	ADD_PARAM_NAME("ConfigurePortA", 1, "pName"); // LPSTR
	ADD_PARAM_NAME("ConfigurePortA", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("ConfigurePortA", 3, "pPortName"); // LPSTR
	ADD_PARAM_NAME("ConfigurePortW", 1, "pName"); // LPWSTR
	ADD_PARAM_NAME("ConfigurePortW", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("ConfigurePortW", 3, "pPortName"); // LPWSTR
	ADD_PARAM_NAME("ConnectNamedPipe", 1, "hNamedPipe"); // HANDLE
	ADD_PARAM_NAME("ConnectNamedPipe", 2, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("ConnectToPrinterDlg", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("ConnectToPrinterDlg", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("ContinueDebugEvent", 1, "dwProcessId"); // DWORD
	ADD_PARAM_NAME("ContinueDebugEvent", 2, "dwThreadId"); // DWORD
	ADD_PARAM_NAME("ContinueDebugEvent", 3, "dwContinueStatus"); // DWORD
	ADD_PARAM_NAME("ControlService", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("ControlService", 2, "dwControl"); // DWORD
	ADD_PARAM_NAME("ControlService", 3, "lpServiceStatus"); // LPSERVICE_STATUS
	ADD_PARAM_NAME("ControlServiceExA", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("ControlServiceExA", 2, "dwControl"); // DWORD
	ADD_PARAM_NAME("ControlServiceExA", 3, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("ControlServiceExA", 4, "pControlParams"); // PVOID
	ADD_PARAM_NAME("ControlServiceExW", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("ControlServiceExW", 2, "dwControl"); // DWORD
	ADD_PARAM_NAME("ControlServiceExW", 3, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("ControlServiceExW", 4, "pControlParams"); // PVOID
	ADD_PARAM_NAME("ConvertDefaultLocale", 1, "Locale"); // LCID
	ADD_PARAM_NAME("ConvertThreadToFiber", 1, "lpParameter"); // LPVOID
	ADD_PARAM_NAME("ConvertThreadToFiberEx", 1, "lpParameter"); // LPVOID
	ADD_PARAM_NAME("ConvertThreadToFiberEx", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("ConvertToAutoInheritPrivateObjectSecurity", 1, "ParentDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("ConvertToAutoInheritPrivateObjectSecurity", 2, "CurrentSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("ConvertToAutoInheritPrivateObjectSecurity", 3, "NewSecurityDescriptor"); // PSECURITY_DESCRIPTOR *
	ADD_PARAM_NAME("ConvertToAutoInheritPrivateObjectSecurity", 4, "ObjectType"); // GUID *
	ADD_PARAM_NAME("ConvertToAutoInheritPrivateObjectSecurity", 5, "IsDirectoryObject"); // BOOLEAN
	ADD_PARAM_NAME("ConvertToAutoInheritPrivateObjectSecurity", 6, "GenericMapping"); // PGENERIC_MAPPING
	ADD_PARAM_NAME("CopyAcceleratorTableA", 1, "hAccelSrc"); // HACCEL
	ADD_PARAM_NAME("CopyAcceleratorTableA", 2, "lpAccelDst"); // LPACCEL
	ADD_PARAM_NAME("CopyAcceleratorTableA", 3, "cAccelEntries"); // int
	ADD_PARAM_NAME("CopyAcceleratorTableW", 1, "hAccelSrc"); // HACCEL
	ADD_PARAM_NAME("CopyAcceleratorTableW", 2, "lpAccelDst"); // LPACCEL
	ADD_PARAM_NAME("CopyAcceleratorTableW", 3, "cAccelEntries"); // int
	ADD_PARAM_NAME("CopyEnhMetaFileA", 1, "hEnh"); // HENHMETAFILE
	ADD_PARAM_NAME("CopyEnhMetaFileA", 2, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("CopyEnhMetaFileW", 1, "hEnh"); // HENHMETAFILE
	ADD_PARAM_NAME("CopyEnhMetaFileW", 2, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("CopyFileA", 1, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("CopyFileA", 2, "lpNewFileName"); // LPCSTR
	ADD_PARAM_NAME("CopyFileA", 3, "bFailIfExists"); // WINBOOL
	ADD_PARAM_NAME("CopyFileExA", 1, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("CopyFileExA", 2, "lpNewFileName"); // LPCSTR
	ADD_PARAM_NAME("CopyFileExA", 3, "lpProgressRoutine"); // LPPROGRESS_ROUTINE
	ADD_PARAM_NAME("CopyFileExA", 4, "lpData"); // LPVOID
	ADD_PARAM_NAME("CopyFileExA", 5, "pbCancel"); // LPBOOL
	ADD_PARAM_NAME("CopyFileExA", 6, "dwCopyFlags"); // DWORD
	ADD_PARAM_NAME("CopyFileExW", 1, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("CopyFileExW", 2, "lpNewFileName"); // LPCWSTR
	ADD_PARAM_NAME("CopyFileExW", 3, "lpProgressRoutine"); // LPPROGRESS_ROUTINE
	ADD_PARAM_NAME("CopyFileExW", 4, "lpData"); // LPVOID
	ADD_PARAM_NAME("CopyFileExW", 5, "pbCancel"); // LPBOOL
	ADD_PARAM_NAME("CopyFileExW", 6, "dwCopyFlags"); // DWORD
	ADD_PARAM_NAME("CopyFileTransactedA", 1, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("CopyFileTransactedA", 2, "lpNewFileName"); // LPCSTR
	ADD_PARAM_NAME("CopyFileTransactedA", 3, "lpProgressRoutine"); // LPPROGRESS_ROUTINE
	ADD_PARAM_NAME("CopyFileTransactedA", 4, "lpData"); // LPVOID
	ADD_PARAM_NAME("CopyFileTransactedA", 5, "pbCancel"); // LPBOOL
	ADD_PARAM_NAME("CopyFileTransactedA", 6, "dwCopyFlags"); // DWORD
	ADD_PARAM_NAME("CopyFileTransactedA", 7, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CopyFileTransactedW", 1, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("CopyFileTransactedW", 2, "lpNewFileName"); // LPCWSTR
	ADD_PARAM_NAME("CopyFileTransactedW", 3, "lpProgressRoutine"); // LPPROGRESS_ROUTINE
	ADD_PARAM_NAME("CopyFileTransactedW", 4, "lpData"); // LPVOID
	ADD_PARAM_NAME("CopyFileTransactedW", 5, "pbCancel"); // LPBOOL
	ADD_PARAM_NAME("CopyFileTransactedW", 6, "dwCopyFlags"); // DWORD
	ADD_PARAM_NAME("CopyFileTransactedW", 7, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CopyFileW", 1, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("CopyFileW", 2, "lpNewFileName"); // LPCWSTR
	ADD_PARAM_NAME("CopyFileW", 3, "bFailIfExists"); // WINBOOL
	ADD_PARAM_NAME("CopyIcon", 1, "hIcon"); // HICON
	ADD_PARAM_NAME("CopyImage", 1, "h"); // HANDLE
	ADD_PARAM_NAME("CopyImage", 2, "type"); // UINT
	ADD_PARAM_NAME("CopyImage", 3, "cx"); // int
	ADD_PARAM_NAME("CopyImage", 4, "cy"); // int
	ADD_PARAM_NAME("CopyImage", 5, "flags"); // UINT
	ADD_PARAM_NAME("CopyMetaFileA", 1, "hmfSrc"); // HMETAFILE
	ADD_PARAM_NAME("CopyMetaFileA", 2, "lpszFile"); // LPCSTR
	ADD_PARAM_NAME("CopyMetaFileW", 1, "hmfSrc"); // HMETAFILE
	ADD_PARAM_NAME("CopyMetaFileW", 2, "lpszFile"); // LPCWSTR
	ADD_PARAM_NAME("CopyRect", 1, "lprcDst"); // LPRECT
	ADD_PARAM_NAME("CopyRect", 2, "lprcSrc"); // CONST RECT *
	ADD_PARAM_NAME("CopySid", 1, "nDestinationSidLength"); // DWORD
	ADD_PARAM_NAME("CopySid", 2, "pDestinationSid"); // PSID
	ADD_PARAM_NAME("CopySid", 3, "pSourceSid"); // PSID
	ADD_PARAM_NAME("CreateAcceleratorTableA", 1, "paccel"); // LPACCEL
	ADD_PARAM_NAME("CreateAcceleratorTableA", 2, "cAccel"); // int
	ADD_PARAM_NAME("CreateAcceleratorTableW", 1, "paccel"); // LPACCEL
	ADD_PARAM_NAME("CreateAcceleratorTableW", 2, "cAccel"); // int
	ADD_PARAM_NAME("CreateActCtxA", 1, "pActCtx"); // PCACTCTXA
	ADD_PARAM_NAME("CreateActCtxW", 1, "pActCtx"); // PCACTCTXW
	ADD_PARAM_NAME("CreateBitmap", 1, "nWidth"); // int
	ADD_PARAM_NAME("CreateBitmap", 2, "nHeight"); // int
	ADD_PARAM_NAME("CreateBitmap", 3, "nPlanes"); // UINT
	ADD_PARAM_NAME("CreateBitmap", 4, "nBitCount"); // UINT
	ADD_PARAM_NAME("CreateBitmap", 5, "lpBits"); // CONST VOID *
	ADD_PARAM_NAME("CreateBitmapIndirect", 1, "pbm"); // CONST BITMAP *
	ADD_PARAM_NAME("CreateBoundaryDescriptorA", 1, "Name"); // LPCSTR
	ADD_PARAM_NAME("CreateBoundaryDescriptorA", 2, "Flags"); // ULONG
	ADD_PARAM_NAME("CreateBoundaryDescriptorW", 1, "Name"); // LPCWSTR
	ADD_PARAM_NAME("CreateBoundaryDescriptorW", 2, "Flags"); // ULONG
	ADD_PARAM_NAME("CreateBrushIndirect", 1, "plbrush"); // CONST LOGBRUSH *
	ADD_PARAM_NAME("CreateCaret", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("CreateCaret", 2, "hBitmap"); // HBITMAP
	ADD_PARAM_NAME("CreateCaret", 3, "nWidth"); // int
	ADD_PARAM_NAME("CreateCaret", 4, "nHeight"); // int
	ADD_PARAM_NAME("CreateColorSpaceA", 1, "lplcs"); // LPLOGCOLORSPACEA
	ADD_PARAM_NAME("CreateColorSpaceW", 1, "lplcs"); // LPLOGCOLORSPACEW
	ADD_PARAM_NAME("CreateCompatibleBitmap", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CreateCompatibleBitmap", 2, "cx"); // int
	ADD_PARAM_NAME("CreateCompatibleBitmap", 3, "cy"); // int
	ADD_PARAM_NAME("CreateCompatibleDC", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CreateConsoleScreenBuffer", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateConsoleScreenBuffer", 2, "dwShareMode"); // DWORD
	ADD_PARAM_NAME("CreateConsoleScreenBuffer", 3, "lpSecurityAttributes"); // CONST SECURITY_ATTRIBUTES *
	ADD_PARAM_NAME("CreateConsoleScreenBuffer", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateConsoleScreenBuffer", 5, "lpScreenBufferData"); // LPVOID
	ADD_PARAM_NAME("CreateCursor", 1, "hInst"); // HINSTANCE
	ADD_PARAM_NAME("CreateCursor", 2, "xHotSpot"); // int
	ADD_PARAM_NAME("CreateCursor", 3, "yHotSpot"); // int
	ADD_PARAM_NAME("CreateCursor", 4, "nWidth"); // int
	ADD_PARAM_NAME("CreateCursor", 5, "nHeight"); // int
	ADD_PARAM_NAME("CreateCursor", 6, "pvANDPlane"); // CONST VOID *
	ADD_PARAM_NAME("CreateCursor", 7, "pvXORPlane"); // CONST VOID *
	ADD_PARAM_NAME("CreateDCA", 1, "pwszDriver"); // LPCSTR
	ADD_PARAM_NAME("CreateDCA", 2, "pwszDevice"); // LPCSTR
	ADD_PARAM_NAME("CreateDCA", 3, "pszPort"); // LPCSTR
	ADD_PARAM_NAME("CreateDCA", 4, "pdm"); // CONST DEVMODEA *
	ADD_PARAM_NAME("CreateDCW", 1, "pwszDriver"); // LPCWSTR
	ADD_PARAM_NAME("CreateDCW", 2, "pwszDevice"); // LPCWSTR
	ADD_PARAM_NAME("CreateDCW", 3, "pszPort"); // LPCWSTR
	ADD_PARAM_NAME("CreateDCW", 4, "pdm"); // CONST DEVMODEW *
	ADD_PARAM_NAME("CreateDIBPatternBrush", 1, "h"); // HGLOBAL
	ADD_PARAM_NAME("CreateDIBPatternBrush", 2, "iUsage"); // UINT
	ADD_PARAM_NAME("CreateDIBPatternBrushPt", 1, "lpPackedDIB"); // CONST VOID *
	ADD_PARAM_NAME("CreateDIBPatternBrushPt", 2, "iUsage"); // UINT
	ADD_PARAM_NAME("CreateDIBSection", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CreateDIBSection", 2, "lpbmi"); // CONST BITMAPINFO *
	ADD_PARAM_NAME("CreateDIBSection", 3, "usage"); // UINT
	ADD_PARAM_NAME("CreateDIBSection", 4, "ppvBits"); // VOID * *
	ADD_PARAM_NAME("CreateDIBSection", 5, "hSection"); // HANDLE
	ADD_PARAM_NAME("CreateDIBSection", 6, "offset"); // DWORD
	ADD_PARAM_NAME("CreateDIBitmap", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CreateDIBitmap", 2, "pbmih"); // CONST BITMAPINFOHEADER *
	ADD_PARAM_NAME("CreateDIBitmap", 3, "flInit"); // DWORD
	ADD_PARAM_NAME("CreateDIBitmap", 4, "pjBits"); // CONST VOID *
	ADD_PARAM_NAME("CreateDIBitmap", 5, "pbmi"); // CONST BITMAPINFO *
	ADD_PARAM_NAME("CreateDIBitmap", 6, "iUsage"); // UINT
	ADD_PARAM_NAME("CreateDesktopA", 1, "lpszDesktop"); // LPCSTR
	ADD_PARAM_NAME("CreateDesktopA", 2, "lpszDevice"); // LPCSTR
	ADD_PARAM_NAME("CreateDesktopA", 3, "pDevmode"); // LPDEVMODEA
	ADD_PARAM_NAME("CreateDesktopA", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateDesktopA", 5, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("CreateDesktopA", 6, "lpsa"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDesktopExA", 1, "lpszDesktop"); // LPCSTR
	ADD_PARAM_NAME("CreateDesktopExA", 2, "lpszDevice"); // LPCSTR
	ADD_PARAM_NAME("CreateDesktopExA", 3, "pDevmode"); // DEVMODE *
	ADD_PARAM_NAME("CreateDesktopExA", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateDesktopExA", 5, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("CreateDesktopExA", 6, "lpsa"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDesktopExA", 7, "ulHeapSize"); // ULONG
	ADD_PARAM_NAME("CreateDesktopExA", 8, "pvoid"); // PVOID
	ADD_PARAM_NAME("CreateDesktopExW", 1, "lpszDesktop"); // LPCWSTR
	ADD_PARAM_NAME("CreateDesktopExW", 2, "lpszDevice"); // LPCWSTR
	ADD_PARAM_NAME("CreateDesktopExW", 3, "pDevmode"); // DEVMODE *
	ADD_PARAM_NAME("CreateDesktopExW", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateDesktopExW", 5, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("CreateDesktopExW", 6, "lpsa"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDesktopExW", 7, "ulHeapSize"); // ULONG
	ADD_PARAM_NAME("CreateDesktopExW", 8, "pvoid"); // PVOID
	ADD_PARAM_NAME("CreateDesktopW", 1, "lpszDesktop"); // LPCWSTR
	ADD_PARAM_NAME("CreateDesktopW", 2, "lpszDevice"); // LPCWSTR
	ADD_PARAM_NAME("CreateDesktopW", 3, "pDevmode"); // LPDEVMODEW
	ADD_PARAM_NAME("CreateDesktopW", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateDesktopW", 5, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("CreateDesktopW", 6, "lpsa"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDialogIndirectParamA", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateDialogIndirectParamA", 2, "lpTemplate"); // LPCDLGTEMPLATEA
	ADD_PARAM_NAME("CreateDialogIndirectParamA", 3, "hWndParent"); // HWND
	ADD_PARAM_NAME("CreateDialogIndirectParamA", 4, "lpDialogFunc"); // DLGPROC
	ADD_PARAM_NAME("CreateDialogIndirectParamA", 5, "dwInitParam"); // LPARAM
	ADD_PARAM_NAME("CreateDialogIndirectParamW", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateDialogIndirectParamW", 2, "lpTemplate"); // LPCDLGTEMPLATEW
	ADD_PARAM_NAME("CreateDialogIndirectParamW", 3, "hWndParent"); // HWND
	ADD_PARAM_NAME("CreateDialogIndirectParamW", 4, "lpDialogFunc"); // DLGPROC
	ADD_PARAM_NAME("CreateDialogIndirectParamW", 5, "dwInitParam"); // LPARAM
	ADD_PARAM_NAME("CreateDialogParamA", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateDialogParamA", 2, "lpTemplateName"); // LPCSTR
	ADD_PARAM_NAME("CreateDialogParamA", 3, "hWndParent"); // HWND
	ADD_PARAM_NAME("CreateDialogParamA", 4, "lpDialogFunc"); // DLGPROC
	ADD_PARAM_NAME("CreateDialogParamA", 5, "dwInitParam"); // LPARAM
	ADD_PARAM_NAME("CreateDialogParamW", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateDialogParamW", 2, "lpTemplateName"); // LPCWSTR
	ADD_PARAM_NAME("CreateDialogParamW", 3, "hWndParent"); // HWND
	ADD_PARAM_NAME("CreateDialogParamW", 4, "lpDialogFunc"); // DLGPROC
	ADD_PARAM_NAME("CreateDialogParamW", 5, "dwInitParam"); // LPARAM
	ADD_PARAM_NAME("CreateDirectoryA", 1, "lpPathName"); // LPCSTR
	ADD_PARAM_NAME("CreateDirectoryA", 2, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDirectoryExA", 1, "lpTemplateDirectory"); // LPCSTR
	ADD_PARAM_NAME("CreateDirectoryExA", 2, "lpNewDirectory"); // LPCSTR
	ADD_PARAM_NAME("CreateDirectoryExA", 3, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDirectoryExW", 1, "lpTemplateDirectory"); // LPCWSTR
	ADD_PARAM_NAME("CreateDirectoryExW", 2, "lpNewDirectory"); // LPCWSTR
	ADD_PARAM_NAME("CreateDirectoryExW", 3, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDirectoryTransactedA", 1, "lpTemplateDirectory"); // LPCSTR
	ADD_PARAM_NAME("CreateDirectoryTransactedA", 2, "lpNewDirectory"); // LPCSTR
	ADD_PARAM_NAME("CreateDirectoryTransactedA", 3, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDirectoryTransactedA", 4, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CreateDirectoryTransactedW", 1, "lpTemplateDirectory"); // LPCWSTR
	ADD_PARAM_NAME("CreateDirectoryTransactedW", 2, "lpNewDirectory"); // LPCWSTR
	ADD_PARAM_NAME("CreateDirectoryTransactedW", 3, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDirectoryTransactedW", 4, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CreateDirectoryW", 1, "lpPathName"); // LPCWSTR
	ADD_PARAM_NAME("CreateDirectoryW", 2, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateDiscardableBitmap", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CreateDiscardableBitmap", 2, "cx"); // int
	ADD_PARAM_NAME("CreateDiscardableBitmap", 3, "cy"); // int
	ADD_PARAM_NAME("CreateEllipticRgn", 1, "x1"); // int
	ADD_PARAM_NAME("CreateEllipticRgn", 2, "y1"); // int
	ADD_PARAM_NAME("CreateEllipticRgn", 3, "x2"); // int
	ADD_PARAM_NAME("CreateEllipticRgn", 4, "y2"); // int
	ADD_PARAM_NAME("CreateEllipticRgnIndirect", 1, "lprect"); // CONST RECT *
	ADD_PARAM_NAME("CreateEnhMetaFileA", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CreateEnhMetaFileA", 2, "lpFilename"); // LPCSTR
	ADD_PARAM_NAME("CreateEnhMetaFileA", 3, "lprc"); // CONST RECT *
	ADD_PARAM_NAME("CreateEnhMetaFileA", 4, "lpDesc"); // LPCSTR
	ADD_PARAM_NAME("CreateEnhMetaFileW", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CreateEnhMetaFileW", 2, "lpFilename"); // LPCWSTR
	ADD_PARAM_NAME("CreateEnhMetaFileW", 3, "lprc"); // CONST RECT *
	ADD_PARAM_NAME("CreateEnhMetaFileW", 4, "lpDesc"); // LPCWSTR
	ADD_PARAM_NAME("CreateEventA", 1, "lpEventAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateEventA", 2, "bManualReset"); // WINBOOL
	ADD_PARAM_NAME("CreateEventA", 3, "bInitialState"); // WINBOOL
	ADD_PARAM_NAME("CreateEventA", 4, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateEventExA", 1, "lpEventAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateEventExA", 2, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateEventExA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateEventExA", 4, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateEventExW", 1, "lpEventAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateEventExW", 2, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateEventExW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateEventExW", 4, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateEventW", 1, "lpEventAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateEventW", 2, "bManualReset"); // WINBOOL
	ADD_PARAM_NAME("CreateEventW", 3, "bInitialState"); // WINBOOL
	ADD_PARAM_NAME("CreateEventW", 4, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateFiber", 1, "dwStackSize"); // SIZE_T
	ADD_PARAM_NAME("CreateFiber", 2, "lpStartAddress"); // LPFIBER_START_ROUTINE
	ADD_PARAM_NAME("CreateFiber", 3, "lpParameter"); // LPVOID
	ADD_PARAM_NAME("CreateFiberEx", 1, "dwStackCommitSize"); // SIZE_T
	ADD_PARAM_NAME("CreateFiberEx", 2, "dwStackReserveSize"); // SIZE_T
	ADD_PARAM_NAME("CreateFiberEx", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateFiberEx", 4, "lpStartAddress"); // LPFIBER_START_ROUTINE
	ADD_PARAM_NAME("CreateFiberEx", 5, "lpParameter"); // LPVOID
	ADD_PARAM_NAME("CreateFileA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("CreateFileA", 2, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateFileA", 3, "dwShareMode"); // DWORD
	ADD_PARAM_NAME("CreateFileA", 4, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateFileA", 5, "dwCreationDisposition"); // DWORD
	ADD_PARAM_NAME("CreateFileA", 6, "dwFlagsAndAttributes"); // DWORD
	ADD_PARAM_NAME("CreateFileA", 7, "hTemplateFile"); // HANDLE
	ADD_PARAM_NAME("CreateFileMappingA", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("CreateFileMappingA", 2, "lpFileMappingAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateFileMappingA", 3, "flProtect"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingA", 4, "dwMaximumSizeHigh"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingA", 5, "dwMaximumSizeLow"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingA", 6, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateFileMappingNumaA", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("CreateFileMappingNumaA", 2, "lpFileMappingAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateFileMappingNumaA", 3, "flProtect"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingNumaA", 4, "dwMaximumSizeHigh"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingNumaA", 5, "dwMaximumSizeLow"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingNumaA", 6, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateFileMappingNumaA", 7, "nndPreferred"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingNumaW", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("CreateFileMappingNumaW", 2, "lpFileMappingAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateFileMappingNumaW", 3, "flProtect"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingNumaW", 4, "dwMaximumSizeHigh"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingNumaW", 5, "dwMaximumSizeLow"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingNumaW", 6, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateFileMappingNumaW", 7, "nndPreferred"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingW", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("CreateFileMappingW", 2, "lpFileMappingAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateFileMappingW", 3, "flProtect"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingW", 4, "dwMaximumSizeHigh"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingW", 5, "dwMaximumSizeLow"); // DWORD
	ADD_PARAM_NAME("CreateFileMappingW", 6, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateFileTransactedA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("CreateFileTransactedA", 2, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateFileTransactedA", 3, "dwShareMode"); // DWORD
	ADD_PARAM_NAME("CreateFileTransactedA", 4, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateFileTransactedA", 5, "dwCreationDisposition"); // DWORD
	ADD_PARAM_NAME("CreateFileTransactedA", 6, "dwFlagsAndAttributes"); // DWORD
	ADD_PARAM_NAME("CreateFileTransactedA", 7, "hTemplateFile"); // HANDLE
	ADD_PARAM_NAME("CreateFileTransactedA", 8, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CreateFileTransactedA", 9, "pusMiniVersion"); // PUSHORT
	ADD_PARAM_NAME("CreateFileTransactedA", 10, "pExtendedParameter"); // PVOID
	ADD_PARAM_NAME("CreateFileTransactedW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("CreateFileTransactedW", 2, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateFileTransactedW", 3, "dwShareMode"); // DWORD
	ADD_PARAM_NAME("CreateFileTransactedW", 4, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateFileTransactedW", 5, "dwCreationDisposition"); // DWORD
	ADD_PARAM_NAME("CreateFileTransactedW", 6, "dwFlagsAndAttributes"); // DWORD
	ADD_PARAM_NAME("CreateFileTransactedW", 7, "hTemplateFile"); // HANDLE
	ADD_PARAM_NAME("CreateFileTransactedW", 8, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CreateFileTransactedW", 9, "pusMiniVersion"); // PUSHORT
	ADD_PARAM_NAME("CreateFileTransactedW", 10, "pExtendedParameter"); // PVOID
	ADD_PARAM_NAME("CreateFileW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("CreateFileW", 2, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateFileW", 3, "dwShareMode"); // DWORD
	ADD_PARAM_NAME("CreateFileW", 4, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateFileW", 5, "dwCreationDisposition"); // DWORD
	ADD_PARAM_NAME("CreateFileW", 6, "dwFlagsAndAttributes"); // DWORD
	ADD_PARAM_NAME("CreateFileW", 7, "hTemplateFile"); // HANDLE
	ADD_PARAM_NAME("CreateFontA", 1, "cHeight"); // int
	ADD_PARAM_NAME("CreateFontA", 2, "cWidth"); // int
	ADD_PARAM_NAME("CreateFontA", 3, "cEscapement"); // int
	ADD_PARAM_NAME("CreateFontA", 4, "cOrientation"); // int
	ADD_PARAM_NAME("CreateFontA", 5, "cWeight"); // int
	ADD_PARAM_NAME("CreateFontA", 6, "bItalic"); // DWORD
	ADD_PARAM_NAME("CreateFontA", 7, "bUnderline"); // DWORD
	ADD_PARAM_NAME("CreateFontA", 8, "bStrikeOut"); // DWORD
	ADD_PARAM_NAME("CreateFontA", 9, "iCharSet"); // DWORD
	ADD_PARAM_NAME("CreateFontA", 10, "iOutPrecision"); // DWORD
	ADD_PARAM_NAME("CreateFontA", 11, "iClipPrecision"); // DWORD
	ADD_PARAM_NAME("CreateFontA", 12, "iQuality"); // DWORD
	ADD_PARAM_NAME("CreateFontA", 13, "iPitchAndFamily"); // DWORD
	ADD_PARAM_NAME("CreateFontA", 14, "pszFaceName"); // LPCSTR
	ADD_PARAM_NAME("CreateFontIndirectA", 1, "lplf"); // CONST LOGFONTA *
	ADD_PARAM_NAME("CreateFontIndirectExA", 1, "lplf"); // CONST LOGFONTA *
	ADD_PARAM_NAME("CreateFontIndirectExW", 1, "lplf"); // CONST LOGFONTW *
	ADD_PARAM_NAME("CreateFontIndirectW", 1, "lplf"); // CONST LOGFONTW *
	ADD_PARAM_NAME("CreateFontW", 1, "cHeight"); // int
	ADD_PARAM_NAME("CreateFontW", 2, "cWidth"); // int
	ADD_PARAM_NAME("CreateFontW", 3, "cEscapement"); // int
	ADD_PARAM_NAME("CreateFontW", 4, "cOrientation"); // int
	ADD_PARAM_NAME("CreateFontW", 5, "cWeight"); // int
	ADD_PARAM_NAME("CreateFontW", 6, "bItalic"); // DWORD
	ADD_PARAM_NAME("CreateFontW", 7, "bUnderline"); // DWORD
	ADD_PARAM_NAME("CreateFontW", 8, "bStrikeOut"); // DWORD
	ADD_PARAM_NAME("CreateFontW", 9, "iCharSet"); // DWORD
	ADD_PARAM_NAME("CreateFontW", 10, "iOutPrecision"); // DWORD
	ADD_PARAM_NAME("CreateFontW", 11, "iClipPrecision"); // DWORD
	ADD_PARAM_NAME("CreateFontW", 12, "iQuality"); // DWORD
	ADD_PARAM_NAME("CreateFontW", 13, "iPitchAndFamily"); // DWORD
	ADD_PARAM_NAME("CreateFontW", 14, "pszFaceName"); // LPCWSTR
	ADD_PARAM_NAME("CreateHalftonePalette", 1, "hdc"); // HDC
	ADD_PARAM_NAME("CreateHardLinkA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("CreateHardLinkA", 2, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("CreateHardLinkA", 3, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateHardLinkTransactedA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("CreateHardLinkTransactedA", 2, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("CreateHardLinkTransactedA", 3, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateHardLinkTransactedA", 4, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CreateHardLinkTransactedW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("CreateHardLinkTransactedW", 2, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("CreateHardLinkTransactedW", 3, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateHardLinkTransactedW", 4, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CreateHardLinkW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("CreateHardLinkW", 2, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("CreateHardLinkW", 3, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateHatchBrush", 1, "iHatch"); // int
	ADD_PARAM_NAME("CreateHatchBrush", 2, "color"); // COLORREF
	ADD_PARAM_NAME("CreateICA", 1, "pszDriver"); // LPCSTR
	ADD_PARAM_NAME("CreateICA", 2, "pszDevice"); // LPCSTR
	ADD_PARAM_NAME("CreateICA", 3, "pszPort"); // LPCSTR
	ADD_PARAM_NAME("CreateICA", 4, "pdm"); // CONST DEVMODEA *
	ADD_PARAM_NAME("CreateICW", 1, "pszDriver"); // LPCWSTR
	ADD_PARAM_NAME("CreateICW", 2, "pszDevice"); // LPCWSTR
	ADD_PARAM_NAME("CreateICW", 3, "pszPort"); // LPCWSTR
	ADD_PARAM_NAME("CreateICW", 4, "pdm"); // CONST DEVMODEW *
	ADD_PARAM_NAME("CreateIcon", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateIcon", 2, "nWidth"); // int
	ADD_PARAM_NAME("CreateIcon", 3, "nHeight"); // int
	ADD_PARAM_NAME("CreateIcon", 4, "cPlanes"); // BYTE
	ADD_PARAM_NAME("CreateIcon", 5, "cBitsPixel"); // BYTE
	ADD_PARAM_NAME("CreateIcon", 6, "lpbANDbits"); // CONST BYTE *
	ADD_PARAM_NAME("CreateIcon", 7, "lpbXORbits"); // CONST BYTE *
	ADD_PARAM_NAME("CreateIconFromResource", 1, "presbits"); // PBYTE
	ADD_PARAM_NAME("CreateIconFromResource", 2, "dwResSize"); // DWORD
	ADD_PARAM_NAME("CreateIconFromResource", 3, "fIcon"); // WINBOOL
	ADD_PARAM_NAME("CreateIconFromResource", 4, "dwVer"); // DWORD
	ADD_PARAM_NAME("CreateIconFromResourceEx", 1, "presbits"); // PBYTE
	ADD_PARAM_NAME("CreateIconFromResourceEx", 2, "dwResSize"); // DWORD
	ADD_PARAM_NAME("CreateIconFromResourceEx", 3, "fIcon"); // WINBOOL
	ADD_PARAM_NAME("CreateIconFromResourceEx", 4, "dwVer"); // DWORD
	ADD_PARAM_NAME("CreateIconFromResourceEx", 5, "cxDesired"); // int
	ADD_PARAM_NAME("CreateIconFromResourceEx", 6, "cyDesired"); // int
	ADD_PARAM_NAME("CreateIconFromResourceEx", 7, "Flags"); // UINT
	ADD_PARAM_NAME("CreateIconIndirect", 1, "piconinfo"); // PICONINFO
	ADD_PARAM_NAME("CreateIoCompletionPort", 1, "FileHandle"); // HANDLE
	ADD_PARAM_NAME("CreateIoCompletionPort", 2, "ExistingCompletionPort"); // HANDLE
	ADD_PARAM_NAME("CreateIoCompletionPort", 3, "CompletionKey"); // ULONG_PTR
	ADD_PARAM_NAME("CreateIoCompletionPort", 4, "NumberOfConcurrentThreads"); // DWORD
	ADD_PARAM_NAME("CreateJobObjectA", 1, "lpJobAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateJobObjectA", 2, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateJobObjectW", 1, "lpJobAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateJobObjectW", 2, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateJobSet", 1, "NumJob"); // ULONG
	ADD_PARAM_NAME("CreateJobSet", 2, "UserJobSet"); // PJOB_SET_ARRAY
	ADD_PARAM_NAME("CreateJobSet", 3, "Flags"); // ULONG
	ADD_PARAM_NAME("CreateMDIWindowA", 1, "lpClassName"); // LPCSTR
	ADD_PARAM_NAME("CreateMDIWindowA", 2, "lpWindowName"); // LPCSTR
	ADD_PARAM_NAME("CreateMDIWindowA", 3, "dwStyle"); // DWORD
	ADD_PARAM_NAME("CreateMDIWindowA", 4, "X"); // int
	ADD_PARAM_NAME("CreateMDIWindowA", 5, "Y"); // int
	ADD_PARAM_NAME("CreateMDIWindowA", 6, "nWidth"); // int
	ADD_PARAM_NAME("CreateMDIWindowA", 7, "nHeight"); // int
	ADD_PARAM_NAME("CreateMDIWindowA", 8, "hWndParent"); // HWND
	ADD_PARAM_NAME("CreateMDIWindowA", 9, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateMDIWindowA", 10, "lParam"); // LPARAM
	ADD_PARAM_NAME("CreateMDIWindowW", 1, "lpClassName"); // LPCWSTR
	ADD_PARAM_NAME("CreateMDIWindowW", 2, "lpWindowName"); // LPCWSTR
	ADD_PARAM_NAME("CreateMDIWindowW", 3, "dwStyle"); // DWORD
	ADD_PARAM_NAME("CreateMDIWindowW", 4, "X"); // int
	ADD_PARAM_NAME("CreateMDIWindowW", 5, "Y"); // int
	ADD_PARAM_NAME("CreateMDIWindowW", 6, "nWidth"); // int
	ADD_PARAM_NAME("CreateMDIWindowW", 7, "nHeight"); // int
	ADD_PARAM_NAME("CreateMDIWindowW", 8, "hWndParent"); // HWND
	ADD_PARAM_NAME("CreateMDIWindowW", 9, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateMDIWindowW", 10, "lParam"); // LPARAM
	ADD_PARAM_NAME("CreateMailslotA", 1, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateMailslotA", 2, "nMaxMessageSize"); // DWORD
	ADD_PARAM_NAME("CreateMailslotA", 3, "lReadTimeout"); // DWORD
	ADD_PARAM_NAME("CreateMailslotA", 4, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateMailslotW", 1, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateMailslotW", 2, "nMaxMessageSize"); // DWORD
	ADD_PARAM_NAME("CreateMailslotW", 3, "lReadTimeout"); // DWORD
	ADD_PARAM_NAME("CreateMailslotW", 4, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateMemoryResourceNotification", 1, "NotificationType"); // MEMORY_RESOURCE_NOTIFICATION_TYPE
	ADD_PARAM_NAME("CreateMetaFileA", 1, "pszFile"); // LPCSTR
	ADD_PARAM_NAME("CreateMetaFileW", 1, "pszFile"); // LPCWSTR
	ADD_PARAM_NAME("CreateMutexA", 1, "lpMutexAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateMutexA", 2, "bInitialOwner"); // WINBOOL
	ADD_PARAM_NAME("CreateMutexA", 3, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateMutexExA", 1, "lpMutexAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateMutexExA", 2, "lpName"); // LPCTSTR
	ADD_PARAM_NAME("CreateMutexExA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateMutexExA", 4, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateMutexExW", 1, "lpMutexAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateMutexExW", 2, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateMutexExW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateMutexExW", 4, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateMutexW", 1, "lpMutexAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateMutexW", 2, "bInitialOwner"); // WINBOOL
	ADD_PARAM_NAME("CreateMutexW", 3, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateNamedPipeA", 1, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateNamedPipeA", 2, "dwOpenMode"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeA", 3, "dwPipeMode"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeA", 4, "nMaxInstances"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeA", 5, "nOutBufferSize"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeA", 6, "nInBufferSize"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeA", 7, "nDefaultTimeOut"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeA", 8, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateNamedPipeW", 1, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateNamedPipeW", 2, "dwOpenMode"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeW", 3, "dwPipeMode"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeW", 4, "nMaxInstances"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeW", 5, "nOutBufferSize"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeW", 6, "nInBufferSize"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeW", 7, "nDefaultTimeOut"); // DWORD
	ADD_PARAM_NAME("CreateNamedPipeW", 8, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreatePalette", 1, "plpal"); // CONST LOGPALETTE *
	ADD_PARAM_NAME("CreatePatternBrush", 1, "hbm"); // HBITMAP
	ADD_PARAM_NAME("CreatePen", 1, "iStyle"); // int
	ADD_PARAM_NAME("CreatePen", 2, "cWidth"); // int
	ADD_PARAM_NAME("CreatePen", 3, "color"); // COLORREF
	ADD_PARAM_NAME("CreatePenIndirect", 1, "plpen"); // CONST LOGPEN *
	ADD_PARAM_NAME("CreatePipe", 1, "hReadPipe"); // PHANDLE
	ADD_PARAM_NAME("CreatePipe", 2, "hWritePipe"); // PHANDLE
	ADD_PARAM_NAME("CreatePipe", 3, "lpPipeAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreatePipe", 4, "nSize"); // DWORD
	ADD_PARAM_NAME("CreatePolyPolygonRgn", 1, "pptl"); // CONST POINT *
	ADD_PARAM_NAME("CreatePolyPolygonRgn", 2, "pc"); // CONST INT *
	ADD_PARAM_NAME("CreatePolyPolygonRgn", 3, "cPoly"); // int
	ADD_PARAM_NAME("CreatePolyPolygonRgn", 4, "iMode"); // int
	ADD_PARAM_NAME("CreatePolygonRgn", 1, "pptl"); // CONST POINT *
	ADD_PARAM_NAME("CreatePolygonRgn", 2, "cPoint"); // int
	ADD_PARAM_NAME("CreatePolygonRgn", 3, "iMode"); // int
	ADD_PARAM_NAME("CreatePrinterIC", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("CreatePrinterIC", 2, "pDevMode"); // LPDEVMODEW
	ADD_PARAM_NAME("CreatePrivateNamespaceA", 1, "lpPrivateNamespaceAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreatePrivateNamespaceA", 2, "lpBoundaryDescriptor"); // LPVOID
	ADD_PARAM_NAME("CreatePrivateNamespaceA", 3, "lpAliasPrefix"); // LPCSTR
	ADD_PARAM_NAME("CreatePrivateNamespaceW", 1, "lpPrivateNamespaceAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreatePrivateNamespaceW", 2, "lpBoundaryDescriptor"); // LPVOID
	ADD_PARAM_NAME("CreatePrivateNamespaceW", 3, "lpAliasPrefix"); // LPCWSTR
	ADD_PARAM_NAME("CreatePrivateObjectSecurity", 1, "ParentDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("CreatePrivateObjectSecurity", 2, "CreatorDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("CreatePrivateObjectSecurity", 3, "NewDescriptor"); // PSECURITY_DESCRIPTOR *
	ADD_PARAM_NAME("CreatePrivateObjectSecurity", 4, "IsDirectoryObject"); // WINBOOL
	ADD_PARAM_NAME("CreatePrivateObjectSecurity", 5, "Token"); // HANDLE
	ADD_PARAM_NAME("CreatePrivateObjectSecurity", 6, "GenericMapping"); // PGENERIC_MAPPING
	ADD_PARAM_NAME("CreatePrivateObjectSecurityEx", 1, "ParentDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("CreatePrivateObjectSecurityEx", 2, "CreatorDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("CreatePrivateObjectSecurityEx", 3, "NewDescriptor"); // PSECURITY_DESCRIPTOR *
	ADD_PARAM_NAME("CreatePrivateObjectSecurityEx", 4, "ObjectType"); // GUID *
	ADD_PARAM_NAME("CreatePrivateObjectSecurityEx", 5, "IsContainerObject"); // WINBOOL
	ADD_PARAM_NAME("CreatePrivateObjectSecurityEx", 6, "AutoInheritFlags"); // ULONG
	ADD_PARAM_NAME("CreatePrivateObjectSecurityEx", 7, "Token"); // HANDLE
	ADD_PARAM_NAME("CreatePrivateObjectSecurityEx", 8, "GenericMapping"); // PGENERIC_MAPPING
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 1, "ParentDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 2, "CreatorDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 3, "NewDescriptor"); // PSECURITY_DESCRIPTOR *
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 4, "ObjectTypes"); // GUID * *
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 5, "GuidCount"); // ULONG
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 6, "IsContainerObject"); // WINBOOL
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 7, "AutoInheritFlags"); // ULONG
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 8, "Token"); // HANDLE
	ADD_PARAM_NAME("CreatePrivateObjectSecurityWithMultipleInheritance", 9, "GenericMapping"); // PGENERIC_MAPPING
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
