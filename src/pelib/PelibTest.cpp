/*****************************************************************************/
/* PelibTest.cpp                          Copyright (c) Ladislav Zezula 2020 */
/*---------------------------------------------------------------------------*/
/* Testing suite for pelib. Windows platform only.                           */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 30.05.20  1.00  Lad  Created                                              */
/*****************************************************************************/

#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif

#ifdef _MSC_VER
#pragma warning(disable:4091)               // imagehlp.h(1873) : warning C4091 : 'typedef ' : ignored on left of '' when no variable is declared
#endif  // _MSC_VER

#define WIN32_NO_STATUS 
#include <assert.h>
#include <tchar.h>
#include <stdio.h>
#include <conio.h>
#include <io.h>
#include <windows.h>
#undef WIN32_NO_STATUS
#include <strsafe.h>
#include <imagehlp.h>
#include <ntstatus.h>

#include <iostream>
#include <fstream>

#include "ImageLoader.h"
#include "Utils.h"
#include "ntdll.h"

//-----------------------------------------------------------------------------
// Local variables

OSVERSIONINFO g_osvi = {0};
DWORD g_dwFilesTested = 0;
DWORD g_dwFilesMatched = 0;
DWORD g_dwFilesMismatch = 0;
DWORD g_dwWinVer = 0;

#define WIN32_PAGE_SIZE 0x1000

#ifndef SEC_IMAGE_NO_EXECUTE
#define SEC_IMAGE_NO_EXECUTE 0x11000000
#endif

//-----------------------------------------------------------------------------
// Local functions

static LPCTSTR GetStringArg(int argIndex, LPCTSTR szDefault = NULL)
{
	if(__argc > argIndex)
	{
		if(__targv[argIndex] && __targv[argIndex][0])
		{
			return __targv[argIndex];
		}
	}

	return szDefault;
}

static int PrintError(LPCTSTR szFormat, ...)
{
	va_list argList;

	va_start(argList, szFormat);
	_vtprintf(szFormat, argList);
	va_end(argList);

	return 3;
}

static void PrintCompareResult(LPCTSTR szFileName, LPCTSTR format, ...)
{
	va_list argList;

	va_start(argList, format);
	_tprintf(_T("%s\n * "), szFileName);
	_vtprintf(format, argList);
	_tprintf(_T("\n"));
	va_end(argList);
}

static ULONG64 GetImageBase(LPBYTE pbImage)
{
	PIMAGE_NT_HEADERS64 pNtHdrs64;
	PIMAGE_NT_HEADERS32 pNtHdrs32;
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pbImage;

	// Make sure that the image base is valid
	if(pbImage != NULL)
	{
		// Try 64-bit image
		pNtHdrs64 = (PIMAGE_NT_HEADERS64)(pbImage + pDosHdr->e_lfanew);
		if(pNtHdrs64->Signature == IMAGE_NT_SIGNATURE && pNtHdrs64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			return pNtHdrs64->OptionalHeader.ImageBase;
		}

		// Try 32-bit image
		pNtHdrs32 = (PIMAGE_NT_HEADERS32)(pbImage + pDosHdr->e_lfanew);
		if(pNtHdrs32->Signature == IMAGE_NT_SIGNATURE && pNtHdrs32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			return pNtHdrs32->OptionalHeader.ImageBase;
		}
	}

	return 0;
}

static bool _cdecl VerifyMemoryAddress(void * ptr, size_t length)
{
	MEMORY_BASIC_INFORMATION mbi;

	// Query the virtual memory
	if(!VirtualQuery(ptr, &mbi, length))
		return false;
	return (mbi.Protect > PAGE_NOACCESS);
}

static void WriteDataToFile(LPCTSTR szFileName, LPBYTE pbData, DWORD cbData)
{
	HANDLE hFile;
	DWORD dwWritten = 0;

	hFile = CreateFile(szFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		WriteFile(hFile, pbData, cbData, &dwWritten, NULL);
		CloseHandle(hFile);
	}
}

static bool CopySampleToFolder(LPCTSTR szFileName, LPCTSTR szCopyFolder)
{
	TCHAR szTargetName[MAX_PATH];
	TCHAR szPlainName[MAX_PATH];
	LPTSTR szExtension;
	int nTryCount = 1;

	if(szCopyFolder && szCopyFolder[0])
	{
		// Split the name to plain name and extension
		StringCchCopy(szPlainName, _countof(szPlainName), GetPlainName(szFileName));
		szExtension = GetFileExtension(szPlainName);
		if(szExtension[0] == _T('.'))
			*szExtension++ = 0;

		// The first try
		StringCchPrintf(szTargetName, _countof(szTargetName), _T("%s\\%s.%s"), szCopyFolder, szPlainName, szExtension);

		// Keep working
		while(nTryCount < 100)
		{
			// If the target file doesn't exist, copy it
			if(GetFileAttributes(szTargetName) == INVALID_FILE_ATTRIBUTES)
			{
				return CopyFile(szFileName, szTargetName, TRUE);
			}

			// Create next name iteration
			StringCchPrintf(szTargetName, _countof(szTargetName), _T("%s\\%s_%03u.%s"), szCopyFolder, szPlainName, nTryCount, szExtension);
			nTryCount++;
		}
	}

	return false;
}

static NTSTATUS MapFileByWindowsLoader(LPCTSTR szFileName, LPBYTE * PtrPointerToImage, LPDWORD PtrSizeOfImage)
{
	OBJECT_ATTRIBUTES ObjAttr;
	LARGE_INTEGER MappedSize = {0};
	LARGE_INTEGER ByteOffset = {0};
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE SectionHandle = NULL;
	HANDLE FileHandle;
	SIZE_T ViewSize = 0;
	PVOID BaseAddress = NULL;
	ULONG AllocationAttributes = SEC_IMAGE;

	// Use SEC_IMAGE_NO_EXECUTE on Windows 10 or newer
//	if(g_dwWinVer >= 0x0601)
//		AllocationAttributes = SEC_IMAGE_NO_EXECUTE;

	// Open the file for creating image
	FileHandle = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if(FileHandle != INVALID_HANDLE_VALUE)
	{
		InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);

#ifndef _DEBUG
		if(IsDebuggerPresent() == FALSE)
		{
			//__debugbreak();
		}
#endif

		Status = NtCreateSection(&SectionHandle, 
								  SECTION_MAP_READ,
								 &ObjAttr,
								 &MappedSize,
								  PAGE_READONLY,
								  AllocationAttributes,
								  FileHandle);

		if(NT_SUCCESS(Status))
		{
			// Map the entire file to memory
			Status = NtMapViewOfSection(SectionHandle,
										NtCurrentProcess(),
									   &BaseAddress,
										0,
										0,
									   &ByteOffset,
									   &ViewSize,
										ViewShare,
										0,
										PAGE_READONLY);
			NtClose(SectionHandle);
		}

		CloseHandle(FileHandle);
	}

	// Give the results
	PtrPointerToImage[0] = (LPBYTE)BaseAddress;
	PtrSizeOfImage[0] = (DWORD)ViewSize;
	return Status;
}

void MapAndCompareImage(LPCTSTR szFileName, LPBYTE pbImageWin, DWORD cbImageWin, PeLib::PELIB_IMAGE_COMPARE & ImageCompare)
{
	ULONG64 WinImageBase = GetImageBase(pbImageWin);
	LPSTR szFileNameA;
	size_t nLength = _tcslen(szFileName) + 1;
	DWORD SizeOfImage;
	DWORD loaderMode = PeLib::LoaderModeWindows7;

	// Set the proper loader mode
	if(g_dwWinVer >= 0x0602)
		loaderMode = PeLib::LoaderModeWindows10;

	// Create ANSI name of the file
	if((szFileNameA = new char[nLength]) != NULL)
	{
		PeLib::ImageLoader imageLoader(loaderMode);

		// Convert to UNICODE
		WideCharToMultiByte(CP_ACP, 0, szFileName, -1, szFileNameA, (int)nLength, NULL, NULL);

		// Load the image using our section reader
		if(imageLoader.Load(szFileNameA) == 0)
		{
			if((SizeOfImage = imageLoader.getSizeOfImageAligned()) != 0)
			{
				// Windows Vista loader performs relocation in the kernel.
				// To be able to compare images, we need to relocate ours
				if(loaderMode >= PeLib::LoaderModeWindows7)
					imageLoader.relocateImage(WinImageBase);

				// Compare the image with the mapped Windows image
				if(pbImageWin && cbImageWin)
					imageLoader.compareWithWindowsMappedImage(ImageCompare, pbImageWin, cbImageWin);

				// Dump the image, if not equal
				if(ImageCompare.compareResult == PeLib::ImagesDifferentPageValue && ImageCompare.dumpIfNotEqual != nullptr)
					imageLoader.dumpImage(ImageCompare.dumpIfNotEqual);
			}
		}

		delete [] szFileNameA;
	}
}

static void TestFile(LPCTSTR szFileName, LPCTSTR szCopyFolder)
{
	PeLib::PELIB_IMAGE_COMPARE ImageCompare{};
	NTSTATUS Status;
	LPBYTE pbImageWin = NULL;
	DWORD cbImageWin = 0;
	TCHAR szErrMsg[0x200];
	bool bNeedDumpBothImages = false;
	bool bNotEnoughMemory = false;
	bool bCompareOK = true;

	// Update the console title
	StringCchPrintf(szErrMsg, _countof(szErrMsg), _T("%u files checked - Section Reader Test"), g_dwFilesTested);
	SetConsoleTitle(szErrMsg);
	g_dwFilesTested++;

	// Frame the reading by exception
	__try
	{
		// Load the image using Windows loader
		Status = MapFileByWindowsLoader(szFileName, &pbImageWin, &cbImageWin);

		// Only continue the comparison if Windows loader didn't report
		// an out-of-memory error code, because we cannot reliably verify anything
		if(Status != STATUS_NO_MEMORY)
		{
			// Load the PE file using our reader
			ImageCompare.PfnVerifyAddress = VerifyMemoryAddress;
			//ImageCompare.dumpIfNotEqual = "C:\\MappedImageOur.bin";
			MapAndCompareImage(szFileName, pbImageWin, cbImageWin, ImageCompare);
			bCompareOK = (ImageCompare.compareResult == PeLib::ImagesEqual);

			// Print the result
			switch(ImageCompare.compareResult)
			{
				case PeLib::ImagesEqual:
					break;

				case PeLib::ImagesWindowsLoadedWeDidnt:
					PrintCompareResult(szFileName, _T("Windows mapped the image OK, but we didn't"));
					break;

				case PeLib::ImagesWindowsDidntLoadWeDid:
					PrintCompareResult(szFileName, _T("Windows didn't map the image (%08x), but we did"), Status);
					break;

				case PeLib::ImagesDifferentSize:
					PrintCompareResult(szFileName, _T("SizeOfImage mismatch"));
					break;

				case PeLib::ImagesDifferentPageAccess:
					PrintCompareResult(szFileName, _T("Image page accessibility mismatch at offset %08x"), ImageCompare.differenceOffset);
					break;

				case PeLib::ImagesDifferentPageValue:
					PrintCompareResult(szFileName, _T("Image mismatch at offset %08x"), ImageCompare.differenceOffset);
					bNeedDumpBothImages = true;
					break;
			}

			// Dump both images for fuhrter investigation, if needed
			if(ImageCompare.dumpIfNotEqual && bNeedDumpBothImages)
			{
				WriteDataToFile(_T("C:\\MappedImageWin.bin"), pbImageWin, cbImageWin);
				_tprintf(_T(" * Images dumped. Press any key to continue ...\n"));
				_getch();
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		_tprintf(_T("%s\n * Exception when processing image\n"), szFileName);
	}

	// Free resources
	if(pbImageWin != NULL)
		NtUnmapViewOfSection(NtCurrentProcess(), pbImageWin);
	pbImageWin = NULL;

	// Copy the file to a link folder, if compare failed
	if(bCompareOK == false && bNotEnoughMemory == false)
	{
		CopySampleToFolder(szFileName, szCopyFolder);
		g_dwFilesMismatch++;
	}
	else
	{
		g_dwFilesMatched++;
	}
}

static void TestFolder(LPCTSTR szFolderName, LPCTSTR szCopyFolder)
{
	WIN32_FIND_DATA wf;
	HANDLE hFind;
	TCHAR szNameBuff[MAX_PATH];
	BOOL bFound = TRUE;

	// Initiate file search
	StringCchPrintf(szNameBuff, _countof(szNameBuff), _T("%s\\*"), szFolderName);
	hFind = FindFirstFile(szNameBuff, &wf);
	if(hFind != INVALID_HANDLE_VALUE)
	{
		// Keep searching
		while(bFound)
		{
			// Exclude the "." and ".." directory entries
			if(_tcscmp(wf.cFileName, _T(".")) && _tcscmp(wf.cFileName, _T("..")))
			{
				// Construct the full name
				StringCchPrintf(szNameBuff, _countof(szNameBuff), _T("%s\\%s"), szFolderName, wf.cFileName);

				// Folder/file?
				if(wf.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					TestFolder(szNameBuff, szCopyFolder);
				}
				else
				{
					TestFile(szNameBuff, szCopyFolder);
				}
			}

			// Search the next file/folder
			bFound = FindNextFile(hFind, &wf);
		}

		// Close the find handle
		FindClose(hFind);
	}
}

//-----------------------------------------------------------------------------
// The 'main' function

int _tmain(void)
{
	LPCTSTR szFileOrFolder = NULL;
	LPCTSTR szCopyFolder = NULL;
	DWORD dwAttr;

	// Get Windows version
	g_osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&g_osvi);
	g_dwWinVer = (g_osvi.dwMajorVersion << 0x08) | g_osvi.dwMinorVersion;

	// ARG1: Name of file/folder
	szFileOrFolder = GetStringArg(1, _T("."));

	// ARG2: Name of collection folder
	szCopyFolder = GetStringArg(2, NULL);

	// For stopping in the debugger
	//_tprintf(_T("Press any key to begin ...\n"));
	//_getch();

	// Check whether the argument is folder or file
	dwAttr = GetFileAttributes(szFileOrFolder);
	if(dwAttr == INVALID_FILE_ATTRIBUTES)
		return PrintError(_T("Failed to open \"%s\" (error code %u)\n"), szFileOrFolder, GetLastError());

	// If a folder, we're gonna recursively go over all files
	if(dwAttr & FILE_ATTRIBUTE_DIRECTORY)
	{
		TestFolder(szFileOrFolder, szCopyFolder);
	}
	else
	{
		TestFile(szFileOrFolder, szCopyFolder);
	}

	// Print summary
	_tprintf(_T("\n=[*]= Summary ==========================================\n"));
	_tprintf(_T(" * Files tested: %u\n"), g_dwFilesTested);
	_tprintf(_T(" * Files matched: %u\n"), g_dwFilesMatched);
	_tprintf(_T(" * Files mismatched: %u\n\n"), g_dwFilesMismatch);
	SetConsoleTitle(_T("Complete - Section Reader Test"));

	// Exit
	_tprintf(_T("Press any key to exit ...\n"));
	_getch();
}

