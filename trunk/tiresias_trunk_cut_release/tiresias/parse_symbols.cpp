//© 2009-2012 The MITRE Corporation. ALL RIGHTS RESERVED.
//Permission to use, copy, modify, and distribute this software for any
//purpose with or without fee is hereby granted, provided that the above
//copyright notice and this permission notice appear in all copies.
//THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#include "server_tiresias_protocol.h"
#include "parse_symbols.h"
#include "database_mysql2.h"

IDiaDataSource *g_pDiaDataSource;
IDiaSession *g_pDiaSession;
IDiaSymbol *g_pGlobalSymbol;
DWORD g_dwMachineType = CV_CFL_80386;

//Currently uses DIA to resolve symbols in binary that are necessary
int ParseSymbolInformationForBinary(int binID, st_msg_t *binary, char *binary_file_path) {
	unsigned int i;
	char windbgModuleName[128];
	int ret;
	vector<resolved_symbol_t *> resolvedBinaryEntries;
	vector<dia_symbol_t *> resolvedSymbols;

	
	//setup windbgModuleName to contain what the module name would look like
	//in windbg output so we can compare with module names expected in the
	//configuration files. I.E hal.dll -> hal, ntoskrnl.exe -> nt
	memset(windbgModuleName,0x0,128);
	
	//special case for nt
	if (!_strnicmp(binary->bNameA,"ntoskrnl.exe", MAX_BIN_NAME_LEN) || !_strnicmp(binary->bNameA, "ntkrnlpa.exe",MAX_BIN_NAME_LEN))
	{
		memcpy(&windbgModuleName,"nt",strlen("nt"));
	} 
	//else we just drop the extension....
	else {
		for (i=0;i<strlen(binary->bNameA) && i < 128;i++) {
			if (binary->bNameA[i] == '.')
				break;
			windbgModuleName[i] = binary->bNameA[i];
		}
	}
	
	for (i=0;i<gExpectedBinarySymbols.size();i++)
	{
		expected_symbol_t entry = (expected_symbol_t)gExpectedBinarySymbols.at(i);

		//if the expected symbol is contained in this binary
		if (!_strnicmp(entry.moduleName,windbgModuleName,MAX_BIN_NAME_LEN))
		{
			resolved_symbol_t *resolved_entry = (resolved_symbol_t *)malloc(sizeof(resolved_symbol_t));
			dia_symbol_t *sym = (dia_symbol_t *)malloc(sizeof(dia_symbol_t));
			if(sym != NULL){
				sym->symbolName = (char *)malloc(strlen(entry.symbolName)+1);
				if(sym->symbolName != NULL){
					memcpy(sym->symbolName, entry.symbolName, strlen(entry.symbolName)+1);
				}
				sym->rva = -1;
			}

			if(sym != NULL && resolved_entry != NULL){
				resolved_entry->binID = binID;
				resolved_entry->index = entry.index; //should always be 0 for binary symbols
				resolved_entry->rva = -1;
				resolved_entry->hostID = binary->hostID;
				if(sym->symbolName != NULL){
					resolved_entry->symbolName = sym->symbolName;
				}
				resolvedBinaryEntries.push_back(resolved_entry);
				resolvedSymbols.push_back(sym);
			}
		}
	}//for

	//we have no symbols to try to resolve, which is fine
	if (resolvedSymbols.size() == 0) {
		return GENERIC_SUCCESS;
	}

	ret = FindRVAofSymbols(&resolvedSymbols, binary_file_path);
	if (ret != GENERIC_SUCCESS) {
		printf("ParseSymbolInformationForBinary: FindRVAofSymbols failed\n");
		goto end;
	}

	for (i=0;i<resolvedSymbols.size();i++) {
		dia_symbol_t *sym = resolvedSymbols.at(i);
		resolved_symbol_t *resolved_entry = resolvedBinaryEntries.at(i);
		resolved_entry->rva = sym->rva;
	}

	ret = InsertResolvedBinarySymbols(&resolvedBinaryEntries);
	if (ret != GENERIC_SUCCESS) {
		printf("ParseSymbolInformationForBinary: InsertResolvedBinarySymbols failed\n");
		goto end;
	}

	end:

	//clean up
	for (unsigned int i=0;i<resolvedSymbols.size();i++)
	{
		dia_symbol_t *sym = resolvedSymbols.at(i);
		resolved_symbol_t *resolved_entry = resolvedBinaryEntries.at(i);

		if(sym != NULL){
			free(sym->symbolName);
			free(sym);
		}

		if(resolved_entry != NULL){
			free(resolved_entry);
		}
	}

	resolvedSymbols.clear();
	resolvedBinaryEntries.clear();


	return ret;
}

//fills in the rva field of each dia_symbol_t in v with the resolved rva
//if found and -1 otherwise.
int FindRVAofSymbols(vector<dia_symbol_t *> *v, char *binary_file_path)
{
	FILE *pFile;
	const wchar_t *szChildname = NULL;
	size_t bytesConverted;
	wchar_t wideBinaryName[512];
	map<string, DWORD> symbolNameToRVAMap;
	size_t origBinaryNameSize = strlen(binary_file_path) + 1;
	if (origBinaryNameSize > 512)
	{
		printf("FindRVAofSymbols: binary_file_path too big\n");
		return GENERIC_ERROR;
	}

	//Convert from char * to wchar_t *
	mbstowcs_s(&bytesConverted, wideBinaryName, origBinaryNameSize, binary_file_path, _TRUNCATE);

	if (_wfopen_s(&pFile, wideBinaryName, L"r") || !pFile) {
		printf("FindRVAofSymbols: unable to open exe file: %s \n", binary_file_path);
		return GENERIC_ERROR;
	}

	fclose(pFile);

	// CoCreate() and initialize COM objects

	if (!LoadPdbDataForExe(wideBinaryName, &g_pDiaDataSource, &g_pDiaSession, &g_pGlobalSymbol))
	{
		printf("FindRVAofSymbols: LoadPdbDataForExe failed\n");
		return GENERIC_ERROR;
	}

	for (unsigned int i=0;i<v->size();i++) {
		dia_symbol_t *sym = (dia_symbol_t *)v->at(i);
		DWORD rva;
		string key(sym->symbolName);

		//check to see if we have already looked up this symbol
		if (!(symbolNameToRVAMap.find(key) == symbolNameToRVAMap.end()))
		{
			rva = symbolNameToRVAMap[key];
			sym->rva = rva;
			continue;
		}

		//else we have not looked up this symbol already
		wchar_t wideSymbolName[256];
		size_t origSymbolNameSize = strlen(sym->symbolName) + 1;

		if (origSymbolNameSize > 256)
		{
			printf("FindRVAofSymbols Error: symbol name to big\n");
			Cleanup();
			return GENERIC_ERROR;
		}

		//Convert from char * to wchar_t *
		mbstowcs_s(&bytesConverted, wideSymbolName, origSymbolNameSize, sym->symbolName, _TRUNCATE);

		if (locateSymbol(g_pGlobalSymbol, wideSymbolName, szChildname,&rva)) {
			sym->rva = rva;
			symbolNameToRVAMap[key] = rva;
		} else {
			sym->rva = -1;
		}
	}//for

	Cleanup();

	return GENERIC_SUCCESS;
}

////////////////////////////////////////////////////////////
// Create an IDiaData source and open a PDB file
//
bool LoadPdbDataForExe(
    const wchar_t    *szFilename,
    IDiaDataSource  **ppSource,
    IDiaSession     **ppSession,
    IDiaSymbol      **ppGlobal)
{
  DWORD dwMachType = 0;
  GUID guid;
  wchar_t wszGuid[64];
  HRESULT hr = CoInitialize(NULL);

  // Obtain access to the provider

  hr = CoCreateInstance(__uuidof(DiaSource),
                        NULL,
                        CLSCTX_INPROC_SERVER,
                        __uuidof(IDiaDataSource),
                        (void **) ppSource);

  if (FAILED(hr)) {
	  printf("LoadPdbDataForExe: CoCreateInstance failed - HRESULT = %08X\n", (unsigned int)hr);
    return false;
  }

  hr = (*ppSource)->loadDataForExe(szFilename, NT_SYMBOL_PATH, NULL);
    if (FAILED(hr)) {
      printf("LoadPdbDataForExe: failed - HRESULT = %08X\n", (unsigned int)hr);

      return false;
    }

  // Open a session for querying symbols

  hr = (*ppSource)->openSession(ppSession);

  if (FAILED(hr)) {
    printf("LoadPdbDataForExe: openSession failed - HRESULT = %08X\n", (unsigned int)hr);

    return false;
  }

  // Retrieve a reference to the global scope

  if ((*ppSession)->get_globalScope(ppGlobal) != S_OK) {
    printf("LoadPdbDataForExe: get_globalScope failed\n");
    return false;
  }
  

 if ( (*ppGlobal)->get_guid( &guid ) == S_OK ) {
   StringFromGUID2(guid, wszGuid, 64);
 }

  // Set Machine type for getting correct register names

  if ((*ppGlobal)->get_machineType(&dwMachType) == S_OK) {
    switch (dwMachType) {
      case IMAGE_FILE_MACHINE_I386 : g_dwMachineType = CV_CFL_80386; break;
      case IMAGE_FILE_MACHINE_IA64 : g_dwMachineType = CV_CFL_IA64; break;
      case IMAGE_FILE_MACHINE_AMD64 : g_dwMachineType = CV_CFL_AMD64; break;
    }
  }

  return true;
}

////////////////////////////////////////////////////////////
// Release DIA objects and CoUninitialize
//
void Cleanup()
{
  if (g_pGlobalSymbol) {
    g_pGlobalSymbol->Release();
    g_pGlobalSymbol = NULL;
  }

  if (g_pDiaSession) {
    g_pDiaSession->Release();
    g_pDiaSession = NULL;
  }

  CoUninitialize();
}


bool locateSymbol(IDiaSymbol *pGlobal, const wchar_t *szRegEx, const wchar_t *szChildname, DWORD *retRVA)
{
  IDiaEnumSymbols *pEnumSymbols;
  DWORD dwRVA;

  if (FAILED(pGlobal->findChildren(SymTagNull, szRegEx, nsRegularExpression, &pEnumSymbols))) {
    return false;
  }

  bool bReturn = true;

  IDiaSymbol *pSymbol;
  ULONG celt = 0;

  if (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
   // PrintGeneric(pSymbol);
	
	  if (pSymbol->get_relativeVirtualAddress(&dwRVA) != S_OK) 
	  {
		printf("LoadPdbDataForExe: Error retrieving RVA\n\n");
		bReturn = false;
	  }
	  else {
		bReturn = true;
	  *retRVA = dwRVA;
	  }
    pSymbol->Release();
  } else
	  bReturn = false;

  pEnumSymbols->Release();

  return bReturn;
}

