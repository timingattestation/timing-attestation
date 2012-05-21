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

//For any functions that needs to access the filesystem 
//e.g. to get known good files, read the config file, etc


#include "file_access.h"

extern "C" {
	#include "database_mysql.h"
	extern HANDLE mysqlMutex;
}
#include "database_mysql2.h"

#include <windows.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdio.h>
#include "pe.h"
#include <sys/stat.h>

////////////////////////////////////////////////////////
//GLOBALS
////////////////////////////////////////////////////////

//EXTERNS
//gff = global from file
extern "C" {
	//in database_mysql.c
	char * gffTiresiasDBName;
	char * gffSharedDBName;
	char * gffDatabaseUsername;
	char * gffDatabasePassword;
}
extern char * gffStoragePath; //in main.cpp
extern char * gffDeviceConfigPath;
extern unsigned int gffMaxWaitTimeout; //in main.cpp

using namespace std;

////////////////////////////////////////////////////////
//START CODE
////////////////////////////////////////////////////////

//converts unsigned int into 10 character hex string with a dash on the end(passed by reference)
//This is used to create the string for prepending the datetimestamp onto a file name
void UItoHexA(unsigned int val, char * str){
	unsigned char nibble;
	memset(str, 0, 10);
	str[0] = '-';
	for(int i = 0; i < 8; i++){
		nibble = (val >> i*4) & 0x0F;
		if(nibble < 10){
			str[8-i] = nibble + 0x30; //0x30 is ASCII zero
		}
		else{
			str[8-i] = (nibble - 10) + 0x41; //0x41 is ASCII capital A
		}
	}
}


//Files are renamed to include a hex timestamp and sizeofimage, so rather than 
//C:\bla\foo.sys it would be C:\bla\foo.sys-timedatestamp-sizeofimage

//takes as input 
//char * filesDirectory - a directory where all the files are stored. Should have trailing slash
//char * name - unqualified name of file to be checked
//unsigned int timeDateStamp - the DateTimeStamp field from the file's NTHeader.FileHeader
//returns as output
//Fully qualified filename of matching version of file
//NOTE: YOU ARE RESPONSIBLE FOR FREEING THE POINTER RETURNED
int FindFile(char * filesDirectory, char * name, unsigned int timeDateStamp, unsigned int sizeOfImage, char ** fullName){
	char timeDateStampStr[DATETIMESTAMP_STR_SIZE];
	char sizeOfImageStr[SIZEOFIMAGE_STR_SIZE];
	struct stat stFileInfo;
	
	int intStat;

	UItoHexA(timeDateStamp, timeDateStampStr);
	UItoHexA(sizeOfImage, sizeOfImageStr);

	unsigned int dirLen = strlen(filesDirectory);
	unsigned int nameLen = strlen(name);
	
	//The DATETIMESTAMP_STR_SIZE includes the null character, so that ensures that
	//this length has enough room for the null
	unsigned int fullNameLen = dirLen + nameLen + DATETIMESTAMP_STR_SIZE + SIZEOFIMAGE_STR_SIZE; 
	*fullName = (char *)malloc(fullNameLen);

	if(*fullName != NULL){
		strcpy_s(*fullName, fullNameLen, filesDirectory);
		strcat_s(*fullName, fullNameLen, name);
		strcat_s(*fullName, fullNameLen, timeDateStampStr);
		strcat_s(*fullName, fullNameLen, sizeOfImageStr);

		intStat = stat(*fullName, &stFileInfo);
		if(intStat != 0){
			free(*fullName);
			return GENERIC_ERROR;
		}
	}

	return GENERIC_SUCCESS;
}

//Really simple parser for my really simple config file format
int ReadConfigAndSetGlobs(char * configFileName){
	char * holder;
	char * tok;
	unsigned int tokLen = 0;
	char line[MAX_LINE];
	FILE * tmpStream;
	char * context;

	errno_t err = fopen_s(&tmpStream, configFileName,"rb");
	if(err != 0){
		printf("ReadConfigAndSetGlobs:error: Couldn't open %s\n", configFileName);
		return GENERIC_ERROR;
	}

	while(!feof(tmpStream)){
		holder = fgets(line, MAX_LINE, tmpStream);
		if(holder == NULL){
			if(feof(tmpStream)){
				//successfully reached the end of file
				fclose(tmpStream);
				return GENERIC_SUCCESS;
				break;
			}
			else{
				printf("ReadConfigAndSetGlobs:error: fgets had an unexpected error\n");
				fclose(tmpStream);
				return GENERIC_ERROR;
			}
		}

		if (line[0] != '0' && line[0] != '1' && line[0] != '2' && line[0] != '3' && line[0] != '4'
			&& line[0] != '5' && line[0] != '6' && line[0] != '7' && line[0] != '8' && line[0] != '9'
			&& !(line[0] == '1' && line[1] == '0') && !(line[0] == '1' && line[1] == '1')
			&& !(line[0] == '1' && line[1] == '2') && !(line[0] == '1' && line[1] == '3'))
			continue;

		tok = strtok_s(line, ":", &context);
		if(tok == NULL){
			printf("ReadConfigAndSetGlobs:error: strtok unexpectedly failed. Check config file structure\n");
			goto invalidConfig;
		}

		switch(strtoul(tok, NULL, 10)){
			case 0:
				tok = strtok_s(NULL, ":",&context);
				if(strcmp(tok, "DATABASEUSERNAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 1 should be matched with DATABASEUSERNAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("DATABASEUSERNAME"))){
					printf("ReadConfigAndSetGlobs:Error: database username may have been truncated due to length. \
							Decrease database username length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffDatabaseUsername = (char *) malloc(tokLen+1);
				
				if(gffDatabaseUsername != NULL){
					strcpy_s(gffDatabaseUsername, tokLen+1, tok);
					//printf("Found database username of '%s'\n", gffDatabaseUsername);
				}
				break;

			case 1:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "DATABASEPASSWORD") != 0){
					printf("ReadConfigAndSetGlobs:Error: 2 should be matched with DATABASEPASSWORD\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("DATABASEPASSWORD"))){
					printf("ReadConfigAndSetGlobs:Error: database password may have been truncated due to length. \
							Decrease database password length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffDatabasePassword = (char *) malloc(tokLen+1);
				if(gffDatabasePassword != NULL){
					strcpy_s(gffDatabasePassword, tokLen+1, tok);
					//printf("Found database password of '%s'\n", gffDatabasePassword);
				}
				break;

			case 2:
				tok = strtok_s(NULL, ":",&context);
				if(strcmp(tok, "TIRESIAS_DB_NAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 2 should be matched with TIRESIAS_DB_NAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("TIRESIAS_DB_NAME"))){
					printf("ReadConfigAndSetGlobs:Error: database name may have been truncated due to length. \
							Decrease database name length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffTiresiasDBName = (char *) malloc(tokLen+1);
				if(gffTiresiasDBName != NULL){
					strcpy_s(gffTiresiasDBName,tokLen+1, tok);
					printf("Found database name of '%s'\n", gffTiresiasDBName);
				}
				break;
			//have to keep this so we can use the same config file for tiresias_script
			case 3:
				break;
			case 4:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "STORAGEPATH") != 0){
					printf("ReadConfigAndSetGlobs:Error: 4 should be matched with STORAGEPATH\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":",&context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("STORAGEPATH"))){
					printf("ReadConfigAndSetGlobs:Error: storage path may have been truncated due to length. \
							Decrease path length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffStoragePath = (char *) malloc(tokLen+1);
				if(gffStoragePath != NULL){
					strcpy_s(gffStoragePath,tokLen+1, tok);
					printf("Found storage path of '%s'\n", gffStoragePath);
				}
				break;
			case 6:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "WAIT_TIMEOUT") != 0){
					printf("ReadConfigAndSetGlobs:Error: 6 should be matched with WAIT_TIMEOUT\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":",&context);
				gffMaxWaitTimeout = strtoul(tok, NULL, 10);
				printf("Found gffMaxWaitTimeout of %u\n", gffMaxWaitTimeout);
				break;
			case 16:
				expected_symbol_t binSym;

				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if (strcmp(tok, "BINARY_SYMBOL") != 0) {
					printf("ReadConfigAndSetGlobs:Error: 16 should be matched with BINARY_SYMBOL instead got: %s\n", tok);
					goto invalidConfig;
				}
				binSym.index = 0;
				
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				binSym.symbolName = (char *)malloc(tokLen+1);
				if(binSym.symbolName != NULL){
					strcpy_s(binSym.symbolName,tokLen+1, tok);
				}

				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				binSym.moduleName = (char *)malloc(tokLen+1);
				if(binSym.moduleName != NULL){
					strcpy_s(binSym.moduleName,tokLen+1,tok);
				}

				gExpectedBinarySymbols.push_back(binSym);
				break;
			case 19:
				tok = strtok_s(NULL, ":", &context);
				if(strcmp(tok, "SHARED_DB_NAME") != 0){
					printf("ReadConfigAndSetGlobs:Error: 19 should be matched with SHARED_DB_NAME\n");
					goto invalidConfig;
				}
				tok = strtok_s(NULL, ":", &context);
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("SHARED_DB_NAME"))){
					printf("ReadConfigAndSetGlobs:Error: SHARED_DB_NAME may have been truncated due to length. \
							Decrease SHARED_DB_NAME length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					goto invalidConfig;
				}
				gffSharedDBName = (char *) malloc(tokLen+1);
				if(gffSharedDBName == NULL){
					goto invalidConfig;
				}
				strcpy_s(gffSharedDBName, tokLen+1, tok);
				printf("Found shared database name of '%s'\n", gffSharedDBName);
				break;
			default:
				printf("Unknown case in config file. Exiting. \n");
				fclose(tmpStream);
				return INVALID_CONFIG;
		}
	}

	fclose(tmpStream);
	return GENERIC_SUCCESS;

invalidConfig:
	fclose(tmpStream);
	return INVALID_CONFIG;

}


//Have to recreate a minimal set of the functionality in AnalyzeFileForBinaryMeasurement
//PREREQ: if you don't have the timeDateStamp and sizeOfImage, call with them set to NULL
//in order to look up based on the host given by hostID. If you have to go that route, you 
//can force that by setting it as a binary prereq.
//
//NOTE: YOU ARE RESPONSIBLE FOR FREEING THE relocatedSection MEMORY RETURNED
int OpenBinaryToGetRelocatedROSection(char * binaryName, char * sectionName, unsigned int hostID, unsigned int baseVA, unsigned int timeDateStamp, unsigned int sizeOfImage, char ** relocatedSection, unsigned int * relocSectLen, unsigned int * sectionStartRVA, unsigned int * sectionEndRVA){
	PIMAGE_DOS_HEADER pDosH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_SECTION_HEADER pFirstSectH = NULL;
	int ret = GENERIC_ERROR;
	FILE * fileStream;
	char * fullFileName;
	unsigned int i, alignmentOffset, endAlignUpPadding;
	binariesTableEntry_t binariesTE;

	binariesTE.timeDateStamp = timeDateStamp;
	binariesTE.sizeOfImage = sizeOfImage;
	binariesTE.baseVA = baseVA;

	//Open the relevant file
	//NOTE! we're responsible for freeing the memory which is allocated for fullFileName
	ret = FindFile(gffStoragePath, binaryName, binariesTE.timeDateStamp, binariesTE.sizeOfImage, &fullFileName);
	if(ret == GENERIC_ERROR){
		//For kernel variants like ntkrnlpa.exe, they are found
		//in memory in the loaded modules list as ntoskrnl.exe but their
		//memory measurements need to be taken from the right kernel version.
		//So we need to try alternative names
		if(_stricmp(binaryName, "ntoskrnl.exe")==0){
			ret = FindFile(gffStoragePath, "ntkrnlpa.exe", binariesTE.timeDateStamp, binariesTE.sizeOfImage, &fullFileName);
			if(ret == GENERIC_ERROR){
				ret = FindFile(gffStoragePath, "ntkrnlmp.exe", binariesTE.timeDateStamp, binariesTE.sizeOfImage, &fullFileName);
				if(ret == GENERIC_ERROR){
					printf("OpenBinaryToGetRelocatedROSection: Couldn't find nt file for any variant name\n");
					return GENERIC_ERROR;
				}
			}
		}
		else{
			printf("OpenBinaryToGetRelocatedROSection: FindFile failed: Couldn't find match for %s-%x-%x\n", 
				binaryName,
				binariesTE.timeDateStamp,
				binariesTE.sizeOfImage
				);
			return ret;
		}
	}

	if(fullFileName != NULL){

		//Open the file to read the headers
		errno_t err = fopen_s(&fileStream,fullFileName,"rb");
		if(err != 0){
			printf("OpenBinaryToGetRelocatedROSection:error: Couldn't fopen_s %s, errno = %d\n", fullFileName, errno);
			free(fullFileName);
			return GENERIC_ERROR;
		}

		if(ParsePEHeaders(fileStream, &pDosH, &pNtH, &pFirstSectH) == GENERIC_ERROR){
			printf("OpenBinaryToGetRelocatedROSection: ParsePEHeaders failed, unsupported case in %s\n", fullFileName);
			free(fullFileName);
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		unsigned int baseVADiff = FindBaseVADiff(binariesTE.baseVA, pNtH);
		char * relocBuf = FindRelocs(fileStream, pNtH, pFirstSectH);
		if(relocBuf == 0){
			printf("OpenBinaryToGetRelocatedROSection: FindRelocs failed\n");
			free(pDosH); 
			free(relocBuf); 
			free(fullFileName); 
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		PIMAGE_SECTION_HEADER * pSections = new PIMAGE_SECTION_HEADER[pNtH->FileHeader.NumberOfSections];
		ret = FindROSections(pNtH, pFirstSectH, pSections, &(binariesTE.numROSections));
		if(ret != GENERIC_SUCCESS){
			printf("OpenBinaryToGetRelocatedROSection: FindROSections failed\n");
			free(pDosH);
			free(relocBuf);
			delete[] pSections;
			free(fullFileName);
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		//Find the section which matches the name we were given
		for(i = 0; i < binariesTE.numROSections; i++){
			if(memcmp(sectionName, &(pSections[i]->Name), MAX_SECT_NAME_CHAR_LEN-1) == 0)
				break;
		}
		if(i == binariesTE.numROSections){
			printf("OpenBinaryToGetRelocatedROSection: Couldn't find section with name %s for binary %s\n", sectionName, binaryName);
			free(pDosH); 
			free(relocBuf); 
			delete[] pSections; 
			free(fullFileName); 
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		//set the section start and end RVA now that we've found the right section
		*sectionStartRVA = pSections[i]->VirtualAddress;
		*sectionEndRVA = *sectionStartRVA + pSections[i]->Misc.VirtualSize;

		//relocatedSection alloced inside GetRelocatedSection, make sure to dealloc outside
		//Note, we're actually returning the buffer in relocatedSection
		//NOTE: YOU ARE RESPONSIBLE FOR FREEING THE relocatedSection MEMORY RETURNED
		ret = GetRelocatedSection(fileStream, pNtH, pSections[i], baseVADiff, relocBuf, &alignmentOffset, &endAlignUpPadding, relocatedSection, relocSectLen);
		if(ret == GENERIC_ERROR){
			printf("OpenBinaryToGetRelocatedROSection: GetRelocatedSection failed for sectionIndex = %u\n", i);
			free(pDosH);
			free(relocBuf);
			delete[] pSections;
			free(fullFileName);
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		//Now here's the thing: the buffer returned by GetRelocatedSection is potentially
		//page aligned down, since during the relocation process it wants to get paged aligned
		//chunks of the file. Therefore, we want to take the buffer and snip off anything at the
		//beginning which is only at the beginning of the buffer due to the page align down.
		*relocSectLen = *relocSectLen-alignmentOffset;
	//	*relocSectLen = *relocSectLen-alignmentOffset-endAlignUpPadding;
		char * tmp = (char *) malloc(*relocSectLen);
		memcpy(tmp, *relocatedSection+alignmentOffset, *relocSectLen);
		free(*relocatedSection);
		*relocatedSection = tmp;

		//cleanup
		free(pDosH);
		free(relocBuf);
		delete[] pSections;
		free(fullFileName);
		fclose(fileStream);	
	}

	return GENERIC_SUCCESS;
}

//This is just meant to be a helper function for self-check verification of the minichecksums
//of external modules like nt or hal
int LoadSectionAndReconstructIAT(char * binaryName, char * sectionName, unsigned int hostID, unsigned int baseVA, unsigned int timeDateStamp, unsigned int sizeOfImage, char ** relocatedSection, unsigned int * relocSectLen, unsigned int * sectionStartRVA, unsigned int * sectionEndRVA){
	PIMAGE_DOS_HEADER pDosH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_SECTION_HEADER pFirstSectH = NULL;
	int ret = GENERIC_ERROR;
	FILE * fileStream;
	char * fullFileName;
	unsigned int i, alignmentOffset, endAlignUpPadding;
	st_msg_t stm;
	binariesTableEntry_t binariesTE;

	binariesTE.timeDateStamp = timeDateStamp;
	binariesTE.sizeOfImage = sizeOfImage;
	binariesTE.baseVA = baseVA;

	//Open the relevant file
	//NOTE! we're responsible for freeing the memory which is allocated for fullFileName
	ret = FindFile(gffStoragePath, binaryName, binariesTE.timeDateStamp, binariesTE.sizeOfImage, &fullFileName);
	if(ret == GENERIC_ERROR){
		//For kernel variants like ntkrnlpa.exe, they are found
		//in memory in the loaded modules list as ntoskrnl.exe but their
		//memory measurements need to be taken from the right kernel version.
		//So we need to try alternative names
		if(_stricmp(binaryName, "ntoskrnl.exe")==0){
			ret = FindFile(gffStoragePath, "ntkrnlpa.exe", binariesTE.timeDateStamp, binariesTE.sizeOfImage, &fullFileName);
			if(ret == GENERIC_ERROR){
				printf("LoadSectionAndReconstructIAT: Couldn't find nt file for any variant name\n");
				return GENERIC_ERROR;
			}
		}
		else{
			printf("LoadSectionAndReconstructIAT: FindFile failed: Couldn't find match for %s-%x-%x\n", 
				binaryName,
				binariesTE.timeDateStamp,
				binariesTE.sizeOfImage);
			return ret;
		}
	}

	if(fullFileName != NULL){
		//Open the file to read the headers
		errno_t err = fopen_s(&fileStream,fullFileName,"rb");
		if(err != 0){
			printf("LoadSectionAndReconstructIAT:error: Couldn't fopen_s %s, errno = %d\n", fullFileName, errno);
			free(fullFileName);
			return GENERIC_ERROR;
		}

		if(ParsePEHeaders(fileStream, &pDosH, &pNtH, &pFirstSectH) == GENERIC_ERROR){
			printf("LoadSectionAndReconstructIAT: ParsePEHeaders failed, unsupported case in %s\n", fullFileName);
			free(fullFileName);
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		unsigned int baseVADiff = FindBaseVADiff(binariesTE.baseVA, pNtH);
		char * relocBuf = FindRelocs(fileStream, pNtH, pFirstSectH);
		if(relocBuf == 0){
			printf("LoadSectionAndReconstructIAT: FindRelocs failed\n");
			free(pDosH); 
			free(relocBuf); 
			free(fullFileName); 
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		PIMAGE_SECTION_HEADER * pSections = new PIMAGE_SECTION_HEADER[pNtH->FileHeader.NumberOfSections];
		ret = FindROSections(pNtH, pFirstSectH, pSections, &(binariesTE.numROSections));
		if(ret != GENERIC_SUCCESS){
			printf("LoadSectionAndReconstructIAT: FindROSections failed\n");
			free(pDosH);
			free(relocBuf);
			delete[] pSections;
			free(fullFileName);
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		//Find the section which matches the name we were given
		for(i = 0; i < binariesTE.numROSections; i++){
			if(memcmp(sectionName, &(pSections[i]->Name), MAX_SECT_NAME_CHAR_LEN-1) == 0)
				break;
		}
		if(i == binariesTE.numROSections){
			printf("LoadSectionAndReconstructIAT: Couldn't find section with name %s for binary %s\n", sectionName, binaryName);
			free(pDosH); 
			free(relocBuf); 
			delete[] pSections; 
			free(fullFileName); 
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		//set the section start and end RVA now that we've found the right section
		*sectionStartRVA = pSections[i]->VirtualAddress;
		*sectionEndRVA = *sectionStartRVA + pSections[i]->Misc.VirtualSize;

		//relocatedSection alloced inside GetRelocatedSection, make sure to dealloc outside
		//Note, we're actually returning the buffer in relocatedSection
		//NOTE: YOU ARE RESPONSIBLE FOR FREEING THE relocatedSection MEMORY RETURNED
		ret = GetRelocatedSection(fileStream, pNtH, pSections[i], baseVADiff, relocBuf, &alignmentOffset, &endAlignUpPadding, relocatedSection, relocSectLen);
		if(ret == GENERIC_ERROR){
			printf("LoadSectionAndReconstructIAT: GetRelocatedSection failed for sectionIndex = %u\n", i);
			free(pDosH);
			free(relocBuf);
			delete[] pSections;
			free(fullFileName);
			fclose(fileStream);	
			return GENERIC_ERROR;
		}
		memset(&stm, 0, sizeof(st_msg_t));
		stm.baseVA = baseVA;
		stm.hostID = hostID;
		ret = ReconstructImports(fileStream, pNtH, pSections[i], *relocatedSection, *relocSectLen, alignmentOffset, baseVADiff, &stm);
		if(ret != GENERIC_SUCCESS){
			printf("LoadSectionAndReconstructIAT: GetRelocatedSection failed for sectionIndex = %u\n", i);
			free(pDosH);
			free(relocBuf);
			delete[] pSections;
			free(fullFileName);
			fclose(fileStream);	
			return GENERIC_ERROR;
		}

		//Now here's the thing: the buffer returned by GetRelocatedSection is potentially
		//page aligned down, since during the relocation process it wants to get paged aligned
		//chunks of the file. Therefore, we want to take the buffer and snip off anything at the
		//beginning which is only at the beginning of the buffer due to the page align down.
	//	*relocSectLen = *relocSectLen-alignmentOffset-endAlignUpPadding;
		*relocSectLen = *relocSectLen-alignmentOffset;
		char * tmp = (char *) malloc(*relocSectLen);
		memcpy(tmp, *relocatedSection+alignmentOffset, *relocSectLen);
		free(*relocatedSection);
		*relocatedSection = tmp;

		//cleanup
		free(pDosH);
		free(relocBuf);
		delete[] pSections;
		free(fullFileName);
		fclose(fileStream);	
	}

	return GENERIC_SUCCESS;
}

int OpenHostSpecificModule(st_msg_t * stm, char * fileName, FILE ** fileStream, loadedModulesEntry * loadedModuleEntry){
	int ret;
	char * fullFileName;

	//We need to figure out what version of the module exists on the system being measured
	ret = SelectLoadedModuleEntryByNameAndHostID(fileName, stm->hostID, loadedModuleEntry);
	if(ret != GENERIC_SUCCESS){
		printf("OpenHostSpecificModule: SelectLoadedModuleEntryByNameAndHostID failed\n");
		return ret;
	}

	//Then we have to see if we have that in our storage
	ret = FindFile(gffStoragePath, fileName, loadedModuleEntry->timeDateStamp, loadedModuleEntry->sizeOfImage, &fullFileName);
	if(ret == GENERIC_ERROR){
		//For kernel variants like ntkrnlpa.exe, they are found
		//in memory in the loaded modules list as ntoskrnl.exe but their
		//memory measurements need to be taken from the right kernel version.
		//So we need to try alternative names
		if(_stricmp(fileName, "ntoskrnl.exe")==0){
			ret = FindFile(gffStoragePath, "ntkrnlpa.exe", loadedModuleEntry->timeDateStamp, loadedModuleEntry->sizeOfImage, &fullFileName);
			if(ret == GENERIC_ERROR){
				ret = FindFile(gffStoragePath, "ntkrnlmp.exe", loadedModuleEntry->timeDateStamp, loadedModuleEntry->sizeOfImage, &fullFileName);
				if(ret == GENERIC_ERROR){
					goto stillbad;
				}
			}
		}
		else{
			stillbad:
			printf("OpenHostSpecificModule: FindFile failed: Couldn't find match for %s-%x-%x\n",
				fileName,
				loadedModuleEntry->timeDateStamp,
				loadedModuleEntry->sizeOfImage);
			printf("OpenHostSpecificModule: FindFile failed\n");
			return ret;
		}
	}
	//If we get to here, we have malloced memory pointed to by fullFileName, and we can fopen_s the file
	//to return the FILE *
	if(fullFileName != NULL){
		errno_t err = fopen_s(fileStream, fullFileName, "rb");
		if(err != 0){
			printf("FindFile:error: Couldn't open %s, errno = %d\n", fullFileName, errno);
			if(fullFileName != NULL){
				free(fullFileName);
			}
			return GENERIC_ERROR;
		}
	}

	return GENERIC_SUCCESS;
}

int ReadDataAtRVAFromFileIntoBuffer(FILE * fileStream, unsigned int rva, char ** buffer, unsigned int bufferLen, PIMAGE_NT_HEADERS pNtH, PIMAGE_SECTION_HEADER pFirstSectH){
	unsigned int bytesRead;
	PIMAGE_SECTION_HEADER pContainingSectionHdr;

	pContainingSectionHdr = rvaToSectH(rva, pNtH, pFirstSectH);
	if(pContainingSectionHdr == NULL){
		printf("ReadDataAtRVAFromFileIntoBuffer: rvaToSectH failed\n");
		return GENERIC_ERROR;
	}
	unsigned int fileOffset = pContainingSectionHdr->PointerToRawData + (rva - pContainingSectionHdr->VirtualAddress);
	
	*buffer = (char *)malloc(bufferLen);
	if(*buffer == NULL){
		printf("ReadDataAtRVAFromFileIntoBuffer: malloc failed\n");
		return GENERIC_ERROR;
	}
	if(fseek(fileStream, fileOffset, 0) != 0){
		printf("ReadDataAtRVAFromFileIntoBuffer: fseek failed\n");
		if(*buffer != NULL){
			free(*buffer);
		}
		return GENERIC_ERROR;
	}
	bytesRead = fread(*buffer, sizeof(char), bufferLen, fileStream);
	if(bytesRead != bufferLen){
		printf("ReadDataAtRVAFromFileIntoBuffer: file was not read, or didn't contain %d bytes\n", bufferLen);
		if(*buffer != NULL){
			free(*buffer);
		}
		return GENERIC_ERROR;
	}

	return GENERIC_SUCCESS;
}