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

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include "tiresias_script.h"

char *dropbox_path = "..\\dropbox\\";
char *storage_path = "..\\storage\\";

char nt_signature[4] = {0x50,0x45,0x00,0x00};
char dos_signature[2] = {0x4D, 0x5A };
char buff[500];

int ReadConfigAndSetGlobs(char *config);
void atomic_move(char *filename, char *stamped_filename, bool deleteIt);

int _tmain(int argc, char* argv[])
{
	WIN32_FIND_DATA ffd;
	HANDLE hFind;
	FILE *hFile;
	char buf[4096];
	char filename[512];
	char stamped_filename[512];
	int n;
	int i;
	long offset = 0;

	//if (ReadConfigAndSetGlobs("c:\\mordor\\tiresias_script\\debug\\tiresias_config.txt") == GENERIC_ERROR)
	//{
//		printf("error parsing tiresias_config... exiting\n");
//		return -1;
//	}

	//if(SetCurrentDirectory(dropbox_path) == FALSE){
	//	printf("doh!");
	//}

	for (;;)
	{
		memset(buf,0x0,sizeof(buf));
		_snprintf(buf,sizeof(buf),"%s*",dropbox_path);
		//_snprintf(buf,sizeof(buf),"c:\\mordor\\tiresias_trunk\\dropbox\\");

		hFind = FindFirstFile(buf,&ffd);

		if (hFind == INVALID_HANDLE_VALUE)
		{
			printf("Problem opening DROPBOX directory... exiting\n");
			return -1;
		}

		//open every file in the DROPBOX
		do
		{
			if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{	 
				memset(&filename,0x0,sizeof(filename));
				_snprintf(filename,sizeof(filename),"%s%s",dropbox_path,ffd.cFileName);
				hFile = fopen(filename, "rb");

				memset(buf,0x0,sizeof(buf));
				n = fread(buf,1,sizeof(buf),hFile);
				fclose(hFile);

				//check to see if this is a PE file by looking for the
				//IMAGE_DOS_SIGNATURE in the first two bytes of the file
				if (buf[0] == dos_signature[0] && buf[1] == dos_signature[1])
				{
					long offset;
					long timestamp;

					printf("detected that %s is a binary file\n", filename);
					offset = *(long *)&buf[0x3C];

					//do sanity checking on nt_signature to make sure the offset isnt bogus
					if (!(buf[offset] == nt_signature[0] && buf[offset+1] == nt_signature[1]))
					{
						printf("sanity checking on nt_signature failed... read incorrect offset?\n");
						return -1;
					}
				}

				hFile = fopen(filename, "rb");
				short unsigned int DOS_SIG;
				fread(&DOS_SIG, 2, 1, hFile);

				// Skip the next 58 bytes.
				fseek(hFile, 58, SEEK_CUR);
				unsigned int e_lfanew;
				fread(&e_lfanew, 4, 1, hFile);

				// Use the e_lfanew value to seek to the start of the PE Header
				fseek(hFile, e_lfanew, SEEK_SET);

				// See if we have a PE Header signature
				unsigned int NT_SIG;
				fread(&NT_SIG, 4, 1, hFile);
				
				struct stIMAGE_FILE_HEADER
				{
					WORD Machine;
					WORD NumberOfSections;
					DWORD TimeDateStamp;
					DWORD PointerToSymbolTable;
					DWORD NumberOfSymbols;
					WORD SizeOfOptionalHeader;
					WORD Characteristics;
				};
				stIMAGE_FILE_HEADER FileHeader;

				// Well lets just read in the whole lot in one go in to our defined structure
				fread(&FileHeader, sizeof(FileHeader), 1, hFile);

				// Output what we have found.
				sprintf(buff, "FileHeader - TimeDateStamp: %x", FileHeader.TimeDateStamp);
				printf("%s\n", buff);
				
				struct stIMAGE_OPTIONAL_HEADER
				{
					BYTE skip1[16];
					DWORD AddressOfEntryPoint;
					BYTE skip2[8];
					DWORD ImageBase;
					DWORD SectionAlignment;
					DWORD FileAlignment;
					BYTE skip3[8];
					WORD MajorSubsystemVersion;
					WORD MinorSubsystemVersion;
					DWORD skip4;
					DWORD SizeOfImage;
					DWORD SizeOfHeaders;
					DWORD skip5;
					WORD Subsystem;
					BYTE skip6[26];
					IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
				};
				stIMAGE_OPTIONAL_HEADER OptionalHeader;
				
				fread(&OptionalHeader, sizeof(OptionalHeader), 1, hFile);

				sprintf(buff, "OptionalHeader - SizeOfImage value: %x", OptionalHeader.SizeOfImage);
				printf("%s\n", buff);
				
				fclose(hFile);

				memset(stamped_filename,0x0,sizeof(stamped_filename));
				_snprintf(stamped_filename,sizeof(stamped_filename),"%s%s-%08x-%08x",storage_path,ffd.cFileName,FileHeader.TimeDateStamp,OptionalHeader.SizeOfImage);
				printf("offset=%x, timestamp=%x, stamped=%s\n", offset,FileHeader.TimeDateStamp,stamped_filename);

				// special case: make a zero size Checkmate.sys copy
				if(strcmpi(ffd.cFileName,"Checkmate.sys") == 0)
				{
					// move original file, but leave a copy for next operation
					atomic_move(filename, stamped_filename, false);

					_snprintf(stamped_filename,sizeof(stamped_filename),"%s%s-%08x-%08x",storage_path,ffd.cFileName,FileHeader.TimeDateStamp,0);
					atomic_move(filename, stamped_filename, true);
				}else
				{
					atomic_move(filename, stamped_filename, true);
				}
			}
		}
		while (FindNextFile(hFind, &ffd) != 0);
		Sleep(5000);
	}
	
	return 0;
}


void atomic_move(char *filename, char *stamped_filename, bool deleteIt)
{
	char cmd[1024];

	memset(cmd,0x0,1024);
	_snprintf(cmd,sizeof(cmd),"copy %s %s\n", filename, stamped_filename);
	system(cmd);

	if(deleteIt == true)
	{
		memset(cmd,0x0,1024);
		_snprintf(cmd,sizeof(cmd),"del %s\n", filename);
		system(cmd);
	}
}

//Really simple parser for my really simple config file format
//stolen and butchered from tiresias file_access.cpp
int ReadConfigAndSetGlobs(char * configFileName){
	char * holder;
	char * tok;
	unsigned int tokLen = 0;
	char line[MAX_LINE];

	FILE * myStream = fopen(configFileName,"rb");
	if(myStream == NULL){
		printf("ReadConfigAndSetGlobs:error: Couldn't open %s\n", configFileName);
		return GENERIC_ERROR;
	}

	while(!feof(myStream)){
		holder = fgets(line, MAX_LINE, myStream);
		if(holder == NULL){
			if(feof(myStream)){
				//successfully reached the end of file
				fclose(myStream);
				return GENERIC_SUCCESS;
				break;
			}
			else{
				printf("ReadConfigAndSetGlobs:error: fgets had an unexpected error\n");
				fclose(myStream);
				return GENERIC_ERROR;
			}
		}
		//skip anything except lines starting with a number
		if(line[0] != '3' && line[0] != '4'){
			continue;
		}

		tok = strtok(line, ":");
		if(tok == NULL){
			printf("ReadConfigAndSetGlobs:error: strtok unexpectedly failed. Check config file structure\n");
			fclose(myStream);
			return GENERIC_ERROR;
		}
		switch(atoi(tok)){
			case 3:
				tok = strtok(NULL, ":");
				if(strcmp(tok, "DROPBOXPATH") != 0){
					printf("ReadConfigAndSetGlobs:Error: 3 should be matched with DROPBOXPATH\n");
					fclose(myStream);
					return GENERIC_ERROR;
				}
				tok = strtok(NULL, ":");
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("DROPBOXPATH"))){
					printf("ReadConfigAndSetGlobs:Error: drop box path may have been truncated due to length. \
						   Decrease path length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					fclose(myStream);
					return GENERIC_ERROR;
				}

				dropbox_path = (char *)malloc(tokLen+1);
				strcpy(dropbox_path, tok);
				printf("Found storage path of '%s'\n", dropbox_path);
				break;

			case 4:
				tok = strtok(NULL, ":");
				if(strcmp(tok, "STORAGEPATH") != 0){
					printf("ReadConfigAndSetGlobs:Error: 4 should be matched with STORAGEPATH\n");
					fclose(myStream);
					return GENERIC_ERROR;
				}
				tok = strtok(NULL, ":");
				tokLen = strlen(tok);
				if(tokLen == (MAX_LINE - 2 - strlen("STORAGEPATH"))){
					printf("ReadConfigAndSetGlobs:Error: storage path may have been truncated due to length. \
						   Decrease path length or increase MAX_LEN in ReadConfigAndSetGlobs\n");
					fclose(myStream);
					return GENERIC_ERROR;
				}
				storage_path = (char *) malloc(tokLen+1);
				strcpy(storage_path, tok);
				printf("Found storage path of '%s'\n", storage_path);
				break;

			default:
				printf("Unknown case in config file. Exiting. \n");
				fclose(myStream);
				return GENERIC_ERROR;
		}
	}

	fclose(myStream);
	return GENERIC_SUCCESS;

}