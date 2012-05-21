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

#ifndef FILES_H
#define FILES_H

#include "global_includes.h"
#include <vector>
#include <string>
#include <mysql.h>

using namespace std;

////////////////////////////////////////////////////////
//MACROS
////////////////////////////////////////////////////////

#define MAX_LINE 1024

////////////////////////////////////////////////////////
//PROTOTYPES
////////////////////////////////////////////////////////

void UItoHexA(unsigned int val, char * str);
char * findFile(char * filesDirectory, char * name, unsigned int timeDateStamp);
int ReadConfigAndSetGlobs(char * configFileName);
int InsertHostsAndModulesFromFile(vector <string> * hosts, vector <string> * modules);
int InsertBrandStringLimitsFromFile(vector <string> * limits);
int InsertHostLimitsFromFile(vector <string> * limits);

#endif