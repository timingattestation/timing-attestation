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

//This is where things that want to use some C++ containers 
//but still using the MySQL C API go


#ifndef DATABASE_MYSQL2_H
#define DATABASE_MYSQL2_H 

#include <queue>
#include <vector>
#include <string>

#include "global_includes.h"
#include "measure_binary.h"
extern "C"{
	#include "database_mysql.h"
}

using namespace std;

extern vector<expected_symbol_t> gExpectedBinarySymbols;

int InsertExports(unsigned int binID, vector<export_t *> * v);
int InsertExpectedBinarySymbols(vector<expected_symbol_t> * v);
int InsertResolvedBinarySymbols(vector<resolved_symbol_t *> * v);

#endif

