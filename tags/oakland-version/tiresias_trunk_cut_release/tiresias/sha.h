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
//***Taken from gross.googlecode.com 1/2/09, minor changes to make it compile

/* $Id$ */
/*
 * Copyright (c) 2006
 *               Antti Siira <antti@utu.fi>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef SHA256_H
#define SHA256_H

#define TRUE  1
#define FALSE 0

//#include <string.h>
//#include <strings.h>
//#include <stdio.h>
//#include <stdlib.h>

typedef unsigned char		uint8_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;

typedef uint8_t		sha_byte_t;
typedef uint32_t	sha_uint_t;
typedef uint64_t	sha_ulong_t;

/* Struct for SHA-256 checksums */
typedef struct
{
        sha_uint_t h0;
        sha_uint_t h1;
        sha_uint_t h2;
        sha_uint_t h3;
        sha_uint_t h4;
        sha_uint_t h5;
        sha_uint_t h6;
        sha_uint_t h7;
} sha_256_t;

/* *to must be at least 72 bytes long char buffer */
void string_sha256_hexdigest(char *to, char *message);
/* *to must be at least 72 bytes long char buffer */
void sha256_hexdigest(char *to, char *message, sha_ulong_t size);
sha_256_t sha256_string(char *message);
sha_256_t sha256(sha_byte_t *message, sha_ulong_t size);

#endif
