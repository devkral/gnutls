/*
 *      Copyright (C) 2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>

ALLOC_FUNC gnutls_secure_malloc = malloc;
ALLOC_FUNC gnutls_malloc = malloc;
FREE_FUNC gnutls_free = free;
REALLOC_FUNC gnutls_realloc = realloc;

void* (*gnutls_calloc)(size_t, size_t) = calloc;
char* (*gnutls_strdup)(const char*) = strdup;

int _gnutls_is_secure_mem_null( const void* ign) { return 0; }

int (*_gnutls_is_secure_memory)(const void*) = _gnutls_is_secure_mem_null;


void *_gnutls_calloc(size_t nmemb, size_t size)
{
	void *ret;
	ret = gnutls_malloc(size);
	if (ret == NULL)
		return ret;

	memset(ret, 0, size);

	return ret;
}

svoid *gnutls_secure_calloc(size_t nmemb, size_t size)
{
	svoid *ret;
	ret = gnutls_secure_malloc(size);
	if (ret == NULL)
		return ret;

	memset(ret, 0, size);

	return ret;
}

/* This realloc will free ptr in case realloc
 * fails.
 */
void* gnutls_realloc_fast( void* ptr, size_t size) 
{
void *ret;

        if (size == 0) return ptr;

	ret = gnutls_realloc( ptr, size);
	if ( ret == NULL) {
		gnutls_free( ptr);
		return NULL;
	}

	return ret;
}

char* _gnutls_strdup( const char* str) {
int siz = strlen( str);
char * ret;

	ret = gnutls_malloc( siz + 1);
	if (ret == NULL)
		return ret;
		
	memcpy( ret, str, siz);
	ret[ siz] = 0;
	
	return ret;
}
