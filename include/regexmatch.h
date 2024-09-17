#ifndef REGEXMATCH_H
#define REGEXMATCH_H

/*
 * Copyright (c) 2015 deviceauthority. - All rights reserved. - www.deviceauthority.com
 *
 * This class provides a C style access to regular expression matching.
 */

#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

void malloc_init( void *(*pcre_malloc_new)(size_t), void (*pcre_free_new)(void *));
int matches( const char* subject, const char* pattern, char* error, unsigned short errorLength );
void malloc_finish();

#ifdef __cplusplus
}
#endif

#endif /* REGEXMATCH_H */
