/*
 * Copyright (c) 2015 deviceauthority. - All rights reserved. - www.deviceauthority.com
 *
 * This class provides a C style access to regular expression matching.
 */
#define PCRE_STATIC 1
#include "regexmatch.h"
#include <pcre.h>
#include <stdio.h>
#include <string.h>
#if defined(USETHREADING)
#include <pthread.h>
#endif // #if defined(USETHREADING)


#define OVECCOUNT 3    /* should be a multiple of 3 */

static void *(*pcre_malloc_keep)(size_t);
static void (*pcre_free_keep)(void *);
#if defined(USETHREADING)
static pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
#endif // #if defined(USETHREADING)

void malloc_init(void *(*pcre_malloc_new)(size_t), void (*pcre_free_new)(void *))
{
    // Store function pointers of current pcre_malloc and free.
    pcre_malloc_keep = pcre_malloc;
    pcre_free_keep = pcre_free;
    // Set pcre_malloc and free to alternate implementation.
    pcre_malloc = pcre_malloc_new;
    pcre_free = pcre_free_new;
}

void malloc_finish()
{
    // Restore function pointers of pcre_malloc and free from stored values.
    pcre_malloc = pcre_malloc_keep;
    pcre_free = pcre_free_keep;
}

int matches(const char *subject, const char *pattern, char *error, unsigned short errorLength)
{
    pcre *re = NULL;
    int result = 0;
    size_t subject_length = strlen(subject);
    int erroroffset;
    int ovector[OVECCOUNT];
    const char *err;
    int rc;

#if defined(USETHREADING)
//#ifdef _WIN32
//    mutex_ = CreateMutex(NULL, FALSE, "regex");
//    WaitForSingleObject(mutex_, INFINITE);
//#else
//    pthread_mutex_lock(&mutex_);
//#endif
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    // nginx overrides the pcre_malloc and pcre_free with it's own but here
    // that causes problems so we set it back to the standard while we execute
    // then put things back as they were by the end.
    malloc_init(malloc, free);

    re = pcre_compile(pattern,               /* the pattern */
                      0,                     /* default options */
                      &err,                  /* for error number */
                      &erroroffset,          /* for error offset */
                      NULL);                 /* use default compile context */
    /* Compilation failed: Report back why in the error text. */
    if (re == NULL)
    {
        const char *infoText = "PCRE compilation failed at offset %d: '%s'.";

        if ((strlen(infoText) + strlen(err) + 10) < errorLength)
        {
#if __STDC_WANT_SECURE_LIB__
            sprintf_s(error, errorLength, infoText, erroroffset, err);
#else
            sprintf(error, infoText, erroroffset, err);
#endif // #if __STDC_WANT_SECURE_LIB__
        }
    }
    else
    {
        /**************************************************************************
         * If the compilation succeeded, we call PCRE again, in order to do a     *
         * pattern match against the subject string. This does just ONE match. If *
         * further matching is needed, it will be done below. Before running the  *
         * match we must set up a match_data block for holding the result.        *
         **************************************************************************/
        rc = pcre_exec(re,                   /* the compiled pattern */
                       NULL,                 /* no extra data - we didn't study the pattern */
                       subject,              /* the subject string */
                       subject_length,       /* the length of the subject */
                       0,                    /* start at offset 0 in the subject */
                       0,                    /* default options */
                       ovector,              /* output vector for substring information */
                       OVECCOUNT);           /* number of elements in the output vector */
        if (rc >= 0)
        {
            // It matched
            result = 1;
        }
        else
        {
            switch (rc)
            {
                case PCRE_ERROR_NOMATCH:
                    // Don't need to set result to 0 as it already is that.
                break;

                default:
                {
                    const char *infoText = "Matching error %d.";

                    if ((strlen(infoText ) + 10) < errorLength)
                    {
#if __STDC_WANT_SECURE_LIB__
                        sprintf_s(error, errorLength, infoText, rc);
#else
                        sprintf(error, infoText, rc);
#endif // #if __STDC_WANT_SECURE_LIB__
                    }
                }
                break;
            }
        }
        // Free up the compiled regular expression.
        pcre_free(re);
    }
    // Now put things back as they were.
    malloc_finish();

#if defined(USETHREADING)
//#ifdef _WIN32
//    ReleaseMutex( mutex_ );
//#else
//    pthread_mutex_unlock(&mutex_);
//#endif
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return result;
}
