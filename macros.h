/**
 * journal-triggerd - Copyright (C) 2013 Olivier Brunel
 *
 * macros.h
 * Copyright (C) 2013 Olivier Brunel <i.am.jack.mail@gmail.com>
 *
 * This file is part of journal-triggerd.
 *
 * journal-triggerd is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * journal-triggerd is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * journal-triggerd. If not, see http://www.gnu.org/licenses/
 */

#ifndef __MACROS_H__
#define __MACROS_H__

#include <string.h>
#include <strings.h>
#include <ctype.h>      /* isblank() */

#define streq(s1, s2)           (((s1) == NULL && (s2) == NULL) ? 1 \
        : ((s1) == NULL || (s2) == NULL) ? 0 : strcmp  ((s1), (s2)) == 0)
#define streqn(s1, s2, n)       (((s1) == NULL || (s2) == NULL) ? 0 \
        : strncmp ((s1), (s2), (n)) == 0)
#define strcaseeq(s1, s2)       (((s1) == NULL && (s2) == NULL) ? 1 \
        : ((s1) == NULL || (s2) == NULL) ? 0 : strcasecmp  ((s1), (s2)) == 0)
#define strcaseeqn(s1, s2, n)       (((s1) == NULL || (s2) == NULL) ? 0 \
        : strncasecmp ((s1), (s2), (n)) == 0)

#define skip_blank(s)   for ( ; isblank (*(s)); ++(s)) ;

#endif /* __MACROS_H__ */

