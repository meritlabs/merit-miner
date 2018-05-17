/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012 Luke Dashjr
 * Copyright 2012-2017 pooler
 * Copyright 2017-2018 The Merit Foundation developers
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See LICENSE.md for more details.
 */

#ifndef __COMPAT_H__
#define __COMPAT_H__

#ifdef WIN32

#include <windows.h>

#define sleep(secs) Sleep((secs) * 1000)

enum {
	PRIO_PROCESS		= 0,
};

static inline int setpriority(int which, int who, int prio)
{
	return -!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

#endif /* WIN32 */

#endif /* __COMPAT_H__ */
