/*
 * iolimitd: limit disk IO daemon using SIGSTOP and SIGCONT
 *
 * Dmitry Yu Okunev <dyokunev@ut.mephi.ru>  2016
 *
 * This code is copied from util-linux-2.27.1/schedutils/ionice.c. The author's header is below:
 */

/*
 * Copyright (C) 2005 Jens Axboe <jens@axboe.dk>
 *
 * Released under the terms of the GNU General Public License version 2
 *
 */


#define IOPRIO_CLASS_SHIFT      (13)
#define IOPRIO_PRIO_MASK        ((1UL << IOPRIO_CLASS_SHIFT) - 1)

#define IOPRIO_PRIO_CLASS(mask) ((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask)  ((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)  (((class) << IOPRIO_CLASS_SHIFT) | data)

enum {
	IOPRIO_CLASS_NONE,
	IOPRIO_CLASS_RT,
	IOPRIO_CLASS_BE,
	IOPRIO_CLASS_IDLE,
};

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};


static inline int ioprio_get ( int which, int who )
{
	return syscall ( SYS_ioprio_get, which, who );
}
