/*
 * iolimitd: limit disk IO daemon using SIGSTOP and SIGCONT
 *
 * Dmitry Yu Okunev <dyokunev@ut.mephi.ru>  2016
 *
 * Released under the terms of the GNU General Public License version 2
 */

// includes

#define _GNU_SOURCE

#define RAND_MAX		(~0)

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <stdint.h>
#include <assert.h>
#include <signal.h>
#include <time.h>

#include "ionice.h"

// configuration

#define PATH_PROCFS		"/proc"

#define TIME_QUANTUM		500000		// microseconds
#define TIME_RESCAN_INTERVAL	1000000		// microseconds
#define READ_WRITE_RATIO	3.0

// code

#define ALLOC_PORTION		1024

#define TOSTR(a) # a
#define XTOSTR(a) TOSTR(a)
#define error(...) fprintf( stderr, __VA_ARGS__ )
#define assert_witherrno(expr) { if ( !(expr) ) { error( __FILE__":%u: Got error on \"" XTOSTR( expr ) "\": %s\n", __LINE__, strerror(errno)); exit(errno ? errno : -1); } }

#define IS_DIGIT(a) ((a) >= '0' && (a) <= '9')

#ifdef DEBUG
#define debug(debug_bit, ...) {fprintf(stderr, __FILE__ ":%i: %s(): 0x%x: ", __LINE__, __func__, debug_bit); fprintf(stderr,__VA_ARGS__);fprintf(stderr, "\n");}
#define debugpoint() {fprintf(stderr, __FILE__ ":%i: %s()\n", __LINE__, __func__);}
#else
#define debug(...) {}
#define debugpoint(...) {}
#endif

static inline long xstrtol ( const char *str, int *err )
{
	if ( err != NULL )
		*err = 0;

	char *end;
	errno = 0;
	long res = strtol ( str, &end, 0 );

	if ( errno || *end ) {
		if ( err != NULL )
			*err = EINVAL;
	}

	return res;
}

struct array {
	void	*elements;
	size_t	 alloced;
	size_t	 size;
	size_t	 element_size;
	pthread_spinlock_t lock;
	void 	*otherdata;
};
typedef struct array array_t;

struct iostat {
	uint64_t	rchar;
	uint64_t	wchar;
	uint64_t	syscr;
	uint64_t	syscw;
};
typedef struct iostat iostat_t;

enum stopped {
	NOT_STOPPED,
	STOPPED_INTERNAL,
	STOPPED_EXTERNAL,
};
typedef enum stopped stopped_t;

enum status {
	STATUS_STOPPED = 'T',
};
typedef enum status status_t;

struct proc {
//	char		name[PATH_MAX];
	int		still_exists;
	pid_t		pid;
	int		ioclass;
	iostat_t	iostat;
	iostat_t	iostat_delta;
	int64_t		score;
	int64_t		reverse_score;
	stopped_t	stopped;
	char		status;
};
typedef struct proc proc_t;

static inline void *xmalloc ( size_t size )
{
	void *ret = malloc ( size );
	assert_witherrno ( ret != NULL );
	return ret;
}

static inline void *xcalloc ( size_t nmemb, size_t size )
{
	void *ret = calloc ( nmemb, size );
	assert_witherrno ( ret != NULL );
	return ret;
}

static inline void *xrealloc ( void *oldptr, size_t size )
{
	void *ret = realloc ( oldptr, size );
	assert_witherrno ( ret != NULL );
	return ret;
}

array_t *array_init ( size_t element_size )
{
	struct array *a = xcalloc ( 1, sizeof ( *a ) );
	a->element_size = element_size;
	pthread_spin_init ( &a->lock, 0 );
	return a;
}

int array_deinit ( array_t *a )
{
	pthread_spin_destroy ( &a->lock );
	free ( a->elements );
	free ( a );
	return 0;
}

int array_flush ( array_t *a )
{
	memset ( a->elements, 0, a->size * a->element_size );
	a->size = 0;
	return 0;
}

#define ARRAY_ELEM(a, i) ( void * ) ( & ( ( char * ) (a)->elements ) [(i) * (a)->element_size] )

void *array_newelement ( array_t *a )
{
	if ( a->size >= a->alloced ) {
		a->alloced += ALLOC_PORTION;
		a->elements = xrealloc ( a->elements, a->alloced * a->element_size );
	}

	return ARRAY_ELEM ( a, a->size++ );
}

static inline int array_lock ( array_t *a )
{
	return pthread_spin_lock ( &a->lock );
}

static inline int array_unlock ( array_t *a )
{
	return pthread_spin_unlock ( &a->lock );
}

int array_foreach ( array_t *a, int ( *funct ) ( void *element, void *arg ), void *arg )
{
	int i = 0;

	while ( i < a->size )
		assert ( funct ( ARRAY_ELEM ( a, i++ ), arg ) == 0 );

	return 0;
}

#define CALLS(a) {\
		a(rchar);\
		a(wchar);\
		a(syscr);\
		a(syscw);\
	}

int pslist_get_iostat ( proc_t *procdata )
{
	FILE *f;
	char iostat_path[PATH_MAX];
	assert ( procdata != NULL );
	assert ( snprintf ( iostat_path, PATH_MAX, PATH_PROCFS"/%u/io", procdata->pid ) > 0 );

	//assert ( ( f = fopen ( iostat_path, "r" ) ) != NULL );
	if ( ( f = fopen ( iostat_path, "r" ) ) == NULL )
		return errno != 0 ? errno : -1;

	char *line = NULL;
	size_t n = 0;
	ssize_t linelen;
	iostat_t oldiostat;
	memcpy ( &oldiostat, &procdata->iostat, sizeof ( procdata->iostat ) );

	while ( ( linelen = getline ( &line, &n, f ) ) > 0 ) {
		char *saveptr = NULL, *colon_ptr, *end_ptr;
		end_ptr = &line[linelen];
		assert ( ( colon_ptr = strtok_r ( line, ":", &saveptr ) ) );
		assert ( ( colon_ptr = strtok_r ( NULL, ":", &saveptr ) ) );
		*colon_ptr  = 0;
		colon_ptr += 2;
		debug(0x40, "procdata->pid == %u; colon_ptr == \"%s\"", procdata->pid, colon_ptr);
		assert ( colon_ptr < end_ptr );
#		define PARSELINE(a) if(!strcmp(line, XTOSTR(a))) procdata->iostat.a = atoi(colon_ptr); else
		CALLS ( PARSELINE ) {};
#		undef PARSELINE
	}

	if ( procdata->stopped == STOPPED_INTERNAL ) {
#		define GETDELTA(a) procdata->iostat_delta.a += procdata->iostat.a - oldiostat.a
		CALLS ( GETDELTA );
#		undef GETDELTA
	} else {
#		define GETDELTA(a) procdata->iostat_delta.a  = procdata->iostat.a - oldiostat.a
		CALLS ( GETDELTA );
#		undef GETDELTA
	}

	debug(0x40, "procdata->pid == %u; procdata->iostat.syscr == %lu; procdata->iostat_delta.syscr == %lu", procdata->pid, procdata->iostat.syscr, procdata->iostat_delta.syscr);

	assert ( fclose ( f ) == 0 );
	return 0;
}

int *lastsignal;
static inline int proc_disappeared ( proc_t *procdata )
{
	debug ( 0x01, "proc_disappeared(): procdata->pid == %u", procdata->pid );
	lastsignal[procdata->pid] = 0;
	procdata->still_exists = 0;
	return 0;
}

int pslist_getiostat_wrapper ( void *_procdata, void *_arg )
{
	proc_t   *procdata = _procdata;
	iostat_t *iostat_totaldelta = _arg;

	if ( !procdata->still_exists )
		return 0;

	int err = pslist_get_iostat ( procdata );

	switch ( err ) {
		case ENOENT:
			debugpoint();
			assert ( proc_disappeared ( procdata ) == 0 );
			break;

		case 0:
			break;

		default:
			assert ( 0 );
	}

	if ( iostat_totaldelta != NULL ) {
#		define UPDATE_TOTALDELTA(a) iostat_totaldelta->a += procdata->iostat_delta.a
		CALLS ( UPDATE_TOTALDELTA );
#		undef UPDATE_TOTALDELTA
	}

	return 0;
}

int getstatus ( proc_t *procdata )
{
	char status_path[PATH_MAX];
	assert ( procdata != NULL );
	assert ( snprintf ( status_path, PATH_MAX, PATH_PROCFS"/%u/stat", procdata->pid ) > 0 );
	FILE *f;

	if ( ( f = fopen ( status_path, "r" ) ) == NULL )
		return errno;

	{
		pid_t read_pid;
		char name[PATH_MAX];
		assert ( fscanf ( f, "%i %s %c", &read_pid, name, &procdata->status ) == 3 );
	}
	assert ( fclose ( f ) == 0 );
	return 0;
}

int running = 1;
pid_t pid_max;

proc_t *pslist_rescan_onedir ( char *dentry_name, array_t *pslist )
{
	int err, ioclass;
	proc_t *procdata;
	err = 0;
	pid_t pid = xstrtol ( dentry_name, &err );
	assert ( err == 0 /* xstrtol ( dent->d_name, &err ) */ );
	ioclass = IOPRIO_PRIO_CLASS ( ioprio_get ( IOPRIO_WHO_PROCESS, pid ) );
	debug ( 0x20, "pid == %u; ioclass == %i", pid, ioclass );

	if ( ioclass != IOPRIO_CLASS_IDLE )
		return NULL;

	procdata = ( proc_t * ) array_newelement ( pslist );
	procdata->pid     = pid;
	procdata->ioclass = IOPRIO_PRIO_CLASS ( ioprio_get ( IOPRIO_WHO_PROCESS, pid ) );
	procdata->still_exists = 1;

	switch ( getstatus ( procdata ) ) {
		case 0:
			break;

		case ENOENT:
			debugpoint();
			proc_disappeared ( procdata );
			break;

		default:
			assert_witherrno ( 0 );
			break;
	}

	switch ( procdata->status ) {
		case STATUS_STOPPED:
			procdata->stopped = ( lastsignal[procdata->pid] == SIGSTOP ? STOPPED_INTERNAL : STOPPED_EXTERNAL );
			break;

		default:
			if ( lastsignal[procdata->pid] == SIGSTOP )
				lastsignal[procdata->pid] = 0;

			procdata->stopped = NOT_STOPPED;
			break;
	}

	pslist_getiostat_wrapper ( procdata, NULL );
	memset ( &procdata->iostat_delta, 0, sizeof ( procdata->iostat_delta ) );
	return procdata;
}

array_t *pslist_new = NULL;
array_t *pslist_cur = NULL;
int pslist_rescan()
{
	DIR *procdir = opendir ( PATH_PROCFS );
	assert_witherrno ( procdir != NULL );
	assert ( array_lock ( pslist_new ) == 0 );

	if ( pslist_new->otherdata == NULL ) {
		pslist_new->otherdata = xcalloc ( 1, sizeof ( *pslist_new->otherdata ) );
	}

	array_flush ( pslist_new );
	struct dirent *dent;

	while ( ( dent = readdir ( procdir ) ) != NULL ) {
		proc_t *procdata;
		debug ( 0x20, "dent->d_name == %s", dent->d_name );

		if ( !IS_DIGIT ( dent->d_name[0] ) )
			continue;

		// the process itself
		procdata = pslist_rescan_onedir ( dent->d_name, pslist_new );

		if ( procdata == NULL )
			continue;

		// children-threads
		DIR *tasksdir = NULL;
		struct dirent *task_dent;
		{
			char tasks_path[PATH_MAX];
			assert ( snprintf ( tasks_path, PATH_MAX, PATH_PROCFS"/%u/task", procdata->pid ) > 0 );
			tasksdir = opendir ( tasks_path );

			if ( tasksdir == NULL ) {
				debugpoint();
				proc_disappeared ( procdata );
				continue;
			}
		}

		while ( ( task_dent = readdir ( tasksdir ) ) != NULL ) {
			if ( !IS_DIGIT ( task_dent->d_name[0] ) )
				continue;

			if ( !strcmp ( task_dent->d_name, dent->d_name ) )
				continue;

			procdata = pslist_rescan_onedir ( task_dent->d_name, pslist_new );
		}
	}

	assert ( array_unlock ( pslist_new ) == 0 );
	closedir ( procdir );
	pslist_new = __atomic_exchange_n ( &pslist_cur, pslist_new, __ATOMIC_RELAXED );
	return 0;
}

pthread_t pslist_rescan_thread;
void *pslist_rescan_loop ( void *_arg )
{
	while ( running ) {
		usleep ( TIME_RESCAN_INTERVAL );
		assert ( pslist_rescan() == 0 );
	}

	return NULL;
}

struct data {
	int64_t  score_left;
	proc_t  *proc_running;
};
typedef struct data data_t;


#define DELTA_TO_REVERSE_SCORE(delta) delta.syscr + delta.syscw * READ_WRITE_RATIO

static inline int sendsig ( data_t *data, proc_t *procdata, int signal )
{
	debug ( 0x08, "sendsig(): sending signal %i to %u", signal, procdata->pid );

	if ( kill ( procdata->pid, signal ) == -1 ) {
		switch ( errno ) {
			case ESRCH:
				debugpoint();
				assert ( proc_disappeared ( procdata ) == 0 );
				data->score_left = 1;
				return 0;

			default:
				assert_witherrno ( 0 );
				return 1;
		}
	}

	lastsignal[procdata->pid] = signal;
	return 0;
}

int iteration ( void *_procdata, void *_arg )
{
	proc_t	*procdata	= _procdata;
	data_t	*data		= _arg;

	if ( !procdata->reverse_score )
		return 0;

	if ( !procdata->still_exists )
		return 0;

	if ( procdata->stopped == STOPPED_EXTERNAL )
		return 0;

	if ( data->score_left > 0 ) {
		if ( procdata->score >= data->score_left ) {
			data->proc_running = procdata;

			if ( procdata->stopped == STOPPED_INTERNAL ) {
				assert ( sendsig ( data, procdata, SIGCONT ) == 0 );
				procdata->stopped = NOT_STOPPED;
			}
		}

		data->score_left -= procdata->score;
	}

	if ( procdata->stopped == NOT_STOPPED ) {
		assert ( sendsig ( data, procdata, SIGSTOP ) == 0 );
		procdata->stopped = STOPPED_INTERNAL;
	}

	return 0;
}

struct gettotalscore_args {
	iostat_t iostat_totaldelta;
	int64_t total_score;
	int64_t total_reverse_score;
};
typedef struct gettotalscore_args gettotalscore_args_t;

int gettotalscore ( void *_procdata, void *_arg )
{
	//debugpoint();
	proc_t			*procdata		= _procdata;
	gettotalscore_args_t	*gettotalscore_args	= _arg;
	debug ( 0x01, "procdata->pid == %u; procdata->still_exists == %u", procdata->pid, procdata->still_exists );

	if ( !procdata->still_exists )
		return 0;

	procdata->reverse_score = DELTA_TO_REVERSE_SCORE ( procdata->iostat_delta );
	debug ( 0x04, "procdata->pid == %u; procdata->reverse_score == %li (%lu %lu)", procdata->pid, procdata->reverse_score, procdata->iostat_delta.syscr, procdata->iostat_delta.syscr );

	if ( procdata->reverse_score == 0 )
		procdata->score = 0;
	else
		procdata->score = ( double ) gettotalscore_args->total_reverse_score * ( double ) pid_max / ( double ) procdata->reverse_score;

	debug ( 0x04, "procdata->pid == %u, procdata->score == %li", procdata->pid, procdata->score );
	gettotalscore_args->total_score += procdata->score;
	return 0;
}

void *pslist_main_loop ( void *_arg )
{
	gettotalscore_args_t gettotalscore_args;

	while ( running ) {
		array_t *pslist;
		data_t *data;
		memset ( &gettotalscore_args, 0, sizeof ( gettotalscore_args ) );
		usleep ( TIME_QUANTUM );
		pslist = __atomic_load_n ( &pslist_cur, __ATOMIC_RELAXED );
		assert ( array_lock ( pslist ) == 0 );
		data = pslist->otherdata;
		assert ( array_foreach ( pslist, pslist_getiostat_wrapper, &gettotalscore_args.iostat_totaldelta ) == 0 );
		gettotalscore_args.total_reverse_score = DELTA_TO_REVERSE_SCORE ( gettotalscore_args.iostat_totaldelta );
		assert ( array_foreach ( pslist, gettotalscore,            &gettotalscore_args ) == 0 );
		uint32_t selector0 = rand();
		uint32_t selector1 = rand();
		uint64_t selector  = ( ( uint64_t ) selector0 << 32 ) + ( uint64_t ) selector1;
		debug ( 0x02, "gettotalscore_args.total_score == %li", gettotalscore_args.total_score );

		if ( gettotalscore_args.total_score == 0 ) {
			assert ( array_unlock ( pslist ) == 0 );
			continue;
		}

		selector %= gettotalscore_args.total_score;
		debug ( 0x02, "selector == %li", selector );
		data->score_left = selector;
		assert ( array_foreach ( pslist, iteration, data ) == 0 );
		assert ( array_unlock ( pslist ) == 0 );
	}

	return NULL;
}

int main()
{
	array_t *pslist[2];
	pslist_new = pslist[ 0 ] = array_init ( sizeof ( proc_t ) );
	pslist_cur = pslist[ 1 ] = array_init ( sizeof ( proc_t ) );
	{
		FILE *pid_max_f;
		assert_witherrno ( ( pid_max_f = fopen ( PATH_PROCFS"/sys/kernel/pid_max", "r" ) ) != NULL );
		assert ( fscanf ( pid_max_f, "%u", &pid_max ) == 1 );
		assert_witherrno ( fclose ( pid_max_f ) == 0 );
	}
	lastsignal = xcalloc ( pid_max + 1, sizeof ( int ) );

	if ( pslist_rescan() != 0 ) {
		error ( "Got error while scanning /proc" );
		exit ( -1 );
	}

	srand ( time ( NULL ) );
	pthread_create ( &pslist_rescan_thread, NULL, pslist_rescan_loop, NULL );
	pslist_main_loop ( NULL );
	{
		void *ret = NULL;
		pthread_join ( pslist_rescan_thread, &ret );
	}
	array_deinit ( pslist[0] );
	array_deinit ( pslist[1] );
	return 0;
}

