#include <limits.h>

/*
 * Operations on timevals.
 *
 * NB: timercmp does not work for >= or <=.
 *
 */
#define timerisset(tvp)         ((tvp)->tv_sec || (tvp)->tv_usec)
#define timercmp(tvp, uvp, cmp) \
        (((tvp)->tv_sec == (uvp)->tv_sec && (tvp)->tv_usec cmp (uvp)->tv_usec) \
        || (tvp)->tv_sec cmp (uvp)->tv_sec)
#define timerclear(tvp)         ((tvp)->tv_sec = (tvp)->tv_usec = 0)


#ifndef bzero
#define bzero(a,n) memset(a, 0, n)
#endif

#ifndef bcopy
#define bcopy(a,b,n) memmove(b, a, n)
#endif

#ifndef bcmp
#define bcmp(a, b, n) memcmp(a, b, n)
#endif 

#if defined(__VAX) || (defined(__ALPHA) && __VMS_VER < 70000000)
extern char *strdup(const char *);
extern int strcasecmp(const register char *s1, const register char *s2);
extern int gettimeofday(void *__tp, void *__tzp);

#if defined(__VAX) && __DECC_VER < 60000000
#define FD_SETSIZE      32
typedef long fd_mask;
#define NBBY    8                            /* bits per byte */
#define NFDBITS (sizeof(fd_mask) * NBBY)     /* bits per mask */
#define __howmany(__x, __y)   (((__x)+((__y)-1))/(__y))
typedef struct __fd_set {
   fd_mask fds_bits[__howmany(FD_SETSIZE, NFDBITS)];
} __fd_set;
typedef int fd_set;

#define	FD_SET(n, p)	(((__fd_set *)(p))->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	(((__fd_set *)(p))->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	(((__fd_set *)(p))->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	(*(p) = 0)
#endif

#endif

