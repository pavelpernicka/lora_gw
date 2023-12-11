/* --- DEPENDENCIES --------------------------------------------------------- */

/* fix an issue between POSIX and C99 */
#if __STDC_VERSION__ >= 199901L
    #define _XOPEN_SOURCE 600
#else
    #define _XOPEN_SOURCE 500
#endif

#define VERBOSE 0           //enable/disable prints
#include <stdint.h>         /* C99 types */
#include <stdbool.h>        /* bool type */
#include <stdio.h>          /* printf, fprintf, snprintf, fopen, fputs */

#include <string.h>         /* memset */
#include <signal.h>         /* sigaction */
#include <time.h>           /* time, clock_gettime, strftime, gmtime */
#include <sys/time.h>       /* timeval */
#include <unistd.h>         /* getopt, access */
#include <stdlib.h>         /* atoi, exit */
#include <errno.h>          /* error messages */
#include <math.h>           /* modf */

#include <sys/socket.h>     /* socket specific definitions */
#include <netinet/in.h>     /* INET constants and stuff */
#include <arpa/inet.h>      /* IP address conversion stuff */
#include <netinet/tcp.h>
#include <netdb.h>          /* gai_strerror */

#include <pthread.h>

#include "trace.h"
#include "jitqueue.h"
#include "timersync.h"
#include "parson.h"
#include "base64.h"
#include "loragw_hal.h"
#include "loragw_gps.h"
#include "loragw_aux.h"
#include "loragw_reg.h"
#include "crypto/lw_crypto.h"
#include "lw_packets.h"
#include "module_logging.h"

#include <assert.h>
#include <inttypes.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>


#include "crypto/lw_crypto.h"

#include "cmac.h"
#include "aes.h"
#include <string.h>
#include "lw_crypto.h"

#define BUFFER_SIZE 1024

#define LW_KEY_LEN (16)
#define LW_MIC_LEN (4)

#define LSHIFT(v, r) do {                                       \
		int i;                                                  \
		for (i = 0; i < 15; i++)                                \
			(r)[i] = (v)[i] << 1 | (v)[i + 1] >> 7;         \
		(r)[15] = (v)[15] << 1;                                 \
	} while (0)

#define XOR(v, r) do {                                          \
		int i;                                                  \
		for (i = 0; i < 16; i++)     \
		{	\
					(r)[i] = (r)[i] ^ (v)[i]; \
		}                          \
	} while (0) \


#define MIN(a,b) (((a)<(b))?(a):(b))


/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))
#define STRINGIFY(x)    #x
#define STR(x)          STRINGIFY(x)

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */

#ifndef VERSION_STRING
  #define VERSION_STRING "undefined"
#endif

#define DEFAULT_SERVER      127.0.0.1   /* hostname also supported */
#define DEFAULT_PORT_UP     1780
#define DEFAULT_PORT_DW     1782
#define DEFAULT_KEEPALIVE   5           /* default time interval for downstream keep-alive packet */
#define DEFAULT_STAT        60          /* default time interval for statistics */
#define PUSH_TIMEOUT_MS     100
#define PULL_TIMEOUT_MS     200
#define GPS_REF_MAX_AGE     30          /* maximum admitted delay in seconds of GPS loss before considering latest GPS sync unusable */
#define FETCH_SLEEP_MS      10          /* nb of ms waited when a fetch return no packets */
#define BEACON_POLL_MS      50          /* time in ms between polling of beacon TX status */

#define PROTOCOL_VERSION    2           /* v1.3 */

#define XERR_INIT_AVG       128         /* nb of measurements the XTAL correction is averaged on as initial value */
#define XERR_FILT_COEF      256         /* coefficient for low-pass XTAL error tracking */

#define PKT_PUSH_DATA   0
#define PKT_PUSH_ACK    1
#define PKT_PULL_DATA   2
#define PKT_PULL_RESP   3
#define PKT_PULL_ACK    4
#define PKT_TX_ACK      5

#define NB_PKT_MAX      8 /* max number of packets per fetch/send cycle */

#define MIN_LORA_PREAMB 6 /* minimum Lora preamble length for this application */
#define STD_LORA_PREAMB 8
#define MIN_FSK_PREAMB  3 /* minimum FSK preamble length for this application */
#define STD_FSK_PREAMB  5

#define STATUS_SIZE     200
#define TX_BUFF_SIZE    ((540 * NB_PKT_MAX) + 30 + STATUS_SIZE)

#define UNIX_GPS_EPOCH_OFFSET 315964800 /* Number of seconds ellapsed between 01.Jan.1970 00:00:00
                                                                          and 06.Jan.1980 00:00:00 */

#define DEFAULT_BEACON_FREQ_HZ      869525000
#define DEFAULT_BEACON_FREQ_NB      1
#define DEFAULT_BEACON_FREQ_STEP    0
#define DEFAULT_BEACON_DATARATE     9
#define DEFAULT_BEACON_BW_HZ        125000
#define DEFAULT_BEACON_POWER        14
#define DEFAULT_BEACON_INFODESC     0
#if 1
#  define HAVE_MEMCPY
#  include <string.h>
#  if defined( _MSC_VER )
#    include <intrin.h>
#    pragma intrinsic( memcpy )
#  endif
#endif

#define h_addr h_addr_list[0] /* for backward compatibility */

/* define if you have fast 32-bit types on your system */
#if 0
#  define HAVE_UINT_32T
#endif

/* define if you don't want any tables */
#if 1
#  define USE_TABLES
#endif

/*  On Intel Core 2 duo VERSION_1 is faster */

/* alternative versions (test for performance on your system) */
#if 0
#  define VERSION_1
#endif

#if defined( HAVE_UINT_32T )
  typedef unsigned uint_32t;  // Edited by Semtech - David Roe 1 Dec 13
#endif
typedef struct {
  int *array;
  size_t used;
  size_t size;
} Array;

/* functions for finite field multiplication in the AES Galois field    */

#define WPOLY   0x011b
#define BPOLY     0x1b
#define DPOLY   0x008d

#define f1(x)   (x)
#define f2(x)   ((x << 1) ^ (((x >> 7) & 1) * WPOLY))
#define f4(x)   ((x << 2) ^ (((x >> 6) & 1) * WPOLY) ^ (((x >> 6) & 2) * WPOLY))
#define f8(x)   ((x << 3) ^ (((x >> 5) & 1) * WPOLY) ^ (((x >> 5) & 2) * WPOLY) \
						  ^ (((x >> 5) & 4) * WPOLY))
#define d2(x)   (((x) >> 1) ^ ((x) & 1 ? DPOLY : 0))

#define f3(x)   (f2(x) ^ x)
#define f9(x)   (f8(x) ^ x)
#define fb(x)   (f8(x) ^ f2(x) ^ x)
#define fd(x)   (f8(x) ^ f4(x) ^ x)
#define fe(x)   (f8(x) ^ f4(x) ^ f2(x))

#if defined( USE_TABLES )

#define sb_data(w) {    /* S Box data values */                            \
	w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),\
	w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76),\
	w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0),\
	w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0),\
	w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc),\
	w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15),\
	w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a),\
	w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75),\
	w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0),\
	w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84),\
	w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b),\
	w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf),\
	w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85),\
	w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8),\
	w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5),\
	w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2),\
	w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17),\
	w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73),\
	w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88),\
	w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb),\
	w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c),\
	w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79),\
	w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9),\
	w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08),\
	w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6),\
	w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a),\
	w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e),\
	w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e),\
	w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94),\
	w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf),\
	w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68),\
	w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16) }

#define isb_data(w) {   /* inverse S Box data values */                    \
	w(0x52), w(0x09), w(0x6a), w(0xd5), w(0x30), w(0x36), w(0xa5), w(0x38),\
	w(0xbf), w(0x40), w(0xa3), w(0x9e), w(0x81), w(0xf3), w(0xd7), w(0xfb),\
	w(0x7c), w(0xe3), w(0x39), w(0x82), w(0x9b), w(0x2f), w(0xff), w(0x87),\
	w(0x34), w(0x8e), w(0x43), w(0x44), w(0xc4), w(0xde), w(0xe9), w(0xcb),\
	w(0x54), w(0x7b), w(0x94), w(0x32), w(0xa6), w(0xc2), w(0x23), w(0x3d),\
	w(0xee), w(0x4c), w(0x95), w(0x0b), w(0x42), w(0xfa), w(0xc3), w(0x4e),\
	w(0x08), w(0x2e), w(0xa1), w(0x66), w(0x28), w(0xd9), w(0x24), w(0xb2),\
	w(0x76), w(0x5b), w(0xa2), w(0x49), w(0x6d), w(0x8b), w(0xd1), w(0x25),\
	w(0x72), w(0xf8), w(0xf6), w(0x64), w(0x86), w(0x68), w(0x98), w(0x16),\
	w(0xd4), w(0xa4), w(0x5c), w(0xcc), w(0x5d), w(0x65), w(0xb6), w(0x92),\
	w(0x6c), w(0x70), w(0x48), w(0x50), w(0xfd), w(0xed), w(0xb9), w(0xda),\
	w(0x5e), w(0x15), w(0x46), w(0x57), w(0xa7), w(0x8d), w(0x9d), w(0x84),\
	w(0x90), w(0xd8), w(0xab), w(0x00), w(0x8c), w(0xbc), w(0xd3), w(0x0a),\
	w(0xf7), w(0xe4), w(0x58), w(0x05), w(0xb8), w(0xb3), w(0x45), w(0x06),\
	w(0xd0), w(0x2c), w(0x1e), w(0x8f), w(0xca), w(0x3f), w(0x0f), w(0x02),\
	w(0xc1), w(0xaf), w(0xbd), w(0x03), w(0x01), w(0x13), w(0x8a), w(0x6b),\
	w(0x3a), w(0x91), w(0x11), w(0x41), w(0x4f), w(0x67), w(0xdc), w(0xea),\
	w(0x97), w(0xf2), w(0xcf), w(0xce), w(0xf0), w(0xb4), w(0xe6), w(0x73),\
	w(0x96), w(0xac), w(0x74), w(0x22), w(0xe7), w(0xad), w(0x35), w(0x85),\
	w(0xe2), w(0xf9), w(0x37), w(0xe8), w(0x1c), w(0x75), w(0xdf), w(0x6e),\
	w(0x47), w(0xf1), w(0x1a), w(0x71), w(0x1d), w(0x29), w(0xc5), w(0x89),\
	w(0x6f), w(0xb7), w(0x62), w(0x0e), w(0xaa), w(0x18), w(0xbe), w(0x1b),\
	w(0xfc), w(0x56), w(0x3e), w(0x4b), w(0xc6), w(0xd2), w(0x79), w(0x20),\
	w(0x9a), w(0xdb), w(0xc0), w(0xfe), w(0x78), w(0xcd), w(0x5a), w(0xf4),\
	w(0x1f), w(0xdd), w(0xa8), w(0x33), w(0x88), w(0x07), w(0xc7), w(0x31),\
	w(0xb1), w(0x12), w(0x10), w(0x59), w(0x27), w(0x80), w(0xec), w(0x5f),\
	w(0x60), w(0x51), w(0x7f), w(0xa9), w(0x19), w(0xb5), w(0x4a), w(0x0d),\
	w(0x2d), w(0xe5), w(0x7a), w(0x9f), w(0x93), w(0xc9), w(0x9c), w(0xef),\
	w(0xa0), w(0xe0), w(0x3b), w(0x4d), w(0xae), w(0x2a), w(0xf5), w(0xb0),\
	w(0xc8), w(0xeb), w(0xbb), w(0x3c), w(0x83), w(0x53), w(0x99), w(0x61),\
	w(0x17), w(0x2b), w(0x04), w(0x7e), w(0xba), w(0x77), w(0xd6), w(0x26),\
	w(0xe1), w(0x69), w(0x14), w(0x63), w(0x55), w(0x21), w(0x0c), w(0x7d) }

#define mm_data(w) {    /* basic data for forming finite field tables */   \
	w(0x00), w(0x01), w(0x02), w(0x03), w(0x04), w(0x05), w(0x06), w(0x07),\
	w(0x08), w(0x09), w(0x0a), w(0x0b), w(0x0c), w(0x0d), w(0x0e), w(0x0f),\
	w(0x10), w(0x11), w(0x12), w(0x13), w(0x14), w(0x15), w(0x16), w(0x17),\
	w(0x18), w(0x19), w(0x1a), w(0x1b), w(0x1c), w(0x1d), w(0x1e), w(0x1f),\
	w(0x20), w(0x21), w(0x22), w(0x23), w(0x24), w(0x25), w(0x26), w(0x27),\
	w(0x28), w(0x29), w(0x2a), w(0x2b), w(0x2c), w(0x2d), w(0x2e), w(0x2f),\
	w(0x30), w(0x31), w(0x32), w(0x33), w(0x34), w(0x35), w(0x36), w(0x37),\
	w(0x38), w(0x39), w(0x3a), w(0x3b), w(0x3c), w(0x3d), w(0x3e), w(0x3f),\
	w(0x40), w(0x41), w(0x42), w(0x43), w(0x44), w(0x45), w(0x46), w(0x47),\
	w(0x48), w(0x49), w(0x4a), w(0x4b), w(0x4c), w(0x4d), w(0x4e), w(0x4f),\
	w(0x50), w(0x51), w(0x52), w(0x53), w(0x54), w(0x55), w(0x56), w(0x57),\
	w(0x58), w(0x59), w(0x5a), w(0x5b), w(0x5c), w(0x5d), w(0x5e), w(0x5f),\
	w(0x60), w(0x61), w(0x62), w(0x63), w(0x64), w(0x65), w(0x66), w(0x67),\
	w(0x68), w(0x69), w(0x6a), w(0x6b), w(0x6c), w(0x6d), w(0x6e), w(0x6f),\
	w(0x70), w(0x71), w(0x72), w(0x73), w(0x74), w(0x75), w(0x76), w(0x77),\
	w(0x78), w(0x79), w(0x7a), w(0x7b), w(0x7c), w(0x7d), w(0x7e), w(0x7f),\
	w(0x80), w(0x81), w(0x82), w(0x83), w(0x84), w(0x85), w(0x86), w(0x87),\
	w(0x88), w(0x89), w(0x8a), w(0x8b), w(0x8c), w(0x8d), w(0x8e), w(0x8f),\
	w(0x90), w(0x91), w(0x92), w(0x93), w(0x94), w(0x95), w(0x96), w(0x97),\
	w(0x98), w(0x99), w(0x9a), w(0x9b), w(0x9c), w(0x9d), w(0x9e), w(0x9f),\
	w(0xa0), w(0xa1), w(0xa2), w(0xa3), w(0xa4), w(0xa5), w(0xa6), w(0xa7),\
	w(0xa8), w(0xa9), w(0xaa), w(0xab), w(0xac), w(0xad), w(0xae), w(0xaf),\
	w(0xb0), w(0xb1), w(0xb2), w(0xb3), w(0xb4), w(0xb5), w(0xb6), w(0xb7),\
	w(0xb8), w(0xb9), w(0xba), w(0xbb), w(0xbc), w(0xbd), w(0xbe), w(0xbf),\
	w(0xc0), w(0xc1), w(0xc2), w(0xc3), w(0xc4), w(0xc5), w(0xc6), w(0xc7),\
	w(0xc8), w(0xc9), w(0xca), w(0xcb), w(0xcc), w(0xcd), w(0xce), w(0xcf),\
	w(0xd0), w(0xd1), w(0xd2), w(0xd3), w(0xd4), w(0xd5), w(0xd6), w(0xd7),\
	w(0xd8), w(0xd9), w(0xda), w(0xdb), w(0xdc), w(0xdd), w(0xde), w(0xdf),\
	w(0xe0), w(0xe1), w(0xe2), w(0xe3), w(0xe4), w(0xe5), w(0xe6), w(0xe7),\
	w(0xe8), w(0xe9), w(0xea), w(0xeb), w(0xec), w(0xed), w(0xee), w(0xef),\
	w(0xf0), w(0xf1), w(0xf2), w(0xf3), w(0xf4), w(0xf5), w(0xf6), w(0xf7),\
	w(0xf8), w(0xf9), w(0xfa), w(0xfb), w(0xfc), w(0xfd), w(0xfe), w(0xff) }

static const uint_8t sbox[256]  =  sb_data(f1);
static const uint_8t isbox[256] = isb_data(f1);

static const uint_8t gfm2_sbox[256] = sb_data(f2);
static const uint_8t gfm3_sbox[256] = sb_data(f3);

static const uint_8t gfmul_9[256] = mm_data(f9);
static const uint_8t gfmul_b[256] = mm_data(fb);
static const uint_8t gfmul_d[256] = mm_data(fd);
static const uint_8t gfmul_e[256] = mm_data(fe);

#define s_box(x)     sbox[(x)]
#define is_box(x)    isbox[(x)]
#define gfm2_sb(x)   gfm2_sbox[(x)]
#define gfm3_sb(x)   gfm3_sbox[(x)]
#define gfm_9(x)     gfmul_9[(x)]
#define gfm_b(x)     gfmul_b[(x)]
#define gfm_d(x)     gfmul_d[(x)]
#define gfm_e(x)     gfmul_e[(x)]

#else

/* this is the high bit of x right shifted by 1 */
/* position. Since the starting polynomial has  */
/* 9 bits (0x11b), this right shift keeps the   */
/* values of all top bits within a byte         */

static uint_8t hibit(const uint_8t x)
{   uint_8t r = (uint_8t)((x >> 1) | (x >> 2));

	r |= (r >> 2);
	r |= (r >> 4);
	return (r + 1) >> 1;
}

/* return the inverse of the finite field element x */

static uint_8t gf_inv(const uint_8t x)
{   uint_8t p1 = x, p2 = BPOLY, n1 = hibit(x), n2 = 0x80, v1 = 1, v2 = 0;

	if(x < 2)
		return x;

	for( ; ; )
	{
		if(n1)
			while(n2 >= n1)             /* divide polynomial p2 by p1    */
			{
				n2 /= n1;               /* shift smaller polynomial left */
				p2 ^= (p1 * n2) & 0xff; /* and remove from larger one    */
				v2 ^= (v1 * n2);        /* shift accumulated value and   */
				n2 = hibit(p2);         /* add into result               */
			}
		else
			return v1;

		if(n2)                          /* repeat with values swapped    */
			while(n1 >= n2)
			{
				n1 /= n2;
				p1 ^= p2 * n1;
				v1 ^= v2 * n1;
				n1 = hibit(p1);
			}
		else
			return v2;
	}
}

/* The forward and inverse affine transformations used in the S-box */
uint_8t fwd_affine(const uint_8t x)
{
#if defined( HAVE_UINT_32T )
	uint_32t w = x;
	w ^= (w << 1) ^ (w << 2) ^ (w << 3) ^ (w << 4);
	return 0x63 ^ ((w ^ (w >> 8)) & 0xff);
#else
	return 0x63 ^ x ^ (x << 1) ^ (x << 2) ^ (x << 3) ^ (x << 4)
					^ (x >> 7) ^ (x >> 6) ^ (x >> 5) ^ (x >> 4);
#endif
}

uint_8t inv_affine(const uint_8t x)
{
#if defined( HAVE_UINT_32T )
	uint_32t w = x;
	w = (w << 1) ^ (w << 3) ^ (w << 6);
	return 0x05 ^ ((w ^ (w >> 8)) & 0xff);
#else
	return 0x05 ^ (x << 1) ^ (x << 3) ^ (x << 6)
				^ (x >> 7) ^ (x >> 5) ^ (x >> 2);
#endif
}

#define s_box(x)   fwd_affine(gf_inv(x))
#define is_box(x)  gf_inv(inv_affine(x))
#define gfm2_sb(x) f2(s_box(x))
#define gfm3_sb(x) f3(s_box(x))
#define gfm_9(x)   f9(x)
#define gfm_b(x)   fb(x)
#define gfm_d(x)   fd(x)
#define gfm_e(x)   fe(x)

#endif

#if defined( HAVE_MEMCPY )
#  define block_copy_nn(d, s, l)    memcpy(d, s, l)
#  define block_copy(d, s)          memcpy(d, s, N_BLOCK)
#else
#  define block_copy_nn(d, s, l)    copy_block_nn(d, s, l)
#  define block_copy(d, s)          copy_block(d, s)

static void copy_block( void *d, const void *s )
{
#if defined( HAVE_UINT_32T )
	((uint_32t*)d)[ 0] = ((uint_32t*)s)[ 0];
	((uint_32t*)d)[ 1] = ((uint_32t*)s)[ 1];
	((uint_32t*)d)[ 2] = ((uint_32t*)s)[ 2];
	((uint_32t*)d)[ 3] = ((uint_32t*)s)[ 3];
#else
	((uint_8t*)d)[ 0] = ((uint_8t*)s)[ 0];
	((uint_8t*)d)[ 1] = ((uint_8t*)s)[ 1];
	((uint_8t*)d)[ 2] = ((uint_8t*)s)[ 2];
	((uint_8t*)d)[ 3] = ((uint_8t*)s)[ 3];
	((uint_8t*)d)[ 4] = ((uint_8t*)s)[ 4];
	((uint_8t*)d)[ 5] = ((uint_8t*)s)[ 5];
	((uint_8t*)d)[ 6] = ((uint_8t*)s)[ 6];
	((uint_8t*)d)[ 7] = ((uint_8t*)s)[ 7];
	((uint_8t*)d)[ 8] = ((uint_8t*)s)[ 8];
	((uint_8t*)d)[ 9] = ((uint_8t*)s)[ 9];
	((uint_8t*)d)[10] = ((uint_8t*)s)[10];
	((uint_8t*)d)[11] = ((uint_8t*)s)[11];
	((uint_8t*)d)[12] = ((uint_8t*)s)[12];
	((uint_8t*)d)[13] = ((uint_8t*)s)[13];
	((uint_8t*)d)[14] = ((uint_8t*)s)[14];
	((uint_8t*)d)[15] = ((uint_8t*)s)[15];
#endif
}

static void copy_block_nn( uint_8t * d, const uint_8t *s, uint_8t nn )
{
	while( nn-- )
		//*((uint_8t*)d)++ = *((uint_8t*)s)++;
		*d++ = *s++;
}

#endif /* HAVE_MEMCPY */

static void xor_block( void *d, const void *s )
{
#if defined( HAVE_UINT_32T )
	((uint_32t*)d)[ 0] ^= ((uint_32t*)s)[ 0];
	((uint_32t*)d)[ 1] ^= ((uint_32t*)s)[ 1];
	((uint_32t*)d)[ 2] ^= ((uint_32t*)s)[ 2];
	((uint_32t*)d)[ 3] ^= ((uint_32t*)s)[ 3];
#else
	((uint_8t*)d)[ 0] ^= ((uint_8t*)s)[ 0];
	((uint_8t*)d)[ 1] ^= ((uint_8t*)s)[ 1];
	((uint_8t*)d)[ 2] ^= ((uint_8t*)s)[ 2];
	((uint_8t*)d)[ 3] ^= ((uint_8t*)s)[ 3];
	((uint_8t*)d)[ 4] ^= ((uint_8t*)s)[ 4];
	((uint_8t*)d)[ 5] ^= ((uint_8t*)s)[ 5];
	((uint_8t*)d)[ 6] ^= ((uint_8t*)s)[ 6];
	((uint_8t*)d)[ 7] ^= ((uint_8t*)s)[ 7];
	((uint_8t*)d)[ 8] ^= ((uint_8t*)s)[ 8];
	((uint_8t*)d)[ 9] ^= ((uint_8t*)s)[ 9];
	((uint_8t*)d)[10] ^= ((uint_8t*)s)[10];
	((uint_8t*)d)[11] ^= ((uint_8t*)s)[11];
	((uint_8t*)d)[12] ^= ((uint_8t*)s)[12];
	((uint_8t*)d)[13] ^= ((uint_8t*)s)[13];
	((uint_8t*)d)[14] ^= ((uint_8t*)s)[14];
	((uint_8t*)d)[15] ^= ((uint_8t*)s)[15];
#endif
}

static void copy_and_key( void *d, const void *s, const void *k )
{
#if defined( HAVE_UINT_32T )
	((uint_32t*)d)[ 0] = ((uint_32t*)s)[ 0] ^ ((uint_32t*)k)[ 0];
	((uint_32t*)d)[ 1] = ((uint_32t*)s)[ 1] ^ ((uint_32t*)k)[ 1];
	((uint_32t*)d)[ 2] = ((uint_32t*)s)[ 2] ^ ((uint_32t*)k)[ 2];
	((uint_32t*)d)[ 3] = ((uint_32t*)s)[ 3] ^ ((uint_32t*)k)[ 3];
#elif 1
	((uint_8t*)d)[ 0] = ((uint_8t*)s)[ 0] ^ ((uint_8t*)k)[ 0];
	((uint_8t*)d)[ 1] = ((uint_8t*)s)[ 1] ^ ((uint_8t*)k)[ 1];
	((uint_8t*)d)[ 2] = ((uint_8t*)s)[ 2] ^ ((uint_8t*)k)[ 2];
	((uint_8t*)d)[ 3] = ((uint_8t*)s)[ 3] ^ ((uint_8t*)k)[ 3];
	((uint_8t*)d)[ 4] = ((uint_8t*)s)[ 4] ^ ((uint_8t*)k)[ 4];
	((uint_8t*)d)[ 5] = ((uint_8t*)s)[ 5] ^ ((uint_8t*)k)[ 5];
	((uint_8t*)d)[ 6] = ((uint_8t*)s)[ 6] ^ ((uint_8t*)k)[ 6];
	((uint_8t*)d)[ 7] = ((uint_8t*)s)[ 7] ^ ((uint_8t*)k)[ 7];
	((uint_8t*)d)[ 8] = ((uint_8t*)s)[ 8] ^ ((uint_8t*)k)[ 8];
	((uint_8t*)d)[ 9] = ((uint_8t*)s)[ 9] ^ ((uint_8t*)k)[ 9];
	((uint_8t*)d)[10] = ((uint_8t*)s)[10] ^ ((uint_8t*)k)[10];
	((uint_8t*)d)[11] = ((uint_8t*)s)[11] ^ ((uint_8t*)k)[11];
	((uint_8t*)d)[12] = ((uint_8t*)s)[12] ^ ((uint_8t*)k)[12];
	((uint_8t*)d)[13] = ((uint_8t*)s)[13] ^ ((uint_8t*)k)[13];
	((uint_8t*)d)[14] = ((uint_8t*)s)[14] ^ ((uint_8t*)k)[14];
	((uint_8t*)d)[15] = ((uint_8t*)s)[15] ^ ((uint_8t*)k)[15];
#else
	block_copy(d, s);
	xor_block(d, k);
#endif
}
#if defined( VERSION_1 )
static void add_round_key( uint_8t d[N_BLOCK], const uint_8t k[N_BLOCK] )
{
	xor_block(d, k);
}
#endif
static void shift_sub_rows( uint_8t st[N_BLOCK] )
{   uint_8t tt;

	st[ 0] = s_box(st[ 0]); st[ 4] = s_box(st[ 4]);
	st[ 8] = s_box(st[ 8]); st[12] = s_box(st[12]);

	tt = st[1]; st[ 1] = s_box(st[ 5]); st[ 5] = s_box(st[ 9]);
	st[ 9] = s_box(st[13]); st[13] = s_box( tt );

	tt = st[2]; st[ 2] = s_box(st[10]); st[10] = s_box( tt );
	tt = st[6]; st[ 6] = s_box(st[14]); st[14] = s_box( tt );

	tt = st[15]; st[15] = s_box(st[11]); st[11] = s_box(st[ 7]);
	st[ 7] = s_box(st[ 3]); st[ 3] = s_box( tt );
}

static void inv_shift_sub_rows( uint_8t st[N_BLOCK] )
{   uint_8t tt;

	st[ 0] = is_box(st[ 0]); st[ 4] = is_box(st[ 4]);
	st[ 8] = is_box(st[ 8]); st[12] = is_box(st[12]);

	tt = st[13]; st[13] = is_box(st[9]); st[ 9] = is_box(st[5]);
	st[ 5] = is_box(st[1]); st[ 1] = is_box( tt );

	tt = st[2]; st[ 2] = is_box(st[10]); st[10] = is_box( tt );
	tt = st[6]; st[ 6] = is_box(st[14]); st[14] = is_box( tt );

	tt = st[3]; st[ 3] = is_box(st[ 7]); st[ 7] = is_box(st[11]);
	st[11] = is_box(st[15]); st[15] = is_box( tt );
}

#if defined( VERSION_1 )
  static void mix_sub_columns( uint_8t dt[N_BLOCK] )
  { uint_8t st[N_BLOCK];
	block_copy(st, dt);
#else
  static void mix_sub_columns( uint_8t dt[N_BLOCK], uint_8t st[N_BLOCK] )
  {
#endif
	dt[ 0] = gfm2_sb(st[0]) ^ gfm3_sb(st[5]) ^ s_box(st[10]) ^ s_box(st[15]);
	dt[ 1] = s_box(st[0]) ^ gfm2_sb(st[5]) ^ gfm3_sb(st[10]) ^ s_box(st[15]);
	dt[ 2] = s_box(st[0]) ^ s_box(st[5]) ^ gfm2_sb(st[10]) ^ gfm3_sb(st[15]);
	dt[ 3] = gfm3_sb(st[0]) ^ s_box(st[5]) ^ s_box(st[10]) ^ gfm2_sb(st[15]);

	dt[ 4] = gfm2_sb(st[4]) ^ gfm3_sb(st[9]) ^ s_box(st[14]) ^ s_box(st[3]);
	dt[ 5] = s_box(st[4]) ^ gfm2_sb(st[9]) ^ gfm3_sb(st[14]) ^ s_box(st[3]);
	dt[ 6] = s_box(st[4]) ^ s_box(st[9]) ^ gfm2_sb(st[14]) ^ gfm3_sb(st[3]);
	dt[ 7] = gfm3_sb(st[4]) ^ s_box(st[9]) ^ s_box(st[14]) ^ gfm2_sb(st[3]);

	dt[ 8] = gfm2_sb(st[8]) ^ gfm3_sb(st[13]) ^ s_box(st[2]) ^ s_box(st[7]);
	dt[ 9] = s_box(st[8]) ^ gfm2_sb(st[13]) ^ gfm3_sb(st[2]) ^ s_box(st[7]);
	dt[10] = s_box(st[8]) ^ s_box(st[13]) ^ gfm2_sb(st[2]) ^ gfm3_sb(st[7]);
	dt[11] = gfm3_sb(st[8]) ^ s_box(st[13]) ^ s_box(st[2]) ^ gfm2_sb(st[7]);

	dt[12] = gfm2_sb(st[12]) ^ gfm3_sb(st[1]) ^ s_box(st[6]) ^ s_box(st[11]);
	dt[13] = s_box(st[12]) ^ gfm2_sb(st[1]) ^ gfm3_sb(st[6]) ^ s_box(st[11]);
	dt[14] = s_box(st[12]) ^ s_box(st[1]) ^ gfm2_sb(st[6]) ^ gfm3_sb(st[11]);
	dt[15] = gfm3_sb(st[12]) ^ s_box(st[1]) ^ s_box(st[6]) ^ gfm2_sb(st[11]);
  }

#if defined( VERSION_1 )
  static void inv_mix_sub_columns( uint_8t dt[N_BLOCK] )
  { uint_8t st[N_BLOCK];
	block_copy(st, dt);
#else
  static void inv_mix_sub_columns( uint_8t dt[N_BLOCK], uint_8t st[N_BLOCK] )
  {
#endif
	dt[ 0] = is_box(gfm_e(st[ 0]) ^ gfm_b(st[ 1]) ^ gfm_d(st[ 2]) ^ gfm_9(st[ 3]));
	dt[ 5] = is_box(gfm_9(st[ 0]) ^ gfm_e(st[ 1]) ^ gfm_b(st[ 2]) ^ gfm_d(st[ 3]));
	dt[10] = is_box(gfm_d(st[ 0]) ^ gfm_9(st[ 1]) ^ gfm_e(st[ 2]) ^ gfm_b(st[ 3]));
	dt[15] = is_box(gfm_b(st[ 0]) ^ gfm_d(st[ 1]) ^ gfm_9(st[ 2]) ^ gfm_e(st[ 3]));

	dt[ 4] = is_box(gfm_e(st[ 4]) ^ gfm_b(st[ 5]) ^ gfm_d(st[ 6]) ^ gfm_9(st[ 7]));
	dt[ 9] = is_box(gfm_9(st[ 4]) ^ gfm_e(st[ 5]) ^ gfm_b(st[ 6]) ^ gfm_d(st[ 7]));
	dt[14] = is_box(gfm_d(st[ 4]) ^ gfm_9(st[ 5]) ^ gfm_e(st[ 6]) ^ gfm_b(st[ 7]));
	dt[ 3] = is_box(gfm_b(st[ 4]) ^ gfm_d(st[ 5]) ^ gfm_9(st[ 6]) ^ gfm_e(st[ 7]));

	dt[ 8] = is_box(gfm_e(st[ 8]) ^ gfm_b(st[ 9]) ^ gfm_d(st[10]) ^ gfm_9(st[11]));
	dt[13] = is_box(gfm_9(st[ 8]) ^ gfm_e(st[ 9]) ^ gfm_b(st[10]) ^ gfm_d(st[11]));
	dt[ 2] = is_box(gfm_d(st[ 8]) ^ gfm_9(st[ 9]) ^ gfm_e(st[10]) ^ gfm_b(st[11]));
	dt[ 7] = is_box(gfm_b(st[ 8]) ^ gfm_d(st[ 9]) ^ gfm_9(st[10]) ^ gfm_e(st[11]));

	dt[12] = is_box(gfm_e(st[12]) ^ gfm_b(st[13]) ^ gfm_d(st[14]) ^ gfm_9(st[15]));
	dt[ 1] = is_box(gfm_9(st[12]) ^ gfm_e(st[13]) ^ gfm_b(st[14]) ^ gfm_d(st[15]));
	dt[ 6] = is_box(gfm_d(st[12]) ^ gfm_9(st[13]) ^ gfm_e(st[14]) ^ gfm_b(st[15]));
	dt[11] = is_box(gfm_b(st[12]) ^ gfm_d(st[13]) ^ gfm_9(st[14]) ^ gfm_e(st[15]));
  }

#if defined( AES_ENC_PREKEYED ) || defined( AES_DEC_PREKEYED )

/*  Set the cipher key for the pre-keyed version */

return_type aes_set_key( const unsigned char key[], length_type keylen, aes_context ctx[1] )
{
	uint_8t cc, rc, hi;

	switch( keylen )
	{
	case 16:
	case 24:
	case 32:
		break;
	default:
		ctx->rnd = 0;
		return -1;
	}
	block_copy_nn(ctx->ksch, key, keylen);
	hi = (keylen + 28) << 2;
	ctx->rnd = (hi >> 4) - 1;
	for( cc = keylen, rc = 1; cc < hi; cc += 4 )
	{   uint_8t tt, t0, t1, t2, t3;

		t0 = ctx->ksch[cc - 4];
		t1 = ctx->ksch[cc - 3];
		t2 = ctx->ksch[cc - 2];
		t3 = ctx->ksch[cc - 1];
		if( cc % keylen == 0 )
		{
			tt = t0;
			t0 = s_box(t1) ^ rc;
			t1 = s_box(t2);
			t2 = s_box(t3);
			t3 = s_box(tt);
			rc = f2(rc);
		}
		else if( keylen > 24 && cc % keylen == 16 )
		{
			t0 = s_box(t0);
			t1 = s_box(t1);
			t2 = s_box(t2);
			t3 = s_box(t3);
		}
		tt = cc - keylen;
		ctx->ksch[cc + 0] = ctx->ksch[tt + 0] ^ t0;
		ctx->ksch[cc + 1] = ctx->ksch[tt + 1] ^ t1;
		ctx->ksch[cc + 2] = ctx->ksch[tt + 2] ^ t2;
		ctx->ksch[cc + 3] = ctx->ksch[tt + 3] ^ t3;
	}
	return 0;
}

#endif

#if defined( AES_ENC_PREKEYED )

/*  Encrypt a single block of 16 bytes */

return_type aes_encrypt( const unsigned char in[N_BLOCK], unsigned char  out[N_BLOCK], const aes_context ctx[1] )
{
	if( ctx->rnd )
	{
		uint_8t s1[N_BLOCK], r;
		copy_and_key( s1, in, ctx->ksch );

		for( r = 1 ; r < ctx->rnd ; ++r )
#if defined( VERSION_1 )
		{
			mix_sub_columns( s1 );
			add_round_key( s1, ctx->ksch + r * N_BLOCK);
		}
#else
		{   uint_8t s2[N_BLOCK];
			mix_sub_columns( s2, s1 );
			copy_and_key( s1, s2, ctx->ksch + r * N_BLOCK);
		}
#endif
		shift_sub_rows( s1 );
		copy_and_key( out, s1, ctx->ksch + r * N_BLOCK );
	}
	else
		return -1;
	return 0;
}

/* CBC encrypt a number of blocks (input and return an IV) */

return_type aes_cbc_encrypt( const unsigned char *in, unsigned char *out,
						 int n_block, unsigned char iv[N_BLOCK], const aes_context ctx[1] )
{

	while(n_block--)
	{
		xor_block(iv, in);
		if(aes_encrypt(iv, iv, ctx) != EXIT_SUCCESS)
			return EXIT_FAILURE;
		//memcpy(out, iv, N_BLOCK);
		block_copy(out, iv);
		in += N_BLOCK;
		out += N_BLOCK;
	}
	return EXIT_SUCCESS;
}

#endif

#if defined( AES_DEC_PREKEYED )

/*  Decrypt a single block of 16 bytes */

return_type aes_decrypt( const unsigned char in[N_BLOCK], unsigned char out[N_BLOCK], const aes_context ctx[1] )
{
	if( ctx->rnd )
	{
		uint_8t s1[N_BLOCK], r;
		copy_and_key( s1, in, ctx->ksch + ctx->rnd * N_BLOCK );
		inv_shift_sub_rows( s1 );

		for( r = ctx->rnd ; --r ; )
#if defined( VERSION_1 )
		{
			add_round_key( s1, ctx->ksch + r * N_BLOCK );
			inv_mix_sub_columns( s1 );
		}
#else
		{   uint_8t s2[N_BLOCK];
			copy_and_key( s2, s1, ctx->ksch + r * N_BLOCK );
			inv_mix_sub_columns( s1, s2 );
		}
#endif
		copy_and_key( out, s1, ctx->ksch );
	}
	else
		return -1;
	return 0;
}

/* CBC decrypt a number of blocks (input and return an IV) */

return_type aes_cbc_decrypt( const unsigned char *in, unsigned char *out,
						 int n_block, unsigned char iv[N_BLOCK], const aes_context ctx[1] )
{
	while(n_block--)
	{   uint_8t tmp[N_BLOCK];

		//memcpy(tmp, in, N_BLOCK);
		block_copy(tmp, in);
		if(aes_decrypt(in, out, ctx) != EXIT_SUCCESS)
			return EXIT_FAILURE;
		xor_block(out, iv);
		//memcpy(iv, tmp, N_BLOCK);
		block_copy(iv, tmp);
		in += N_BLOCK;
		out += N_BLOCK;
	}
	return EXIT_SUCCESS;
}

#endif

#if defined( AES_ENC_128_OTFK )

/*  The 'on the fly' encryption key update for for 128 bit keys */

static void update_encrypt_key_128( uint_8t k[N_BLOCK], uint_8t *rc )
{   uint_8t cc;

	k[0] ^= s_box(k[13]) ^ *rc;
	k[1] ^= s_box(k[14]);
	k[2] ^= s_box(k[15]);
	k[3] ^= s_box(k[12]);
	*rc = f2( *rc );

	for(cc = 4; cc < 16; cc += 4 )
	{
		k[cc + 0] ^= k[cc - 4];
		k[cc + 1] ^= k[cc - 3];
		k[cc + 2] ^= k[cc - 2];
		k[cc + 3] ^= k[cc - 1];
	}
}

/*  Encrypt a single block of 16 bytes with 'on the fly' 128 bit keying */

void aes_encrypt_128( const unsigned char in[N_BLOCK], unsigned char out[N_BLOCK],
					 const unsigned char key[N_BLOCK], unsigned char o_key[N_BLOCK] )
{   uint_8t s1[N_BLOCK], r, rc = 1;

	if(o_key != key)
		block_copy( o_key, key );
	copy_and_key( s1, in, o_key );

	for( r = 1 ; r < 10 ; ++r )
#if defined( VERSION_1 )
	{
		mix_sub_columns( s1 );
		update_encrypt_key_128( o_key, &rc );
		add_round_key( s1, o_key );
	}
#else
	{   uint_8t s2[N_BLOCK];
		mix_sub_columns( s2, s1 );
		update_encrypt_key_128( o_key, &rc );
		copy_and_key( s1, s2, o_key );
	}
#endif

	shift_sub_rows( s1 );
	update_encrypt_key_128( o_key, &rc );
	copy_and_key( out, s1, o_key );
}

#endif

#if defined( AES_DEC_128_OTFK )

/*  The 'on the fly' decryption key update for for 128 bit keys */

static void update_decrypt_key_128( uint_8t k[N_BLOCK], uint_8t *rc )
{   uint_8t cc;

	for( cc = 12; cc > 0; cc -= 4 )
	{
		k[cc + 0] ^= k[cc - 4];
		k[cc + 1] ^= k[cc - 3];
		k[cc + 2] ^= k[cc - 2];
		k[cc + 3] ^= k[cc - 1];
	}
	*rc = d2(*rc);
	k[0] ^= s_box(k[13]) ^ *rc;
	k[1] ^= s_box(k[14]);
	k[2] ^= s_box(k[15]);
	k[3] ^= s_box(k[12]);
}

/*  Decrypt a single block of 16 bytes with 'on the fly' 128 bit keying */

void aes_decrypt_128( const unsigned char in[N_BLOCK], unsigned char out[N_BLOCK],
					  const unsigned char key[N_BLOCK], unsigned char o_key[N_BLOCK] )
{
	uint_8t s1[N_BLOCK], r, rc = 0x6c;
	if(o_key != key)
		block_copy( o_key, key );

	copy_and_key( s1, in, o_key );
	inv_shift_sub_rows( s1 );

	for( r = 10 ; --r ; )
#if defined( VERSION_1 )
	{
		update_decrypt_key_128( o_key, &rc );
		add_round_key( s1, o_key );
		inv_mix_sub_columns( s1 );
	}
#else
	{	uint_8t s2[N_BLOCK];
		update_decrypt_key_128( o_key, &rc );
		copy_and_key( s2, s1, o_key );
		inv_mix_sub_columns( s1, s2 );
	}
#endif
	update_decrypt_key_128( o_key, &rc );
	copy_and_key( out, s1, o_key );
}

#endif

#if defined( AES_ENC_256_OTFK )

/*  The 'on the fly' encryption key update for for 256 bit keys */

static void update_encrypt_key_256( uint_8t k[2 * N_BLOCK], uint_8t *rc )
{   uint_8t cc;

	k[0] ^= s_box(k[29]) ^ *rc;
	k[1] ^= s_box(k[30]);
	k[2] ^= s_box(k[31]);
	k[3] ^= s_box(k[28]);
	*rc = f2( *rc );

	for(cc = 4; cc < 16; cc += 4)
	{
		k[cc + 0] ^= k[cc - 4];
		k[cc + 1] ^= k[cc - 3];
		k[cc + 2] ^= k[cc - 2];
		k[cc + 3] ^= k[cc - 1];
	}

	k[16] ^= s_box(k[12]);
	k[17] ^= s_box(k[13]);
	k[18] ^= s_box(k[14]);
	k[19] ^= s_box(k[15]);

	for( cc = 20; cc < 32; cc += 4 )
	{
		k[cc + 0] ^= k[cc - 4];
		k[cc + 1] ^= k[cc - 3];
		k[cc + 2] ^= k[cc - 2];
		k[cc + 3] ^= k[cc - 1];
	}
}

/*  Encrypt a single block of 16 bytes with 'on the fly' 256 bit keying */

void aes_encrypt_256( const unsigned char in[N_BLOCK], unsigned char out[N_BLOCK],
					  const unsigned char key[2 * N_BLOCK], unsigned char o_key[2 * N_BLOCK] )
{
	uint_8t s1[N_BLOCK], r, rc = 1;
	if(o_key != key)
	{
		block_copy( o_key, key );
		block_copy( o_key + 16, key + 16 );
	}
	copy_and_key( s1, in, o_key );

	for( r = 1 ; r < 14 ; ++r )
#if defined( VERSION_1 )
	{
		mix_sub_columns(s1);
		if( r & 1 )
			add_round_key( s1, o_key + 16 );
		else
		{
			update_encrypt_key_256( o_key, &rc );
			add_round_key( s1, o_key );
		}
	}
#else
	{   uint_8t s2[N_BLOCK];
		mix_sub_columns( s2, s1 );
		if( r & 1 )
			copy_and_key( s1, s2, o_key + 16 );
		else
		{
			update_encrypt_key_256( o_key, &rc );
			copy_and_key( s1, s2, o_key );
		}
	}
#endif

	shift_sub_rows( s1 );
	update_encrypt_key_256( o_key, &rc );
	copy_and_key( out, s1, o_key );
}

#endif

#if defined( AES_DEC_256_OTFK )

/*  The 'on the fly' encryption key update for for 256 bit keys */

static void update_decrypt_key_256( uint_8t k[2 * N_BLOCK], uint_8t *rc )
{   uint_8t cc;

	for(cc = 28; cc > 16; cc -= 4)
	{
		k[cc + 0] ^= k[cc - 4];
		k[cc + 1] ^= k[cc - 3];
		k[cc + 2] ^= k[cc - 2];
		k[cc + 3] ^= k[cc - 1];
	}

	k[16] ^= s_box(k[12]);
	k[17] ^= s_box(k[13]);
	k[18] ^= s_box(k[14]);
	k[19] ^= s_box(k[15]);

	for(cc = 12; cc > 0; cc -= 4)
	{
		k[cc + 0] ^= k[cc - 4];
		k[cc + 1] ^= k[cc - 3];
		k[cc + 2] ^= k[cc - 2];
		k[cc + 3] ^= k[cc - 1];
	}

	*rc = d2(*rc);
	k[0] ^= s_box(k[29]) ^ *rc;
	k[1] ^= s_box(k[30]);
	k[2] ^= s_box(k[31]);
	k[3] ^= s_box(k[28]);
}

/*  Decrypt a single block of 16 bytes with 'on the fly'
	256 bit keying
*/
void aes_decrypt_256( const unsigned char in[N_BLOCK], unsigned char out[N_BLOCK],
					  const unsigned char key[2 * N_BLOCK], unsigned char o_key[2 * N_BLOCK] )
{
	uint_8t s1[N_BLOCK], r, rc = 0x80;

	if(o_key != key)
	{
		block_copy( o_key, key );
		block_copy( o_key + 16, key + 16 );
	}

	copy_and_key( s1, in, o_key );
	inv_shift_sub_rows( s1 );

	for( r = 14 ; --r ; )
#if defined( VERSION_1 )
	{
		if( ( r & 1 ) )
		{
			update_decrypt_key_256( o_key, &rc );
			add_round_key( s1, o_key + 16 );
		}
		else
			add_round_key( s1, o_key );
		inv_mix_sub_columns( s1 );
	}
#else
	{   uint_8t s2[N_BLOCK];
		if( ( r & 1 ) )
		{
			update_decrypt_key_256( o_key, &rc );
			copy_and_key( s2, s1, o_key + 16 );
		}
		else
			copy_and_key( s2, s1, o_key );
		inv_mix_sub_columns( s1, s2 );
	}
#endif
	copy_and_key( out, s1, o_key );
}

#endif


void AES_CMAC_Init(AES_CMAC_CTX *ctx)
{
	memset(ctx->X, 0, sizeof ctx->X);
	ctx->M_n = 0;
	memset(ctx->rijndael.ksch, '\0', sizeof(ctx->rijndael.ksch));
}

void AES_CMAC_SetKey(AES_CMAC_CTX *ctx, const u_int8_t key[AES_CMAC_KEY_LENGTH])
{
	//rijndael_set_key_enc_only(&ctx->rijndael, key, 128);
	aes_set_key( key, AES_CMAC_KEY_LENGTH, &ctx->rijndael);
}

void AES_CMAC_Update(AES_CMAC_CTX *ctx, const u_int8_t *data, u_int len)
{
	u_int mlen;
	unsigned char in[16];

	if (ctx->M_n > 0) {
		mlen = MIN(16 - ctx->M_n, len);
		memcpy(ctx->M_last + ctx->M_n, data, mlen);
		ctx->M_n += mlen;
		if (ctx->M_n < 16 || len == mlen)
			return;
		XOR(ctx->M_last, ctx->X);
		//rijndael_encrypt(&ctx->rijndael, ctx->X, ctx->X);
		aes_encrypt( ctx->X, ctx->X, &ctx->rijndael);
		data += mlen;
		len -= mlen;
	}
	while (len > 16) {      /* not last block */

		XOR(data, ctx->X);
		//rijndael_encrypt(&ctx->rijndael, ctx->X, ctx->X);

		memcpy(in, &ctx->X[0], 16); //Bestela ez du ondo iten
		aes_encrypt( in, in, &ctx->rijndael);
		memcpy(&ctx->X[0], in, 16);

		data += 16;
		len -= 16;
	}
	/* potential last block, save it */
	memcpy(ctx->M_last, data, len);
	ctx->M_n = len;
}

void AES_CMAC_Final(u_int8_t digest[AES_CMAC_DIGEST_LENGTH], AES_CMAC_CTX *ctx)
{
	u_int8_t K[16];
	unsigned char in[16];
	/* generate subkey K1 */
	memset(K, '\0', 16);

	//rijndael_encrypt(&ctx->rijndael, K, K);

	aes_encrypt( K, K, &ctx->rijndael);

	if (K[0] & 0x80) {
		LSHIFT(K, K);
		K[15] ^= 0x87;
	} else
		LSHIFT(K, K);


	if (ctx->M_n == 16) {
		/* last block was a complete block */
		XOR(K, ctx->M_last);

	} else {
		/* generate subkey K2 */
		if (K[0] & 0x80) {
			LSHIFT(K, K);
			K[15] ^= 0x87;
		} else
			LSHIFT(K, K);

		/* padding(M_last) */
		ctx->M_last[ctx->M_n] = 0x80;
		while (++ctx->M_n < 16)
			ctx->M_last[ctx->M_n] = 0;

		XOR(K, ctx->M_last);

	}
	XOR(ctx->M_last, ctx->X);

	//rijndael_encrypt(&ctx->rijndael, ctx->X, digest);

	memcpy(in, &ctx->X[0], 16); //Bestela ez du ondo iten
	aes_encrypt(in, digest, &ctx->rijndael);
	memset(K, 0, sizeof K);

}



/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES (GLOBAL) ------------------------------------------- */

/* signal handling variables */
volatile bool exit_sig = false; /* 1 -> application terminates cleanly (shut down hardware, close open files, etc) */
volatile bool quit_sig = false; /* 1 -> application terminates without shutting down the hardware */

/* packets filtering configuration variables */
static bool fwd_valid_pkt = true; /* packets with PAYLOAD CRC OK are forwarded */
static bool fwd_error_pkt = false; /* packets with PAYLOAD CRC ERROR are NOT forwarded */
static bool fwd_nocrc_pkt = false; /* packets with NO PAYLOAD CRC are NOT forwarded */
static bool abp = false;

/* network configuration variables */
static uint64_t lgwm = 0; /* Lora gateway MAC address */
static char serv_addr[64] = STR(DEFAULT_SERVER); /* address of the server (host name or IPv4/IPv6) */
static char serv_port_up[8] = STR(DEFAULT_PORT_UP); /* server port for upstream traffic */
static char serv_port_down[8] = STR(DEFAULT_PORT_DW); /* server port for downstream traffic */
static int keepalive_time = DEFAULT_KEEPALIVE; /* send a PULL_DATA request every X seconds, negative = disabled */

/* statistics collection configuration variables */
static unsigned stat_interval = DEFAULT_STAT; /* time interval (in sec) at which statistics are collected and displayed */

/* gateway <-> MAC protocol variables */
static uint32_t net_mac_h; /* Most Significant Nibble, network order */
static uint32_t net_mac_l; /* Least Significant Nibble, network order */

/* network sockets */
static int sock_up; /* socket for upstream traffic */
static int sock_down; /* socket for downstream traffic */

/* network protocol variables */
static struct timeval push_timeout_half = {0, (PUSH_TIMEOUT_MS * 500)}; /* cut in half, critical for throughput */
static struct timeval pull_timeout = {0, (PULL_TIMEOUT_MS * 1000)}; /* non critical for throughput */

/* hardware access control and correction */
pthread_mutex_t mx_concent = PTHREAD_MUTEX_INITIALIZER; /* control access to the concentrator */
static pthread_mutex_t mx_xcorr = PTHREAD_MUTEX_INITIALIZER; /* control access to the XTAL correction */
static bool xtal_correct_ok = false; /* set true when XTAL correction is stable enough */
static double xtal_correct = 1.0;

/* GPS configuration and synchronization */
static char gps_tty_path[64] = "\0"; /* path of the TTY port GPS is connected on */
static int gps_tty_fd = -1; /* file descriptor of the GPS TTY port */
static bool gps_enabled = false; /* is GPS enabled on that gateway ? */

/* GPS time reference */
static pthread_mutex_t mx_timeref = PTHREAD_MUTEX_INITIALIZER; /* control access to GPS time reference */
static bool gps_ref_valid; /* is GPS reference acceptable (ie. not too old) */
static struct tref time_reference_gps; /* time reference used for GPS <-> timestamp conversion */

/* Reference coordinates, for broadcasting (beacon) */
static struct coord_s reference_coord;

/* Enable faking the GPS coordinates of the gateway */
static bool gps_fake_enable; /* enable the feature */

/* measurements to establish statistics */
static pthread_mutex_t mx_meas_up = PTHREAD_MUTEX_INITIALIZER; /* control access to the upstream measurements */
static uint32_t meas_nb_rx_rcv = 0; /* count packets received */
static uint32_t meas_nb_rx_ok = 0; /* count packets received with PAYLOAD CRC OK */
static uint32_t meas_nb_rx_bad = 0; /* count packets received with PAYLOAD CRC ERROR */
static uint32_t meas_nb_rx_nocrc = 0; /* count packets received with NO PAYLOAD CRC */
static uint32_t meas_up_pkt_fwd = 0; /* number of radio packet forwarded to the server */
static uint32_t meas_up_network_byte = 0; /* sum of UDP bytes sent for upstream traffic */
static uint32_t meas_up_payload_byte = 0; /* sum of radio payload bytes sent for upstream traffic */
static uint32_t meas_up_dgram_sent = 0; /* number of datagrams sent for upstream traffic */
static uint32_t meas_up_ack_rcv = 0; /* number of datagrams acknowledged for upstream traffic */

static pthread_mutex_t mx_meas_dw = PTHREAD_MUTEX_INITIALIZER; /* control access to the downstream measurements */
static uint32_t meas_dw_pull_sent = 0; /* number of PULL requests sent for downstream traffic */
static uint32_t meas_dw_ack_rcv = 0; /* number of PULL requests acknowledged for downstream traffic */
static uint32_t meas_dw_dgram_rcv = 0; /* count PULL response packets received for downstream traffic */
static uint32_t meas_dw_network_byte = 0; /* sum of UDP bytes sent for upstream traffic */
static uint32_t meas_dw_payload_byte = 0; /* sum of radio payload bytes sent for upstream traffic */
static uint32_t meas_nb_tx_ok = 0; /* count packets emitted successfully */
static uint32_t meas_nb_tx_fail = 0; /* count packets were TX failed for other reasons */
static uint32_t meas_nb_tx_requested = 0; /* count TX request from server (downlinks) */
static uint32_t meas_nb_tx_rejected_collision_packet = 0; /* count packets were TX request were rejected due to collision with another packet already programmed */
static uint32_t meas_nb_tx_rejected_collision_beacon = 0; /* count packets were TX request were rejected due to collision with a beacon already programmed */
static uint32_t meas_nb_tx_rejected_too_late = 0; /* count packets were TX request were rejected because it is too late to program it */
static uint32_t meas_nb_tx_rejected_too_early = 0; /* count packets were TX request were rejected because timestamp is too much in advance */
static uint32_t meas_nb_beacon_queued = 0; /* count beacon inserted in jit queue */
static uint32_t meas_nb_beacon_sent = 0; /* count beacon actually sent to concentrator */
static uint32_t meas_nb_beacon_rejected = 0; /* count beacon rejected for queuing */

static pthread_mutex_t mx_meas_gps = PTHREAD_MUTEX_INITIALIZER; /* control access to the GPS statistics */
static bool gps_coord_valid; /* could we get valid GPS coordinates ? */
static struct coord_s meas_gps_coord; /* GPS position of the gateway */
static struct coord_s meas_gps_err; /* GPS position of the gateway */

static pthread_mutex_t mx_stat_rep = PTHREAD_MUTEX_INITIALIZER; /* control access to the status report */
static bool report_ready = false; /* true when there is a new report to send to the server */
static char status_report[STATUS_SIZE]; /* status report as a JSON object */

/* beacon parameters */
static uint32_t beacon_period = 0; /* set beaconing period, must be a sub-multiple of 86400, the nb of sec in a day */
static uint32_t beacon_freq_hz = DEFAULT_BEACON_FREQ_HZ; /* set beacon TX frequency, in Hz */
static uint8_t beacon_freq_nb = DEFAULT_BEACON_FREQ_NB; /* set number of beaconing channels beacon */
static uint32_t beacon_freq_step = DEFAULT_BEACON_FREQ_STEP; /* set frequency step between beacon channels, in Hz */
static uint8_t beacon_datarate = DEFAULT_BEACON_DATARATE; /* set beacon datarate (SF) */
static uint32_t beacon_bw_hz = DEFAULT_BEACON_BW_HZ; /* set beacon bandwidth, in Hz */
static int8_t beacon_power = DEFAULT_BEACON_POWER; /* set beacon TX power, in dBm */
static uint8_t beacon_infodesc = DEFAULT_BEACON_INFODESC; /* set beacon information descriptor */
uint16_t lwnonce = 3;
/* auto-quit function */
static uint32_t autoquit_threshold = 0; /* enable auto-quit after a number of non-acknowledged PULL_DATA (0 = disabled)*/

/* Just In Time TX scheduling */
static struct jit_queue_s jit_queue;

/* Gateway specificities */
static int8_t antenna_gain = 0;

/* TX capabilities */
static struct lgw_tx_gain_lut_s txlut; /* TX gain table */
static uint32_t tx_freq_min[LGW_RF_CHAIN_NB]; /* lowest frequency supported by TX chain */
static uint32_t tx_freq_max[LGW_RF_CHAIN_NB]; /* highest frequency supported by TX chain */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DECLARATION ---------------------------------------- */

static void sig_handler(int sigio);

static int parse_SX1301_configuration(const char * conf_file);

static int parse_gateway_configuration(const char * conf_file);

static uint16_t crc16(const uint8_t * data, unsigned size);

static double difftimespec(struct timespec end, struct timespec beginning);

static void gps_process_sync(void);

static void gps_process_coords(void);

static void localpkt_up(struct lgw_pkt_rx_s *);
int offline = 1;
JSON_Array *mydevices;
static uint64_t myuid[20];
static uint8_t myappkey[20][16];
static uint8_t mynwkskey[20][16];
static uint8_t myappskey[20][16];
static uint32_t mydevaddr[20];
size_t devcount=0;
static uint64_t mynonce[20];
static uint64_t myjoineui[20];
static char mydevice[20][64];
static char myapplication[64];
static char ttnapiurl[64];
int ttnapiport;
int laststatus=1;
uint32_t myfcntdown[20];
uint32_t mylastfcntup[20];
static char myauthkey[72];
static char mydecoder[20][64];
bool myabp[20];
uint32_t joinnonce = 0;
struct timeval last_unix_time;

void ttn_data_exchange(void);
/* threads */
void thread_up(void);
void thread_down(void);
void thread_gps(void);
void thread_valid(void);
void thread_jit(void);
void thread_netstatus(void);
void thread_timersync(void);

static void lw_write_dw(uint8_t *output, uint32_t input)
{
	uint8_t* ptr = output;

	*(ptr++) = (uint8_t)(input), input >>= 8u;
	*(ptr++) = (uint8_t)(input), input >>= 8u;
	*(ptr++) = (uint8_t)(input), input >>= 8u;
	*(ptr) = (uint8_t)(input);
}

//static uint32_t lw_read_dw(uint8_t *buf)
//{
//	uint32_t ret;
//
//	ret = ( (uint32_t)buf[0] << 0 );
//    ret |= ( (uint32_t)buf[1] << 8 );
//    ret |= ( (uint32_t)buf[2] << 16 );
//    ret |= ( (uint32_t)buf[3] << 24 );
//
//	return ret;
//}

void lw_msg_mic(lw_mic_t* mic, lw_key_t *key)
{
    uint8_t b0[LW_KEY_LEN];
    memset(b0, 0 , LW_KEY_LEN);
    b0[0] = 0x49;
// todo add LoRaWAN 1.1 support for b0[1..4]
//  LoRaWAN 1.1 spec, 4.4:
//  If the device is connected to a LoRaWAN1.1 Network Server and the ACK bit of the downlink frame is set,
//	meaning this frame is acknowledging an uplink �confirmed� frame,
//	then ConfFCnt is the frame counter value modulo 2^16 of the �confirmed� uplink frame that is being acknowledged.
//	In all other cases ConfFCnt = 0x0000.
    b0[5] = key->link;

    lw_write_dw(b0+6, key->devaddr.data);
    lw_write_dw(b0+10, key->fcnt32);
    b0[15] = (uint8_t)key->len;

	AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, b0, LW_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LW_MIC_LEN);
}

void lw_msg_mic11(lw_mic_t *mic, lw_key_mic11_t *key) {
	uint8_t b0[LW_KEY_LEN];
	memset(b0, 0 , LW_KEY_LEN);
	b0[0] = 0x49;
// todo add LoRaWAN 1.1 support for b0[1..4]
//  LoRaWAN 1.1 spec, 4.4:
//  If the device is connected to a LoRaWAN1.1 Network Server and the ACK bit of the downlink frame is set,
//	meaning this frame is acknowledging an uplink �confirmed� frame,
//	then ConfFCnt is the frame counter value modulo 2^16 of the �confirmed� uplink frame that is being acknowledged.
//	In all other cases ConfFCnt = 0x0000.
	b0[1] = key->confFCnt & 0xffu;
	b0[2] = key->confFCnt >> 0x8u;
	b0[3] = key->txDr;
	b0[4] = key->txCh;
	b0[5] = 0x00;  // Dir = 0x00
	lw_write_dw(b0+6, key->devaddr->data);  // 6 - 9
	lw_write_dw(b0+10, key->fcnt32);  // 10-13
	b0[14] = 0x00;
	b0[15] = (uint8_t)key->len;

/*	log("B1: ");
	for (int i=0; i<LW_KEY_LEN; i++) {
		log("%02x", b0[i]);
	}
	log("\n");*/

	// cmacS = aes128_cmac(SNwkSIntKey, B1 | msg)
	AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->snwksintkey);
	AES_CMAC_Update(&cmacctx, b0, LW_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);
	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);
	memcpy(mic->buf, temp, 2);

	// cmacF = aes128_cmac(FNwkSIntKey, B0 | msg)
	b0[1] = b0[2] = b0[3] = b0[4] = 0x00;
/*	log("B0: ");
	for (int i=0; i<LW_KEY_LEN; i++) {
		log("%02x", b0[i]);
	}
	log("\n");*/
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->fnwksintkey);
	AES_CMAC_Update(&cmacctx, b0, LW_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);
	AES_CMAC_Final(temp, &cmacctx);
	memcpy(mic->buf + 2, temp, 2);
}

void lw_join_mic(lw_mic_t* mic, lw_key_t *key)
{
    AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LW_MIC_LEN);
}

// Use to generate JoinAccept Payload
int lw_join_encrypt(uint8_t *out, lw_key_t *key)
{

MSG("\njoin-encrypt\n");

    if((key->len == 0) || (key->len%LW_KEY_LEN != 0)){
        MSG("\nERROR encrypt -1\n");
        return -1;
    }

    aes_context aesContext;
MSG("\njoin encrypting now:");
	aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

    // Check if optional CFList is included
    int i;
    for(i=0; i<key->len; i+=LW_KEY_LEN){
        aes_decrypt( key->in + i, out + i, &aesContext ); // naporcuje se na 2x64 bajtů
        MSG("IN: %02X   ", *(key->in + i));
        MSG("OUT: %02X \n", *(out + i));
    }

    return key->len;
}

// Use to decrypt JoinAccept Payload
int lw_join_decrypt(uint8_t *out, lw_key_t *key)
{
    if((key->len == 0) || (key->len%LW_KEY_LEN != 0)){
        return -1;
    }

    aes_context aesContext;

	aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

    // Check if optional CFList is included
    int i;
    for(i=0; i<key->len; i+=LW_KEY_LEN){
        aes_encrypt( key->in + i, out + i, &aesContext );
    }

    return key->len;
}

static void lw_block_xor(uint8_t const l[], uint8_t const r[], uint8_t out[], uint16_t bytes)
{
	uint8_t const* lptr = l;
	uint8_t const* rptr = r;
	uint8_t* optr = out;
	uint8_t const* const end = out + bytes;

	for (;optr < end; lptr++, rptr++, optr++)
		*optr = *lptr ^ *rptr;
}

int lw_encrypt(uint8_t *out, lw_key_t *key)
{
    if (key->len == 0)
		return -1;

	uint8_t A[LW_KEY_LEN];

	uint16_t const over_hang_bytes = key->len%LW_KEY_LEN;
    int blocks = key->len/LW_KEY_LEN;
    if (over_hang_bytes) {
    	++blocks;
    }

	memset(A, 0, LW_KEY_LEN);

	A[0] = 0x01; //encryption flags
	A[5] = key->link;

	lw_write_dw(A+6, key->devaddr.data);
	lw_write_dw(A+10, key->fcnt32);

	uint8_t const* blockInput = key->in;
	uint8_t* blockOutput = out;
	uint16_t i;
	for(i = 1; i <= blocks; i++, blockInput += LW_KEY_LEN, blockOutput += LW_KEY_LEN){
		A[15] = (uint8_t)(i);

		aes_context aesContext;
		aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

		uint8_t S[LW_KEY_LEN];
		aes_encrypt(A, S, &aesContext);

		uint16_t bytes_to_encrypt;
		if ((i < blocks) || (over_hang_bytes == 0))
			bytes_to_encrypt = LW_KEY_LEN;
		else
			bytes_to_encrypt = over_hang_bytes;

		lw_block_xor(S, blockInput, blockOutput, bytes_to_encrypt);
	}
	return key->len;
}


void lw_get_skeys(uint8_t *nwkskey, uint8_t *appskey, lw_skey_seed_t *seed)
{
    aes_context aesContext;
    uint8_t b[LW_KEY_LEN];

    memset(&aesContext, 0, sizeof(aesContext));
    memset(b, 0, LW_KEY_LEN);
    b[1] = (uint8_t)(seed->anonce.data>>0u);
    b[2] = (uint8_t)(seed->anonce.data>>8u);
    b[3] = (uint8_t)(seed->anonce.data>>16u);
    b[4] = (uint8_t)(seed->netid.data>>0u);
    b[5] = (uint8_t)(seed->netid.data>>8u);
    b[6] = (uint8_t)(seed->netid.data>>16u);
    b[7] = (uint8_t)(seed->dnonce.data>>0u);
    b[8] = (uint8_t)(seed->dnonce.data>>8u);

    b[0] = 0x01;
	aes_set_key(seed->aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, nwkskey, &aesContext );

    b[0] = 0x02;
	aes_set_key(seed->aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, appskey, &aesContext );
}

void lw_get_skeys_from_arrays(uint8_t *nwkskey, uint8_t *appskey, uint8_t *joinnonce, uint8_t *netid, uint8_t *devnonce, uint8_t *aeskey )
{
    aes_context aesContext;
    uint8_t b[LW_KEY_LEN];

    memset(&aesContext, 0, sizeof(aesContext));
    memset(b, 0, LW_KEY_LEN);
    b[1] = *(joinnonce);
    b[2] = *(joinnonce+1);
    b[3] = *(joinnonce+2);
    b[4] = *(netid);
    b[5] = *(netid+1);
    b[6] = *(netid+2);
    b[7] = *(devnonce);
    b[8] = *(devnonce+1);

    b[0] = 0x01;
	aes_set_key(aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, nwkskey, &aesContext );

    b[0] = 0x02;
	aes_set_key(aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, appskey, &aesContext );
}

void lw_get_skeys_11(uint8_t *FNwkSntKey, uint8_t* SNwkSIntKey, uint8_t* NwkSEncKey, uint8_t *AppSKey, lw_skey_seed_11_t *seed)
{
    aes_context aesContext;
    uint8_t b[LW_KEY_LEN];

    memset(&aesContext, 0, sizeof(aesContext));
	memset(b, 0, LW_KEY_LEN);
	b[1] = (uint8_t)(seed->jnonce.data>>0u);
	b[2] = (uint8_t)(seed->jnonce.data>>8u);
	b[3] = (uint8_t)(seed->jnonce.data>>16u);
	b[4] = seed->joineui[7];
	b[5] = seed->joineui[6];
	b[6] = seed->joineui[5];
	b[7] = seed->joineui[4];
	b[8] = seed->joineui[3];
	b[9] = seed->joineui[2];
	b[10] = seed->joineui[1];
	b[11] = seed->joineui[0];
	b[12] = (uint8_t)(seed->dnonce.data>>0u);
	b[13] = (uint8_t)(seed->dnonce.data>>8u);

    b[0] = 0x01;
	aes_set_key(seed->nwkkey, LW_KEY_LEN, &aesContext);
    aes_encrypt(b, FNwkSntKey, &aesContext);

	b[0] = 0x02;
	aes_set_key(seed->appkey, LW_KEY_LEN, &aesContext);
	aes_encrypt(b, AppSKey, &aesContext);

    b[0] = 0x03;
	aes_set_key(seed->nwkkey, LW_KEY_LEN, &aesContext);
    aes_encrypt(b, SNwkSIntKey, &aesContext);

    b[0] = 0x04;
	aes_set_key(seed->nwkkey, LW_KEY_LEN, &aesContext);
    aes_encrypt(b, NwkSEncKey, &aesContext);
}

/**
 * En- or decrypt FOpts. Only used for LoRaWAN >= 1.1
 * @param data
 * @param dataLen
 * @param key
 * @param isUplink
 * @param devaddr
 * @param cnt
 */
void encrypt_fopts(uint8_t *data, uint8_t dataLen, uint8_t *key, bool aFCntDown, bool isUplink, lw_devaddr_t *devaddr,
				   uint32_t cnt) {
	uint8_t A[16];
	A[0] = 0x01;
	A[1] = A[2] = A[3] = 0x00;
	A[4] = (aFCntDown ? 0x02 : 0x01);
	A[5] = (isUplink ? 0 : 1);
	lw_write_dw(A + 6, devaddr->data);
	lw_write_dw(A + 10, cnt);
	A[14] = 0x00;
	A[15] = 0x01;

	aes_context aesContext;
	aes_set_key(key, LW_KEY_LEN, &aesContext);
	uint8_t S[16];
	aes_encrypt(A, S, &aesContext);

	for (uint8_t i=0; i<dataLen; i++) {
		data[i] ^= S[i];
	}
}


/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */

void initArray(Array *a, size_t initialSize) {
  a->array = malloc(initialSize * sizeof(int));
  a->used = 0;
  a->size = initialSize;
}

void insertArray(Array *a, int element) {
  // a->used is the number of used entries, because a->array[a->used++] updates a->used only *after* the array has been accessed.
  // Therefore a->used can go up to a->size 
  if (a->used == a->size) {
    a->size *= 2;
    a->array = realloc(a->array, a->size * sizeof(int));
  }
  a->array[a->used++] = element;
}

void freeArray(Array *a) {
  free(a->array);
  a->array = NULL;
  a->used = a->size = 0;
}

static void sig_handler(int sigio) {
    if (sigio == SIGQUIT) {
        quit_sig = true;
    } else if ((sigio == SIGINT) || (sigio == SIGTERM)) {
        exit_sig = true;
    }
    return;
}

static int parse_SX1301_configuration(const char * conf_file) {
    int i;
    char param_name[32]; /* used to generate variable parameter names */
    const char *str; /* used to store string value from JSON object */
    const char conf_obj_name[] = "SX1301_conf";
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    JSON_Object *conf_lbt_obj = NULL;
    JSON_Object *conf_lbtchan_obj = NULL;
    JSON_Value *val = NULL;
    JSON_Array *conf_array = NULL;
    struct lgw_conf_board_s boardconf;
    struct lgw_conf_lbt_s lbtconf;
    struct lgw_conf_rxrf_s rfconf;
    struct lgw_conf_rxif_s ifconf;
    uint32_t sf, bw, fdev;

    /* try to parse JSON */
    root_val = json_parse_file_with_comments(conf_file);
    if (root_val == NULL) {
        MSG("ERROR: %s is not a valid JSON file\n", conf_file);
        exit(EXIT_FAILURE);
    }

    /* point to the gateway configuration object */
    conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
    if (conf_obj == NULL) {
        MSG("INFO: %s does not contain a JSON object named %s\n", conf_file, conf_obj_name);
        return -1;
    } else {
        MSG("INFO: %s does contain a JSON object named %s, parsing SX1301 parameters\n", conf_file, conf_obj_name);
    }

    /* set board configuration */
    memset(&boardconf, 0, sizeof boardconf); /* initialize configuration structure */
    val = json_object_get_value(conf_obj, "lorawan_public"); /* fetch value (if possible) */
    if (json_value_get_type(val) == JSONBoolean) {
        boardconf.lorawan_public = (bool)json_value_get_boolean(val);
    } else {
        MSG("WARNING: Data type for lorawan_public seems wrong, please check\n");
        boardconf.lorawan_public = false;
    }
    val = json_object_get_value(conf_obj, "clksrc"); /* fetch value (if possible) */
    if (json_value_get_type(val) == JSONNumber) {
        boardconf.clksrc = (uint8_t)json_value_get_number(val);
    } else {
        MSG("WARNING: Data type for clksrc seems wrong, please check\n");
        boardconf.clksrc = 0;
    }
    MSG("INFO: lorawan_public %d, clksrc %d\n", boardconf.lorawan_public, boardconf.clksrc);
    /* all parameters parsed, submitting configuration to the HAL */
    if (lgw_board_setconf(boardconf) != LGW_HAL_SUCCESS) {
        MSG("ERROR: Failed to configure board\n");
        return -1;
    }

    /* set LBT configuration */
    memset(&lbtconf, 0, sizeof lbtconf); /* initialize configuration structure */
    conf_lbt_obj = json_object_get_object(conf_obj, "lbt_cfg"); /* fetch value (if possible) */
    if (conf_lbt_obj == NULL) {
        MSG("INFO: no configuration for LBT\n");
    } else {
        val = json_object_get_value(conf_lbt_obj, "enable"); /* fetch value (if possible) */
        if (json_value_get_type(val) == JSONBoolean) {
            lbtconf.enable = (bool)json_value_get_boolean(val);
        } else {
            MSG("WARNING: Data type for lbt_cfg.enable seems wrong, please check\n");
            lbtconf.enable = false;
        }
        if (lbtconf.enable == true) {
            val = json_object_get_value(conf_lbt_obj, "rssi_target"); /* fetch value (if possible) */
            if (json_value_get_type(val) == JSONNumber) {
                lbtconf.rssi_target = (int8_t)json_value_get_number(val);
            } else {
                MSG("WARNING: Data type for lbt_cfg.rssi_target seems wrong, please check\n");
                lbtconf.rssi_target = 0;
            }
            val = json_object_get_value(conf_lbt_obj, "sx127x_rssi_offset"); /* fetch value (if possible) */
            if (json_value_get_type(val) == JSONNumber) {
                lbtconf.rssi_offset = (int8_t)json_value_get_number(val);
            } else {
                MSG("WARNING: Data type for lbt_cfg.sx127x_rssi_offset seems wrong, please check\n");
                lbtconf.rssi_offset = 0;
            }
            /* set LBT channels configuration */
            conf_array = json_object_get_array(conf_lbt_obj, "chan_cfg");
            if (conf_array != NULL) {
                lbtconf.nb_channel = json_array_get_count( conf_array );
                MSG("INFO: %u LBT channels configured\n", lbtconf.nb_channel);
            }
            for (i = 0; i < (int)lbtconf.nb_channel; i++) {
                /* Sanity check */
                if (i >= LBT_CHANNEL_FREQ_NB)
                {
                    MSG("ERROR: LBT channel %d not supported, skip it\n", i );
                    break;
                }
                /* Get LBT channel configuration object from array */
                conf_lbtchan_obj = json_array_get_object(conf_array, i);

                /* Channel frequency */
                val = json_object_dotget_value(conf_lbtchan_obj, "freq_hz"); /* fetch value (if possible) */
                if (json_value_get_type(val) == JSONNumber) {
                    lbtconf.channels[i].freq_hz = (uint32_t)json_value_get_number(val);
                } else {
                    MSG("WARNING: Data type for lbt_cfg.channels[%d].freq_hz seems wrong, please check\n", i);
                    lbtconf.channels[i].freq_hz = 0;
                }

                /* Channel scan time */
                val = json_object_dotget_value(conf_lbtchan_obj, "scan_time_us"); /* fetch value (if possible) */
                if (json_value_get_type(val) == JSONNumber) {
                    lbtconf.channels[i].scan_time_us = (uint16_t)json_value_get_number(val);
                } else {
                    MSG("WARNING: Data type for lbt_cfg.channels[%d].scan_time_us seems wrong, please check\n", i);
                    lbtconf.channels[i].scan_time_us = 0;
                }
            }

            /* all parameters parsed, submitting configuration to the HAL */
            if (lgw_lbt_setconf(lbtconf) != LGW_HAL_SUCCESS) {
                MSG("ERROR: Failed to configure LBT\n");
                return -1;
            }
        } else {
            MSG("INFO: LBT is disabled\n");
        }
    }

    /* set antenna gain configuration */
    val = json_object_get_value(conf_obj, "antenna_gain"); /* fetch value (if possible) */
    if (val != NULL) {
        if (json_value_get_type(val) == JSONNumber) {
            antenna_gain = (int8_t)json_value_get_number(val);
        } else {
            MSG("WARNING: Data type for antenna_gain seems wrong, please check\n");
            antenna_gain = 0;
        }
    }
    MSG("INFO: antenna_gain %d dBi\n", antenna_gain);

    /* set configuration for tx gains */
    memset(&txlut, 0, sizeof txlut); /* initialize configuration structure */
    for (i = 0; i < TX_GAIN_LUT_SIZE_MAX; i++) {
        snprintf(param_name, sizeof param_name, "tx_lut_%i", i); /* compose parameter path inside JSON structure */
        val = json_object_get_value(conf_obj, param_name); /* fetch value (if possible) */
        if (json_value_get_type(val) != JSONObject) {
            MSG("INFO: no configuration for tx gain lut %i\n", i);
            continue;
        }
        txlut.size++; /* update TX LUT size based on JSON object found in configuration file */
        /* there is an object to configure that TX gain index, let's parse it */
        snprintf(param_name, sizeof param_name, "tx_lut_%i.pa_gain", i);
        val = json_object_dotget_value(conf_obj, param_name);
        if (json_value_get_type(val) == JSONNumber) {
            txlut.lut[i].pa_gain = (uint8_t)json_value_get_number(val);
        } else {
            MSG("WARNING: Data type for %s[%d] seems wrong, please check\n", param_name, i);
            txlut.lut[i].pa_gain = 0;
        }
        snprintf(param_name, sizeof param_name, "tx_lut_%i.dac_gain", i);
        val = json_object_dotget_value(conf_obj, param_name);
        if (json_value_get_type(val) == JSONNumber) {
            txlut.lut[i].dac_gain = (uint8_t)json_value_get_number(val);
        } else {
            txlut.lut[i].dac_gain = 3; /* This is the only dac_gain supported for now */
        }
        snprintf(param_name, sizeof param_name, "tx_lut_%i.dig_gain", i);
        val = json_object_dotget_value(conf_obj, param_name);
        if (json_value_get_type(val) == JSONNumber) {
            txlut.lut[i].dig_gain = (uint8_t)json_value_get_number(val);
        } else {
            MSG("WARNING: Data type for %s[%d] seems wrong, please check\n", param_name, i);
            txlut.lut[i].dig_gain = 0;
        }
        snprintf(param_name, sizeof param_name, "tx_lut_%i.mix_gain", i);
        val = json_object_dotget_value(conf_obj, param_name);
        if (json_value_get_type(val) == JSONNumber) {
            txlut.lut[i].mix_gain = (uint8_t)json_value_get_number(val);
        } else {
            MSG("WARNING: Data type for %s[%d] seems wrong, please check\n", param_name, i);
            txlut.lut[i].mix_gain = 0;
        }
        snprintf(param_name, sizeof param_name, "tx_lut_%i.rf_power", i);
        val = json_object_dotget_value(conf_obj, param_name);
        if (json_value_get_type(val) == JSONNumber) {
            txlut.lut[i].rf_power = (int8_t)json_value_get_number(val);
        } else {
            MSG("WARNING: Data type for %s[%d] seems wrong, please check\n", param_name, i);
            txlut.lut[i].rf_power = 0;
        }
    }
    /* all parameters parsed, submitting configuration to the HAL */
    if (txlut.size > 0) {
        MSG("INFO: Configuring TX LUT with %u indexes\n", txlut.size);
        if (lgw_txgain_setconf(&txlut) != LGW_HAL_SUCCESS) {
            MSG("ERROR: Failed to configure concentrator TX Gain LUT\n");
            return -1;
        }
    } else {
        MSG("WARNING: No TX gain LUT defined\n");
    }

    /* set configuration for RF chains */
    for (i = 0; i < LGW_RF_CHAIN_NB; ++i) {
        memset(&rfconf, 0, sizeof rfconf); /* initialize configuration structure */
        snprintf(param_name, sizeof param_name, "radio_%i", i); /* compose parameter path inside JSON structure */
        val = json_object_get_value(conf_obj, param_name); /* fetch value (if possible) */
        if (json_value_get_type(val) != JSONObject) {
            MSG("INFO: no configuration for radio %i\n", i);
            continue;
        }
        /* there is an object to configure that radio, let's parse it */
        snprintf(param_name, sizeof param_name, "radio_%i.enable", i);
        val = json_object_dotget_value(conf_obj, param_name);
        if (json_value_get_type(val) == JSONBoolean) {
            rfconf.enable = (bool)json_value_get_boolean(val);
        } else {
            rfconf.enable = false;
        }
        if (rfconf.enable == false) { /* radio disabled, nothing else to parse */
            MSG("INFO: radio %i disabled\n", i);
        } else  { /* radio enabled, will parse the other parameters */
            snprintf(param_name, sizeof param_name, "radio_%i.freq", i);
            rfconf.freq_hz = (uint32_t)json_object_dotget_number(conf_obj, param_name);
            snprintf(param_name, sizeof param_name, "radio_%i.rssi_offset", i);
            rfconf.rssi_offset = (float)json_object_dotget_number(conf_obj, param_name);
            snprintf(param_name, sizeof param_name, "radio_%i.type", i);
            str = json_object_dotget_string(conf_obj, param_name);
            if (!strncmp(str, "SX1255", 6)) {
                rfconf.type = LGW_RADIO_TYPE_SX1255;
            } else if (!strncmp(str, "SX1257", 6)) {
                rfconf.type = LGW_RADIO_TYPE_SX1257;
            } else {
                MSG("WARNING: invalid radio type: %s (should be SX1255 or SX1257)\n", str);
            }
            snprintf(param_name, sizeof param_name, "radio_%i.tx_enable", i);
            val = json_object_dotget_value(conf_obj, param_name);
            if (json_value_get_type(val) == JSONBoolean) {
                rfconf.tx_enable = (bool)json_value_get_boolean(val);
                if (rfconf.tx_enable == true) {
                    /* tx is enabled on this rf chain, we need its frequency range */
                    snprintf(param_name, sizeof param_name, "radio_%i.tx_freq_min", i);
                    tx_freq_min[i] = (uint32_t)json_object_dotget_number(conf_obj, param_name);
                    snprintf(param_name, sizeof param_name, "radio_%i.tx_freq_max", i);
                    tx_freq_max[i] = (uint32_t)json_object_dotget_number(conf_obj, param_name);
                    if ((tx_freq_min[i] == 0) || (tx_freq_max[i] == 0)) {
                        MSG("WARNING: no frequency range specified for TX rf chain %d\n", i);
                    }
                    /* ... and the notch filter frequency to be set */
                    snprintf(param_name, sizeof param_name, "radio_%i.tx_notch_freq", i);
                    rfconf.tx_notch_freq = (uint32_t)json_object_dotget_number(conf_obj, param_name);
                }
            } else {
                rfconf.tx_enable = false;
            }
            MSG("INFO: radio %i enabled (type %s), center frequency %u, RSSI offset %f, tx enabled %d, tx_notch_freq %u\n", i, str, rfconf.freq_hz, rfconf.rssi_offset, rfconf.tx_enable, rfconf.tx_notch_freq);
        }
        /* all parameters parsed, submitting configuration to the HAL */
        if (lgw_rxrf_setconf(i, rfconf) != LGW_HAL_SUCCESS) {
            MSG("ERROR: invalid configuration for radio %i\n", i);
            return -1;
        }
    }

    /* set configuration for Lora multi-SF channels (bandwidth cannot be set) */
    for (i = 0; i < LGW_MULTI_NB; ++i) {
        memset(&ifconf, 0, sizeof ifconf); /* initialize configuration structure */
        snprintf(param_name, sizeof param_name, "chan_multiSF_%i", i); /* compose parameter path inside JSON structure */
        val = json_object_get_value(conf_obj, param_name); /* fetch value (if possible) */
        if (json_value_get_type(val) != JSONObject) {
            MSG("INFO: no configuration for Lora multi-SF channel %i\n", i);
            continue;
        }
        /* there is an object to configure that Lora multi-SF channel, let's parse it */
        snprintf(param_name, sizeof param_name, "chan_multiSF_%i.enable", i);
        val = json_object_dotget_value(conf_obj, param_name);
        if (json_value_get_type(val) == JSONBoolean) {
            ifconf.enable = (bool)json_value_get_boolean(val);
        } else {
            ifconf.enable = false;
        }
        if (ifconf.enable == false) { /* Lora multi-SF channel disabled, nothing else to parse */
            MSG("INFO: Lora multi-SF channel %i disabled\n", i);
        } else  { /* Lora multi-SF channel enabled, will parse the other parameters */
            snprintf(param_name, sizeof param_name, "chan_multiSF_%i.radio", i);
            ifconf.rf_chain = (uint32_t)json_object_dotget_number(conf_obj, param_name);
            snprintf(param_name, sizeof param_name, "chan_multiSF_%i.if", i);
            ifconf.freq_hz = (int32_t)json_object_dotget_number(conf_obj, param_name);
            // TODO: handle individual SF enabling and disabling (spread_factor)
            MSG("INFO: Lora multi-SF channel %i>  radio %i, IF %i Hz, 125 kHz bw, SF 7 to 12\n", i, ifconf.rf_chain, ifconf.freq_hz);
        }
        /* all parameters parsed, submitting configuration to the HAL */
        if (lgw_rxif_setconf(i, ifconf) != LGW_HAL_SUCCESS) {
            MSG("ERROR: invalid configuration for Lora multi-SF channel %i\n", i);
            return -1;
        }
    }

    /* set configuration for Lora standard channel */
    memset(&ifconf, 0, sizeof ifconf); /* initialize configuration structure */
    val = json_object_get_value(conf_obj, "chan_Lora_std"); /* fetch value (if possible) */
    if (json_value_get_type(val) != JSONObject) {
        MSG("INFO: no configuration for Lora standard channel\n");
    } else {
        val = json_object_dotget_value(conf_obj, "chan_Lora_std.enable");
        if (json_value_get_type(val) == JSONBoolean) {
            ifconf.enable = (bool)json_value_get_boolean(val);
        } else {
            ifconf.enable = false;
        }
        if (ifconf.enable == false) {
            MSG("INFO: Lora standard channel %i disabled\n", i);
        } else  {
            ifconf.rf_chain = (uint32_t)json_object_dotget_number(conf_obj, "chan_Lora_std.radio");
            ifconf.freq_hz = (int32_t)json_object_dotget_number(conf_obj, "chan_Lora_std.if");
            bw = (uint32_t)json_object_dotget_number(conf_obj, "chan_Lora_std.bandwidth");
            switch(bw) {
                case 500000: ifconf.bandwidth = BW_500KHZ; break;
                case 250000: ifconf.bandwidth = BW_250KHZ; break;
                case 125000: ifconf.bandwidth = BW_125KHZ; break;
                default: ifconf.bandwidth = BW_UNDEFINED;
            }
            sf = (uint32_t)json_object_dotget_number(conf_obj, "chan_Lora_std.spread_factor");
            switch(sf) {
                case  7: ifconf.datarate = DR_LORA_SF7;  break;
                case  8: ifconf.datarate = DR_LORA_SF8;  break;
                case  9: ifconf.datarate = DR_LORA_SF9;  break;
                case 10: ifconf.datarate = DR_LORA_SF10; break;
                case 11: ifconf.datarate = DR_LORA_SF11; break;
                case 12: ifconf.datarate = DR_LORA_SF12; break;
                default: ifconf.datarate = DR_UNDEFINED;
            }
            MSG("INFO: Lora std channel> radio %i, IF %i Hz, %u Hz bw, SF %u\n", ifconf.rf_chain, ifconf.freq_hz, bw, sf);
        }
        if (lgw_rxif_setconf(8, ifconf) != LGW_HAL_SUCCESS) {
            MSG("ERROR: invalid configuration for Lora standard channel\n");
            return -1;
        }
    }

    /* set configuration for FSK channel */
    memset(&ifconf, 0, sizeof ifconf); /* initialize configuration structure */
    val = json_object_get_value(conf_obj, "chan_FSK"); /* fetch value (if possible) */
    if (json_value_get_type(val) != JSONObject) {
        MSG("INFO: no configuration for FSK channel\n");
    } else {
        val = json_object_dotget_value(conf_obj, "chan_FSK.enable");
        if (json_value_get_type(val) == JSONBoolean) {
            ifconf.enable = (bool)json_value_get_boolean(val);
        } else {
            ifconf.enable = false;
        }
        if (ifconf.enable == false) {
            MSG("INFO: FSK channel %i disabled\n", i);
        } else  {
            ifconf.rf_chain = (uint32_t)json_object_dotget_number(conf_obj, "chan_FSK.radio");
            ifconf.freq_hz = (int32_t)json_object_dotget_number(conf_obj, "chan_FSK.if");
            bw = (uint32_t)json_object_dotget_number(conf_obj, "chan_FSK.bandwidth");
            fdev = (uint32_t)json_object_dotget_number(conf_obj, "chan_FSK.freq_deviation");
            ifconf.datarate = (uint32_t)json_object_dotget_number(conf_obj, "chan_FSK.datarate");

            /* if chan_FSK.bandwidth is set, it has priority over chan_FSK.freq_deviation */
            if ((bw == 0) && (fdev != 0)) {
                bw = 2 * fdev + ifconf.datarate;
            }
            if      (bw == 0)      ifconf.bandwidth = BW_UNDEFINED;
            else if (bw <= 7800)   ifconf.bandwidth = BW_7K8HZ;
            else if (bw <= 15600)  ifconf.bandwidth = BW_15K6HZ;
            else if (bw <= 31200)  ifconf.bandwidth = BW_31K2HZ;
            else if (bw <= 62500)  ifconf.bandwidth = BW_62K5HZ;
            else if (bw <= 125000) ifconf.bandwidth = BW_125KHZ;
            else if (bw <= 250000) ifconf.bandwidth = BW_250KHZ;
            else if (bw <= 500000) ifconf.bandwidth = BW_500KHZ;
            else ifconf.bandwidth = BW_UNDEFINED;

            MSG("INFO: FSK channel> radio %i, IF %i Hz, %u Hz bw, %u bps datarate\n", ifconf.rf_chain, ifconf.freq_hz, bw, ifconf.datarate);
        }
        if (lgw_rxif_setconf(9, ifconf) != LGW_HAL_SUCCESS) {
            MSG("ERROR: invalid configuration for FSK channel\n");
            return -1;
        }
    }
    json_value_free(root_val);

    return 0;
}

static int parse_gateway_configuration(const char * conf_file) {
    const char conf_obj_name[] = "gateway_conf";
    JSON_Value *root_val;
    JSON_Object *conf_obj = NULL;
    JSON_Object *dev_obj = NULL;
    JSON_Value *val = NULL; /* needed to detect the absence of some fields */
    const char *str; /* pointer to sub-strings in the JSON data */
    unsigned long long ull = 0;
    uint32_t ull1 = 0;
    uint8_t appkeyhere[16];

    /* try to parse JSON */
    root_val = json_parse_file_with_comments(conf_file);
    if (root_val == NULL) {
        MSG("ERROR: %s is not a valid JSON file\n", conf_file);
        exit(EXIT_FAILURE);
    }

    /* point to the gateway configuration object */
    conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
    if (conf_obj == NULL) {
        MSG("INFO: %s does not contain a JSON object named %s\n", conf_file, conf_obj_name);
        return -1;
    } else {
        MSG("INFO: %s does contain a JSON object named %s, parsing gateway parameters\n", conf_file, conf_obj_name);
    }

    /* gateway unique identifier (aka MAC address) (optional) */
    str = json_object_get_string(conf_obj, "gateway_ID");
    if (str != NULL) {
        sscanf(str, "%llx", &ull);
        lgwm = ull;
        MSG("INFO: gateway MAC address is configured to %016llX\n", ull);
    }

    str = json_object_get_string(conf_obj, "application");
    if (str != NULL) {
        strncpy(myapplication, str, sizeof myapplication);
        MSG("INFO: TTN application name set to \"%s\"\n", myapplication);
    }

    str = json_object_get_string(conf_obj, "apiurl");
    if (str != NULL) {
        strncpy(ttnapiurl, str, sizeof ttnapiurl);
        MSG("INFO: TTN api url set to \"%s\"\n", ttnapiurl);
    }

    val = json_object_get_value(conf_obj, "apiport");
    if (val != NULL) {
        ttnapiport = json_value_get_number(val);
        MSG("INFO: TTN api port set to \"%u\"\n", ttnapiport);
    }

    str = json_object_get_string(conf_obj, "authkey");
    if (str != NULL) {
        strncpy(myauthkey, str, sizeof myauthkey);
        MSG("INFO: TTN auth key set to \"%s\"\n", myauthkey);
    }

    mydevices = json_object_get_array(conf_obj, "mydevices");
    devcount = 0;
    MSG("INFO: mydevices array size:%u list: \n", json_array_get_count(mydevices));
    for (unsigned int i = 0; i < json_array_get_count(mydevices); i++) {
        devcount = i;
        MSG("%u\n", devcount);
        dev_obj = json_array_get_object(mydevices, i);
        printf("%.10s %.10s\n",
               json_object_dotget_string(dev_obj, "uid"),
               json_object_get_string(dev_obj, "appKey"));

        str = json_object_get_string(dev_obj, "uid");
        if (str != NULL) {
            sscanf(str, "%llx", &ull);
            myuid[i] = ull;
            myfcntdown[i] = 0;
            MSG("INFO: found myuid: %016llX\n", ull);
        }

        str = json_object_get_string(dev_obj, "decoder");
        if (str != NULL) {
            strncpy(mydecoder[i], str, sizeof mydecoder[i]);
            MSG("INFO: decoder for this device set to \"%s\"\n", mydecoder[i]);
        }

        str = json_object_get_string(dev_obj, "devid");
        if (str != NULL) {
            strncpy(mydevice[i], str, sizeof mydevice[i]);
            MSG("INFO: TTN ID for this device set to \"%s\"\n", mydevice[i]);
        }

        val = json_object_get_value(dev_obj, "abp");
        myabp[i]=0;
        if (json_value_get_type(val) == JSONBoolean) {
            abp = (bool)json_value_get_boolean(val);
            if(abp==1){
                myabp[i]=1;
                str = json_object_get_string(dev_obj, "appskey");
                if (str != NULL) {
                    MSG("INFO: -> appskey: %X\n", ull1);
                    for (size_t count = 0; count < sizeof appkeyhere/sizeof *appkeyhere; count++) {
                        sscanf(str, "%2hhx", &appkeyhere[count]);
                        myappskey[i][count] = appkeyhere[count];
                        str += 2;
                    }
                }
                str = json_object_get_string(dev_obj, "nwkskey");
                if (str != NULL) {
                    MSG("INFO: -> nwkskey: %X\n", ull1);
                    for (size_t count = 0; count < sizeof appkeyhere/sizeof *appkeyhere; count++) {
                        sscanf(str, "%2hhx", &appkeyhere[count]);
                        mynwkskey[i][count] = appkeyhere[count];
                        str += 2;
                    }
                }
                
                str = json_object_get_string(dev_obj, "devAddr");
                if (str != NULL) {
                    sscanf(str, "%X", &ull1);
                    mydevaddr[i] = ull1;
                    MSG("INFO: -> devaddr: %X\n", ull1);
                }

            }else{
                str = json_object_get_string(dev_obj, "appKey");
                if (str != NULL) {
                    MSG("INFO: -> appkey: ");
                    for (size_t count = 0; count < sizeof appkeyhere/sizeof *appkeyhere; count++) {
                        sscanf(str, "%2hhx", &appkeyhere[count]);
                        myappkey[i][count] = appkeyhere[count];
                        str += 2;
                    }
                    printf("0x");
                    for(size_t count = 0; count < sizeof (myappkey[i])/sizeof *(myappkey[i]); count++){
                        printf("%02x", myappkey[i][count]);
                    }
                    printf("\n");
            
                }

            }
        }else{
            MSG("ERROR: Join mode not set or value is invalid datatype. Use 'abp': bool in mydevices config");
        }
    }

    /* server hostname or IP address (optional) */
    str = json_object_get_string(conf_obj, "server_address");
    if (str != NULL) {
        strncpy(serv_addr, str, sizeof serv_addr);
        MSG("INFO: server hostname or IP address is configured to \"%s\"\n", serv_addr);
    }

    /* get up and down ports (optional) */
    val = json_object_get_value(conf_obj, "serv_port_up");
    if (val != NULL) {
        snprintf(serv_port_up, sizeof serv_port_up, "%u", (uint16_t)json_value_get_number(val));
        MSG("INFO: upstream port is configured to \"%s\"\n", serv_port_up);
    }
    val = json_object_get_value(conf_obj, "serv_port_down");
    if (val != NULL) {
        snprintf(serv_port_down, sizeof serv_port_down, "%u", (uint16_t)json_value_get_number(val));
        MSG("INFO: downstream port is configured to \"%s\"\n", serv_port_down);
    }

    /* get keep-alive interval (in seconds) for downstream (optional) */
    val = json_object_get_value(conf_obj, "keepalive_interval");
    if (val != NULL) {
        keepalive_time = (int)json_value_get_number(val);
        MSG("INFO: downstream keep-alive interval is configured to %u seconds\n", keepalive_time);
    }

    /* get interval (in seconds) for statistics display (optional) */
    val = json_object_get_value(conf_obj, "stat_interval");
    if (val != NULL) {
        stat_interval = (unsigned)json_value_get_number(val);
        MSG("INFO: statistics display and data exchange with TTN interval is configured to %u seconds\n", stat_interval);
    }

    /* get time-out value (in ms) for upstream datagrams (optional) */
    val = json_object_get_value(conf_obj, "push_timeout_ms");
    if (val != NULL) {
        push_timeout_half.tv_usec = 500 * (long int)json_value_get_number(val);
        MSG("INFO: upstream PUSH_DATA time-out is configured to %u ms\n", (unsigned)(push_timeout_half.tv_usec / 500));
    }

    /* packet filtering parameters */
    val = json_object_get_value(conf_obj, "forward_crc_valid");
    if (json_value_get_type(val) == JSONBoolean) {
        fwd_valid_pkt = (bool)json_value_get_boolean(val);
    }
    MSG("INFO: packets received with a valid CRC will%s be forwarded\n", (fwd_valid_pkt ? "" : " NOT"));
    val = json_object_get_value(conf_obj, "forward_crc_error");
    if (json_value_get_type(val) == JSONBoolean) {
        fwd_error_pkt = (bool)json_value_get_boolean(val);
    }
    MSG("INFO: packets received with a CRC error will%s be forwarded\n", (fwd_error_pkt ? "" : " NOT"));
    val = json_object_get_value(conf_obj, "forward_crc_disabled");
    if (json_value_get_type(val) == JSONBoolean) {
        fwd_nocrc_pkt = (bool)json_value_get_boolean(val);
    }
    MSG("INFO: packets received with no CRC will%s be forwarded\n", (fwd_nocrc_pkt ? "" : " NOT"));

    /* GPS module TTY path (optional) */
    str = json_object_get_string(conf_obj, "gps_tty_path");
    if (str != NULL) {
        strncpy(gps_tty_path, str, sizeof gps_tty_path);
        MSG("INFO: GPS serial port path is configured to \"%s\"\n", gps_tty_path);
    }

    /* get reference coordinates */
    val = json_object_get_value(conf_obj, "ref_latitude");
    if (val != NULL) {
        reference_coord.lat = (double)json_value_get_number(val);
        MSG("INFO: Reference latitude is configured to %f deg\n", reference_coord.lat);
    }
    val = json_object_get_value(conf_obj, "ref_longitude");
    if (val != NULL) {
        reference_coord.lon = (double)json_value_get_number(val);
        MSG("INFO: Reference longitude is configured to %f deg\n", reference_coord.lon);
    }
    val = json_object_get_value(conf_obj, "ref_altitude");
    if (val != NULL) {
        reference_coord.alt = (short)json_value_get_number(val);
        MSG("INFO: Reference altitude is configured to %i meters\n", reference_coord.alt);
    }

    /* Gateway GPS coordinates hardcoding (aka. faking) option */
    val = json_object_get_value(conf_obj, "fake_gps");
    if (json_value_get_type(val) == JSONBoolean) {
        gps_fake_enable = (bool)json_value_get_boolean(val);
        if (gps_fake_enable == true) {
            MSG("INFO: fake GPS is enabled\n");
        } else {
            MSG("INFO: fake GPS is disabled\n");
        }
    }

    /* Beacon signal period (optional) */
    val = json_object_get_value(conf_obj, "beacon_period");
    if (val != NULL) {
        beacon_period = (uint32_t)json_value_get_number(val);
        if ((beacon_period > 0) && (beacon_period < 6)) {
            MSG("ERROR: invalid configuration for Beacon period, must be >= 6s\n");
            return -1;
        } else {
            MSG("INFO: Beaconing period is configured to %u seconds\n", beacon_period);
        }
    }

    /* Beacon TX frequency (optional) */
    val = json_object_get_value(conf_obj, "beacon_freq_hz");
    if (val != NULL) {
        beacon_freq_hz = (uint32_t)json_value_get_number(val);
        MSG("INFO: Beaconing signal will be emitted at %u Hz\n", beacon_freq_hz);
    }

    /* Number of beacon channels (optional) */
    val = json_object_get_value(conf_obj, "beacon_freq_nb");
    if (val != NULL) {
        beacon_freq_nb = (uint8_t)json_value_get_number(val);
        MSG("INFO: Beaconing channel number is set to %u\n", beacon_freq_nb);
    }

    /* Frequency step between beacon channels (optional) */
    val = json_object_get_value(conf_obj, "beacon_freq_step");
    if (val != NULL) {
        beacon_freq_step = (uint32_t)json_value_get_number(val);
        MSG("INFO: Beaconing channel frequency step is set to %uHz\n", beacon_freq_step);
    }

    /* Beacon datarate (optional) */
    val = json_object_get_value(conf_obj, "beacon_datarate");
    if (val != NULL) {
        beacon_datarate = (uint8_t)json_value_get_number(val);
        MSG("INFO: Beaconing datarate is set to SF%d\n", beacon_datarate);
    }

    /* Beacon modulation bandwidth (optional) */
    val = json_object_get_value(conf_obj, "beacon_bw_hz");
    if (val != NULL) {
        beacon_bw_hz = (uint32_t)json_value_get_number(val);
        MSG("INFO: Beaconing modulation bandwidth is set to %dHz\n", beacon_bw_hz);
    }

    /* Beacon TX power (optional) */
    val = json_object_get_value(conf_obj, "beacon_power");
    if (val != NULL) {
        beacon_power = (int8_t)json_value_get_number(val);
        MSG("INFO: Beaconing TX power is set to %ddBm\n", beacon_power);
    }

    /* Beacon information descriptor (optional) */
    val = json_object_get_value(conf_obj, "beacon_infodesc");
    if (val != NULL) {
        beacon_infodesc = (uint8_t)json_value_get_number(val);
        MSG("INFO: Beaconing information descriptor is set to %u\n", beacon_infodesc);
    }

    /* Auto-quit threshold (optional) */
    val = json_object_get_value(conf_obj, "autoquit_threshold");
    if (val != NULL) {
        autoquit_threshold = (uint32_t)json_value_get_number(val);
        MSG("INFO: Auto-quit after %u non-acknowledged PULL_DATA\n", autoquit_threshold);
    }
    /* free JSON parsing data structure */
    json_value_free(root_val);
    return 0;
}

static uint16_t crc16(const uint8_t * data, unsigned size) {
    const uint16_t crc_poly = 0x1021;
    const uint16_t init_val = 0x0000;
    uint16_t x = init_val;
    unsigned i, j;

    if (data == NULL)  {
        return 0;
    }

    for (i=0; i<size; ++i) {
        x ^= (uint16_t)data[i] << 8;
        for (j=0; j<8; ++j) {
            x = (x & 0x8000) ? (x<<1) ^ crc_poly : (x<<1);
        }
    }

    return x;
}

static double difftimespec(struct timespec end, struct timespec beginning) {
    double x;

    x = 1E-9 * (double)(end.tv_nsec - beginning.tv_nsec);
    x += (double)(end.tv_sec - beginning.tv_sec);

    return x;
}

static int send_tx_ack(uint8_t token_h, uint8_t token_l, enum jit_error_e error) {
    uint8_t buff_ack[64]; /* buffer to give feedback to server */
    int buff_index;

    /* reset buffer */
    memset(&buff_ack, 0, sizeof buff_ack);

    /* Prepare downlink feedback to be sent to server */
    buff_ack[0] = PROTOCOL_VERSION;
    buff_ack[1] = token_h;
    buff_ack[2] = token_l;
    buff_ack[3] = PKT_TX_ACK;
    *(uint32_t *)(buff_ack + 4) = net_mac_h;
    *(uint32_t *)(buff_ack + 8) = net_mac_l;
    buff_index = 12; /* 12-byte header */

    /* Put no JSON string if there is nothing to report */
    if (error != JIT_ERROR_OK) {
        /* start of JSON structure */
        memcpy((void *)(buff_ack + buff_index), (void *)"{\"txpk_ack\":{", 13);
        buff_index += 13;
        /* set downlink error status in JSON structure */
        memcpy((void *)(buff_ack + buff_index), (void *)"\"error\":", 8);
        buff_index += 8;
        switch (error) {
            case JIT_ERROR_FULL:
            case JIT_ERROR_COLLISION_PACKET:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"COLLISION_PACKET\"", 18);
                buff_index += 18;
                /* update stats */
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_rejected_collision_packet += 1;
                pthread_mutex_unlock(&mx_meas_dw);
                break;
            case JIT_ERROR_TOO_LATE:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"TOO_LATE\"", 10);
                buff_index += 10;
                /* update stats */
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_rejected_too_late += 1;
                pthread_mutex_unlock(&mx_meas_dw);
                break;
            case JIT_ERROR_TOO_EARLY:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"TOO_EARLY\"", 11);
                buff_index += 11;
                /* update stats */
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_rejected_too_early += 1;
                pthread_mutex_unlock(&mx_meas_dw);
                break;
            case JIT_ERROR_COLLISION_BEACON:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"COLLISION_BEACON\"", 18);
                buff_index += 18;
                /* update stats */
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_rejected_collision_beacon += 1;
                pthread_mutex_unlock(&mx_meas_dw);
                break;
            case JIT_ERROR_TX_FREQ:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"TX_FREQ\"", 9);
                buff_index += 9;
                break;
            case JIT_ERROR_TX_POWER:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"TX_POWER\"", 10);
                buff_index += 10;
                break;
            case JIT_ERROR_GPS_UNLOCKED:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"GPS_UNLOCKED\"", 14);
                buff_index += 14;
                break;
            default:
                memcpy((void *)(buff_ack + buff_index), (void *)"\"UNKNOWN\"", 9);
                buff_index += 9;
                break;
        }
        /* end of JSON structure */
        memcpy((void *)(buff_ack + buff_index), (void *)"}}", 2);
        buff_index += 2;
    }

    buff_ack[buff_index] = 0; /* add string terminator, for safety */

    /* send datagram to server */
    return send(sock_down, (void *)buff_ack, buff_index, 0);
}

void print_binary(unsigned char c)
{
 unsigned char i1 = (1 << (sizeof(c)*8-1));
 for(; i1; i1 >>= 1)
      printf("%d",(c&i1)!=0);
}

/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main(void)
{
    struct sigaction sigact; /* SIGQUIT&SIGINT&SIGTERM signal handling */
    int i; /* loop variable and temporary variable for return value */
    int x;

    /* configuration file related */
    char *global_cfg_path= "/etc/global_conf.json"; /* contain global (typ. network-wide) configuration */
    char *local_cfg_path = "/etc/local_conf.json"; /* contain node specific configuration, overwrite global parameters for parameters that are defined in both */
    char *debug_cfg_path = "/etc/debug_conf.json"; /* if present, all other configuration files are ignored */
    srand(time(0));

    /* threads */
    pthread_t thrid_up;
    pthread_t thrid_down;
    pthread_t thrid_gps;
    pthread_t thrid_valid;
    pthread_t thrid_jit;
    pthread_t thrid_netstatus;
    pthread_t thrid_timersync;

    /* network socket creation */
    //struct addrinfo hints;
    //struct addrinfo *result; /* store result of getaddrinfo */
    //struct addrinfo *q; /* pointer to move into *result data */
    //char host_name[64];
    //char port_name[64];

    /* variables to get local copies of measurements */
    uint32_t cp_nb_rx_rcv;
    uint32_t cp_nb_rx_ok;
    //uint32_t cp_nb_rx_bad;
    //uint32_t cp_nb_rx_nocrc;
    uint32_t cp_up_pkt_fwd;
    //uint32_t cp_up_network_byte;
    //uint32_t cp_up_payload_byte;
    uint32_t cp_up_dgram_sent;
    uint32_t cp_up_ack_rcv;
    uint32_t cp_dw_pull_sent;
    //uint32_t cp_dw_ack_rcv;
    uint32_t cp_dw_dgram_rcv;
    //uint32_t cp_dw_network_byte;
    //uint32_t cp_dw_payload_byte;
    uint32_t cp_nb_tx_ok;
    //uint32_t cp_nb_tx_fail;
    uint32_t cp_nb_tx_requested = 0;
    uint32_t cp_nb_tx_rejected_collision_packet = 0;
    uint32_t cp_nb_tx_rejected_collision_beacon = 0;
    uint32_t cp_nb_tx_rejected_too_late = 0;
    uint32_t cp_nb_tx_rejected_too_early = 0;
    uint32_t cp_nb_beacon_queued = 0;
    uint32_t cp_nb_beacon_sent = 0;
    uint32_t cp_nb_beacon_rejected = 0;

    /* GPS coordinates variables */
    bool coord_ok = false;
    struct coord_s cp_gps_coord = {0.0, 0.0, 0};

    /* SX1301 data variables */
    uint32_t trig_tstamp;

    /* statistics variable */
    time_t t;
    char stat_timestamp[24];
    //float rx_ok_ratio;
    //float rx_bad_ratio;
    //float rx_nocrc_ratio;
    float up_ack_ratio;
    //float dw_ack_ratio;
    MSG("Reseting concentrator");
    int fd = open("/sys/class/gpio/export", O_WRONLY);
    if (fd == -1) {
        perror("Unable to open /sys/class/gpio/export");
    }

    if (write(fd, "95", 2) != 2) {
        perror("Error writing to /sys/class/gpio/export");
    }

    close(fd);

    // Set the pin to be an output by writing "out" to /sys/class/gpio/gpio24/direction

    fd = open("/sys/class/gpio/pioC31/direction", O_WRONLY);
    if (fd == -1) {
        perror("Unable to open /sys/class/gpio/pioC31/direction");
    }

    if (write(fd, "out", 3) != 3) {
        perror("Error writing to /sys/class/gpio/pioC31/direction");
    }

    close(fd);

    fd = open("/sys/class/gpio/pioC31/value", O_WRONLY);
    if (fd == -1) {
        perror("Unable to open /sys/class/gpio/pioC31/value");
    }
    if (write(fd, "1", 1) != 1) {
        perror("Error writing to /sys/class/gpio/gpio24/value");
    }
    if (write(fd, "0", 1) != 1) {
        perror("Error writing to /sys/class/gpio/gpio24/value");
    }

    close(fd);


    /* display version informations */
    MSG("*** Beacon Packet Forwarder for Lora Gateway ***\nVersion: " VERSION_STRING "\n");
    MSG("*** Lora concentrator HAL library version info ***\n%s\n***\n", lgw_version_info());

    /* display host endianness */
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        MSG("INFO: Little endian host\n");
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        MSG("INFO: Big endian host\n");
    #else
        MSG("INFO: Host endianness unknown\n");
    #endif

    /* load configuration files */
    if (access(debug_cfg_path, R_OK) == 0) { /* if there is a debug conf, parse only the debug conf */
        MSG("INFO: found debug configuration file %s, parsing it\n", debug_cfg_path);
        MSG("INFO: other configuration files will be ignored\n");
        x = parse_SX1301_configuration(debug_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
        x = parse_gateway_configuration(debug_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
    } else if (access(global_cfg_path, R_OK) == 0) { /* if there is a global conf, parse it and then try to parse local conf  */
        MSG("INFO: found global configuration file %s, parsing it\n", global_cfg_path);
        x = parse_SX1301_configuration(global_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
        x = parse_gateway_configuration(global_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
        if (access(local_cfg_path, R_OK) == 0) {
            MSG("INFO: found local configuration file %s, parsing it\n", local_cfg_path);
            MSG("INFO: redefined parameters will overwrite global parameters\n");
            parse_SX1301_configuration(local_cfg_path);
            parse_gateway_configuration(local_cfg_path);
        }
    } else if (access(local_cfg_path, R_OK) == 0) { /* if there is only a local conf, parse it and that's all */
        MSG("INFO: found local configuration file %s, parsing it\n", local_cfg_path);
        x = parse_SX1301_configuration(local_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
        x = parse_gateway_configuration(local_cfg_path);
        if (x != 0) {
            exit(EXIT_FAILURE);
        }
    } else {
        MSG("ERROR: [main] failed to find any configuration file named %s, %s OR %s\n", global_cfg_path, local_cfg_path, debug_cfg_path);
        exit(EXIT_FAILURE);
    }

    /* Start GPS a.s.a.p., to allow it to lock */
    if (gps_tty_path[0] != '\0') { /* do not try to open GPS device if no path set */
        i = lgw_gps_enable(gps_tty_path, "ubx7", 0, &gps_tty_fd); /* HAL only supports u-blox 7 for now */
        if (i != LGW_GPS_SUCCESS) {
            printf("WARNING: [main] impossible to open %s for GPS sync (check permissions)\n", gps_tty_path);
            gps_enabled = false;
            gps_ref_valid = false;
        } else {
            printf("INFO: [main] TTY port %s open for GPS synchronization\n", gps_tty_path);
            gps_enabled = true;
            gps_ref_valid = false;
        }
    }

    /* get timezone info */
    tzset();

    /* sanity check on configuration variables */
    // TODO

    /* process some of the configuration variables */
    net_mac_h = htonl((uint32_t)(0xFFFFFFFF & (lgwm>>32)));
    net_mac_l = htonl((uint32_t)(0xFFFFFFFF &  lgwm  ));

    /* starting the concentrator */
    i = lgw_start();
    if (i == LGW_HAL_SUCCESS) {
        MSG("INFO: [main] concentrator started, packet can now be received\n");
    } else {
        MSG("ERROR: [main] failed to start the concentrator\n");
        exit(EXIT_FAILURE);
    }
    gettimeofday(&last_unix_time, NULL);
    /* spawn threads to manage upstream and downstream */
    i = pthread_create( &thrid_up, NULL, (void * (*)(void *))thread_up, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create upstream thread\n");
        exit(EXIT_FAILURE);
    }
    if(1){
        i = pthread_create( &thrid_down, NULL, (void * (*)(void *))thread_down, NULL);
        if (i != 0) {
            MSG("ERROR: [main] impossible to create downstream thread\n");
            exit(EXIT_FAILURE);
        }
    }
    i = pthread_create( &thrid_jit, NULL, (void * (*)(void *))thread_jit, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create JIT thread\n");
        exit(EXIT_FAILURE);
    }
    i = pthread_create( &thrid_netstatus, NULL, (void * (*)(void *))thread_netstatus, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create Net status thread\n");
        exit(EXIT_FAILURE);
    }
    i = pthread_create( &thrid_timersync, NULL, (void * (*)(void *))thread_timersync, NULL);
    if (i != 0) {
        MSG("ERROR: [main] impossible to create Timer Sync thread\n");
        exit(EXIT_FAILURE);
    }

    /* spawn thread to manage GPS */
    if (gps_enabled == true) {
        i = pthread_create( &thrid_gps, NULL, (void * (*)(void *))thread_gps, NULL);
        if (i != 0) {
            MSG("ERROR: [main] impossible to create GPS thread\n");
            exit(EXIT_FAILURE);
        }
        i = pthread_create( &thrid_valid, NULL, (void * (*)(void *))thread_valid, NULL);
        if (i != 0) {
            MSG("ERROR: [main] impossible to create validation thread\n");
            exit(EXIT_FAILURE);
        }
    }

    /* configure signal handling */
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigact.sa_handler = sig_handler;
    sigaction(SIGQUIT, &sigact, NULL); /* Ctrl-\ */
    sigaction(SIGINT, &sigact, NULL); /* Ctrl-C */
    sigaction(SIGTERM, &sigact, NULL); /* default "kill" command */

    /* main loop task : statistics collection */
    while (!exit_sig && !quit_sig) {
        /* wait for next reporting interval */
        wait_ms(1000 * stat_interval);
        if(offline==0){
            ttn_data_exchange();
        }
        /* get timestamp for statistics */
        t = time(NULL);
        strftime(stat_timestamp, sizeof stat_timestamp, "%F %T %Z", gmtime(&t));

        /* access upstream statistics, copy and reset them */
        pthread_mutex_lock(&mx_meas_up);
        cp_nb_rx_rcv       = meas_nb_rx_rcv;
        cp_nb_rx_ok        = meas_nb_rx_ok;
        //cp_nb_rx_bad       = meas_nb_rx_bad;
        //cp_nb_rx_nocrc     = meas_nb_rx_nocrc;
        cp_up_pkt_fwd      = meas_up_pkt_fwd;
       // cp_up_network_byte = meas_up_network_byte;
        //cp_up_payload_byte = meas_up_payload_byte;
        cp_up_dgram_sent   = meas_up_dgram_sent;
        cp_up_ack_rcv      = meas_up_ack_rcv;
        meas_nb_rx_rcv = 0;
        meas_nb_rx_ok = 0;
        meas_nb_rx_bad = 0;
        meas_nb_rx_nocrc = 0;
        meas_up_pkt_fwd = 0;
        meas_up_network_byte = 0;
        //meas_up_payload_byte = 0;
        meas_up_dgram_sent = 0;
        meas_up_ack_rcv = 0;
        pthread_mutex_unlock(&mx_meas_up);
        /*if (cp_nb_rx_rcv > 0) {
            rx_ok_ratio = (float)cp_nb_rx_ok / (float)cp_nb_rx_rcv;
            rx_bad_ratio = (float)cp_nb_rx_bad / (float)cp_nb_rx_rcv;
            rx_nocrc_ratio = (float)cp_nb_rx_nocrc / (float)cp_nb_rx_rcv;
        } else {
            rx_ok_ratio = 0.0;
            rx_bad_ratio = 0.0;
            rx_nocrc_ratio = 0.0;
        }*/
        if (cp_up_dgram_sent > 0) {
            up_ack_ratio = (float)cp_up_ack_rcv / (float)cp_up_dgram_sent;
        } else {
            up_ack_ratio = 0.0;
        }

        /* access downstream statistics, copy and reset them */
        pthread_mutex_lock(&mx_meas_dw);
        cp_dw_pull_sent    =  meas_dw_pull_sent;
        //cp_dw_ack_rcv      =  meas_dw_ack_rcv;
        cp_dw_dgram_rcv    =  meas_dw_dgram_rcv;
        //cp_dw_network_byte =  meas_dw_network_byte;
        //cp_dw_payload_byte =  meas_dw_payload_byte;
        cp_nb_tx_ok        =  meas_nb_tx_ok;
        //cp_nb_tx_fail      =  meas_nb_tx_fail;
        cp_nb_tx_requested                 +=  meas_nb_tx_requested;
        cp_nb_tx_rejected_collision_packet +=  meas_nb_tx_rejected_collision_packet;
        cp_nb_tx_rejected_collision_beacon +=  meas_nb_tx_rejected_collision_beacon;
        cp_nb_tx_rejected_too_late         +=  meas_nb_tx_rejected_too_late;
        cp_nb_tx_rejected_too_early        +=  meas_nb_tx_rejected_too_early;
        cp_nb_beacon_queued   +=  meas_nb_beacon_queued;
        cp_nb_beacon_sent     +=  meas_nb_beacon_sent;
        cp_nb_beacon_rejected +=  meas_nb_beacon_rejected;
        meas_dw_pull_sent = 0;
        meas_dw_ack_rcv = 0;
        meas_dw_dgram_rcv = 0;
        meas_dw_network_byte = 0;
        meas_dw_payload_byte = 0;
        meas_nb_tx_ok = 0;
        meas_nb_tx_fail = 0;
        meas_nb_tx_requested = 0;
        meas_nb_tx_rejected_collision_packet = 0;
        meas_nb_tx_rejected_collision_beacon = 0;
        meas_nb_tx_rejected_too_late = 0;
        meas_nb_tx_rejected_too_early = 0;
        meas_nb_beacon_queued = 0;
        meas_nb_beacon_sent = 0;
        meas_nb_beacon_rejected = 0;
        pthread_mutex_unlock(&mx_meas_dw);
        if (cp_dw_pull_sent > 0) {
            //dw_ack_ratio = (float)cp_dw_ack_rcv / (float)cp_dw_pull_sent;
        } else {
            //dw_ack_ratio = 0.0;
        }

        /* access GPS statistics, copy them */
        if (gps_enabled == true) {
            pthread_mutex_lock(&mx_meas_gps);
            coord_ok = gps_coord_valid;
            cp_gps_coord = meas_gps_coord;
            pthread_mutex_unlock(&mx_meas_gps);
        }

        /* overwrite with reference coordinates if function is enabled */
        if (gps_fake_enable == true) {
            cp_gps_coord = reference_coord;
        }

        /* display a report */
        /*printf("\n##### %s #####\n", stat_timestamp);
        printf("### [UPSTREAM] ###\n");
        printf("# RF packets received by concentrator: %u\n", cp_nb_rx_rcv);
        printf("# CRC_OK: %.2f%%, CRC_FAIL: %.2f%%, NO_CRC: %.2f%%\n", 100.0 * rx_ok_ratio, 100.0 * rx_bad_ratio, 100.0 * rx_nocrc_ratio);
        printf("# RF packets forwarded: %u (%u bytes)\n", cp_up_pkt_fwd, cp_up_payload_byte);
        printf("# PUSH_DATA datagrams sent: %u (%u bytes)\n", cp_up_dgram_sent, cp_up_network_byte);
        printf("# PUSH_DATA acknowledged: %.2f%%\n", 100.0 * up_ack_ratio);
        printf("### [DOWNSTREAM] ###\n");
        printf("# PULL_DATA sent: %u (%.2f%% acknowledged)\n", cp_dw_pull_sent, 100.0 * dw_ack_ratio);
        printf("# PULL_RESP(onse) datagrams received: %u (%u bytes)\n", cp_dw_dgram_rcv, cp_dw_network_byte);
        printf("# RF packets sent to concentrator: %u (%u bytes)\n", (cp_nb_tx_ok+cp_nb_tx_fail), cp_dw_payload_byte);
        printf("# TX errors: %u\n", cp_nb_tx_fail);
        if (cp_nb_tx_requested != 0 ) {
            printf("# TX rejected (collision packet): %.2f%% (req:%u, rej:%u)\n", 100.0 * cp_nb_tx_rejected_collision_packet / cp_nb_tx_requested, cp_nb_tx_requested, cp_nb_tx_rejected_collision_packet);
            printf("# TX rejected (collision beacon): %.2f%% (req:%u, rej:%u)\n", 100.0 * cp_nb_tx_rejected_collision_beacon / cp_nb_tx_requested, cp_nb_tx_requested, cp_nb_tx_rejected_collision_beacon);
            printf("# TX rejected (too late): %.2f%% (req:%u, rej:%u)\n", 100.0 * cp_nb_tx_rejected_too_late / cp_nb_tx_requested, cp_nb_tx_requested, cp_nb_tx_rejected_too_late);
            printf("# TX rejected (too early): %.2f%% (req:%u, rej:%u)\n", 100.0 * cp_nb_tx_rejected_too_early / cp_nb_tx_requested, cp_nb_tx_requested, cp_nb_tx_rejected_too_early);
        }
        printf("# BEACON queued: %u\n", cp_nb_beacon_queued);
        printf("# BEACON sent so far: %u\n", cp_nb_beacon_sent);
        printf("# BEACON rejected: %u\n", cp_nb_beacon_rejected);
        printf("### [JIT] ###\n");*/
        /* get timestamp captured on PPM pulse  */
        pthread_mutex_lock(&mx_concent);
        i = lgw_get_trigcnt(&trig_tstamp);
        pthread_mutex_unlock(&mx_concent);
        /*if (i != LGW_HAL_SUCCESS) {
            printf("# SX1301 time (PPS): unknown\n");
        } else {
            printf("# SX1301 time (PPS): %u\n", trig_tstamp);
        }
        jit_print_queue (&jit_queue, false, DEBUG_LOG);
        printf("### [GPS] ###\n");
        if (gps_enabled == true) {
            // no need for mutex, display is not critical 
            if (gps_ref_valid == true) {
                printf("# Valid time reference (age: %li sec)\n", (long)difftime(time(NULL), time_reference_gps.systime));
            } else {
                printf("# Invalid time reference (age: %li sec)\n", (long)difftime(time(NULL), time_reference_gps.systime));
            }
            if (coord_ok == true) {
                printf("# GPS coordinates: latitude %.5f, longitude %.5f, altitude %i m\n", cp_gps_coord.lat, cp_gps_coord.lon, cp_gps_coord.alt);
            } else {
                printf("# no valid GPS coordinates available yet\n");
            }
        } else if (gps_fake_enable == true) {
            printf("# GPS *FAKE* coordinates: latitude %.5f, longitude %.5f, altitude %i m\n", cp_gps_coord.lat, cp_gps_coord.lon, cp_gps_coord.alt);
        } else {
            printf("# GPS sync is disabled\n");
        }
        printf("##### END #####\n");
        */

        /* generate a JSON report (will be sent to server by upstream thread) */
        pthread_mutex_lock(&mx_stat_rep);
        if (((gps_enabled == true) && (coord_ok == true)) || (gps_fake_enable == true)) {
            snprintf(status_report, STATUS_SIZE, "\"stat\":{\"time\":\"%s\",\"lati\":%.5f,\"long\":%.5f,\"alti\":%i,\"rxnb\":%u,\"rxok\":%u,\"rxfw\":%u,\"ackr\":%.1f,\"dwnb\":%u,\"txnb\":%u}", stat_timestamp, cp_gps_coord.lat, cp_gps_coord.lon, cp_gps_coord.alt, cp_nb_rx_rcv, cp_nb_rx_ok, cp_up_pkt_fwd, 100.0 * up_ack_ratio, cp_dw_dgram_rcv, cp_nb_tx_ok);
        } else {
            snprintf(status_report, STATUS_SIZE, "\"stat\":{\"time\":\"%s\",\"rxnb\":%u,\"rxok\":%u,\"rxfw\":%u,\"ackr\":%.1f,\"dwnb\":%u,\"txnb\":%u}", stat_timestamp, cp_nb_rx_rcv, cp_nb_rx_ok, cp_up_pkt_fwd, 100.0 * up_ack_ratio, cp_dw_dgram_rcv, cp_nb_tx_ok);
        }
        report_ready = true;
        pthread_mutex_unlock(&mx_stat_rep);
    }

    /* wait for upstream thread to finish (1 fetch cycle max) */
    pthread_join(thrid_up, NULL);
    pthread_cancel(thrid_down); /* don't wait for downstream thread */
    pthread_cancel(thrid_jit); /* don't wait for jit thread */
    pthread_cancel(thrid_netstatus);
    pthread_cancel(thrid_timersync); /* don't wait for timer sync thread */
    if (gps_enabled == true) {
        pthread_cancel(thrid_gps); /* don't wait for GPS thread */
        pthread_cancel(thrid_valid); /* don't wait for validation thread */

        i = lgw_gps_disable(gps_tty_fd);
        if (i == LGW_HAL_SUCCESS) {
            MSG("INFO: GPS closed successfully\n");
        } else {
            MSG("WARNING: failed to close GPS successfully\n");
        }
    }

    /* if an exit signal was received, try to quit properly */
    if (exit_sig) {
        /* shut down network sockets */
        shutdown(sock_up, SHUT_RDWR);
        shutdown(sock_down, SHUT_RDWR);
        /* stop the hardware */
        i = lgw_stop();
        if (i == LGW_HAL_SUCCESS) {
            MSG("INFO: concentrator stopped successfully\n");
        } else {
            MSG("WARNING: failed to stop concentrator successfully\n");
        }
    }

    MSG("INFO: Exiting packet forwarder program\n");
    exit(EXIT_SUCCESS);
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 1: RECEIVING PACKETS AND FORWARDING THEM ---------------------- */

void thread_up(void) {
    int i, j; /* loop variables */
    unsigned pkt_in_dgram; /* nb on Lora packet in the current datagram */

    /* allocate memory for packet fetching and processing */
    struct lgw_pkt_rx_s rxpkt[NB_PKT_MAX]; /* array containing inbound packets + metadata */
    struct lgw_pkt_rx_s *p; /* pointer on a RX packet */
    int nb_pkt;

    /* local copy of GPS time reference */
    bool ref_ok = false; /* determine if GPS time reference must be used or not */
    struct tref local_ref; /* time reference used for UTC <-> timestamp conversion */

    /* data buffers */
    uint8_t buff_up[TX_BUFF_SIZE]; /* buffer to compose the upstream packet */
    int buff_index;
    uint8_t buff_ack[32]; /* buffer to receive acknowledges */

    /* protocol variables */
    uint8_t token_h; /* random token for acknowledgement matching */
    uint8_t token_l; /* random token for acknowledgement matching */

    /* ping measurement variables */
    struct timespec send_time;
    struct timespec recv_time;

    /* GPS synchronization variables */
    struct timespec pkt_utc_time;
    struct tm * x; /* broken-up UTC time */
    struct timespec pkt_gps_time;
    uint64_t pkt_gps_time_ms;

    /* report management variable */
    bool send_report = false;

    /* mote info variables */
    uint32_t mote_addr = 0;
    uint16_t mote_fcnt = 0;

    /* set upstream socket RX timeout */


    /* pre-fill the data buffer with fixed fields */
    buff_up[0] = PROTOCOL_VERSION;
    buff_up[3] = PKT_PUSH_DATA;
    *(uint32_t *)(buff_up + 4) = net_mac_h;
    *(uint32_t *)(buff_up + 8) = net_mac_l;

    while (!exit_sig && !quit_sig) {

            i = setsockopt(sock_up, SOL_SOCKET, SO_RCVTIMEO, (void *)&push_timeout_half, sizeof push_timeout_half);
            if (i != 0) {
#if VERBOSE==1
                MSG("ERROR: [up] setsockopt returned %s\n", strerror(errno));
#endif
                offline=1;
                laststatus=1;
            }

        /* fetch packets */
        pthread_mutex_lock(&mx_concent);
        nb_pkt = lgw_receive(NB_PKT_MAX, rxpkt);
        pthread_mutex_unlock(&mx_concent);
        if (nb_pkt == LGW_HAL_ERROR) {
            MSG("ERROR: [up] failed packet fetch, exiting\n");
            exit(EXIT_FAILURE);
        }

        /* check if there are status report to send */
        send_report = report_ready; /* copy the variable so it doesn't change mid-function */
        /* no mutex, we're only reading */

        /* wait a short time if no packets, nor status report */
        if ((nb_pkt == 0) && (send_report == false)) {
            wait_ms(FETCH_SLEEP_MS);
            continue;
        }

        /* get a copy of GPS time reference (avoid 1 mutex per packet) */
        if ((nb_pkt > 0) && (gps_enabled == true)) {
            pthread_mutex_lock(&mx_timeref);
            ref_ok = gps_ref_valid;
            local_ref = time_reference_gps;
            pthread_mutex_unlock(&mx_timeref);
        } else {
            ref_ok = false;
        }

        /* start composing datagram with the header */
        token_h = (uint8_t)rand(); /* random token */
        token_l = (uint8_t)rand(); /* random token */
        buff_up[1] = token_h;
        buff_up[2] = token_l;
        buff_index = 12; /* 12-byte header */

        /* start of JSON structure */
        memcpy((void *)(buff_up + buff_index), (void *)"{\"rxpk\":[", 9);
        buff_index += 9;

        /* serialize Lora packets metadata and payload */
        pkt_in_dgram = 0;
        for (i=0; i < nb_pkt; ++i) {
            p = &rxpkt[i];

            /* Get mote information from current packet (addr, fcnt) */
            /* FHDR - DevAddr */
            mote_addr  = p->payload[1];
            mote_addr |= p->payload[2] << 8;
            mote_addr |= p->payload[3] << 16;
            mote_addr |= p->payload[4] << 24;
            /* FHDR - FCnt */
            mote_fcnt  = p->payload[6];
            mote_fcnt |= p->payload[7] << 8;

            /* basic packet filtering */
            pthread_mutex_lock(&mx_meas_up);
            meas_nb_rx_rcv += 1;
            switch(p->status) {
                case STAT_CRC_OK:
                    meas_nb_rx_ok += 1;
                    printf( "\nINFO: Received pkt from mote: %08X (fcnt=%u)\n", mote_addr, mote_fcnt );
                    if (!fwd_valid_pkt) {
                        pthread_mutex_unlock(&mx_meas_up);
                        continue; /* skip that packet */
                    }
                    break;
                case STAT_CRC_BAD:
                    meas_nb_rx_bad += 1;
                    if (!fwd_error_pkt) {
                        pthread_mutex_unlock(&mx_meas_up);
                        continue; /* skip that packet */
                    }
                    break;
                case STAT_NO_CRC:
                    meas_nb_rx_nocrc += 1;
                    if (!fwd_nocrc_pkt) {
                        pthread_mutex_unlock(&mx_meas_up);
                        continue; /* skip that packet */
                    }
                    break;
                default:
                    MSG("WARNING: [up] received packet with unknown status %u (size %u, modulation %u, BW %u, DR %u, RSSI %.1f)\n", p->status, p->size, p->modulation, p->bandwidth, p->datarate, p->rssi);
                    pthread_mutex_unlock(&mx_meas_up);
                    continue; /* skip that packet */
                    // exit(EXIT_FAILURE);
            }
            meas_up_pkt_fwd += 1;
            meas_up_payload_byte += p->size;
            pthread_mutex_unlock(&mx_meas_up);

            /* Start of packet, add inter-packet separator if necessary */
            if (pkt_in_dgram == 0) {
                buff_up[buff_index] = '{';
                ++buff_index;
            } else {
                buff_up[buff_index] = ',';
                buff_up[buff_index+1] = '{';
                buff_index += 2;
            }

            /* RAW timestamp, 8-17 useful chars */
            j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, "\"tmst\":%u", p->count_us);
            if (j > 0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                exit(EXIT_FAILURE);
            }

            /* Packet RX time (GPS based), 37 useful chars */
            if (ref_ok == true) {
                /* convert packet timestamp to UTC absolute time */
                j = lgw_cnt2utc(local_ref, p->count_us, &pkt_utc_time);
                if (j == LGW_GPS_SUCCESS) {
                    /* split the UNIX timestamp to its calendar components */
                    x = gmtime(&(pkt_utc_time.tv_sec));
                    j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"time\":\"%04i-%02i-%02iT%02i:%02i:%02i.%06liZ\"", (x->tm_year)+1900, (x->tm_mon)+1, x->tm_mday, x->tm_hour, x->tm_min, x->tm_sec, (pkt_utc_time.tv_nsec)/1000); /* ISO 8601 format */
                    if (j > 0) {
                        buff_index += j;
                    } else {
                        MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                        exit(EXIT_FAILURE);
                    }
                }
                /* convert packet timestamp to GPS absolute time */
                j = lgw_cnt2gps(local_ref, p->count_us, &pkt_gps_time);
                if (j == LGW_GPS_SUCCESS) {
                    pkt_gps_time_ms = pkt_gps_time.tv_sec * 1E3 + pkt_gps_time.tv_nsec / 1E6;
                    j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"tmms\":%llu",
                                    pkt_gps_time_ms); /* GPS time in milliseconds since 06.Jan.1980 */
                    if (j > 0) {
                        buff_index += j;
                    } else {
                        MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                        exit(EXIT_FAILURE);
                    }
                }
            }

            /* Packet concentrator channel, RF chain & RX frequency, 34-36 useful chars */
            j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"chan\":%1u,\"rfch\":%1u,\"freq\":%.6lf", p->if_chain, p->rf_chain, ((double)p->freq_hz / 1e6));
            if (j > 0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                exit(EXIT_FAILURE);
            }

            /* Packet status, 9-10 useful chars */
            switch (p->status) {
                case STAT_CRC_OK:
                    memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":1", 9);
                    buff_index += 9;
                    break;
                case STAT_CRC_BAD:
                    memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":-1", 10);
                    buff_index += 10;
                    break;
                case STAT_NO_CRC:
                    memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":0", 9);
                    buff_index += 9;
                    break;
                default:
                    MSG("ERROR: [up] received packet with unknown status\n");
                    memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":?", 9);
                    buff_index += 9;
                    exit(EXIT_FAILURE);
            }

            /* Packet modulation, 13-14 useful chars */
            if (p->modulation == MOD_LORA) {
                memcpy((void *)(buff_up + buff_index), (void *)",\"modu\":\"LORA\"", 14);
                buff_index += 14;

                /* Lora datarate & bandwidth, 16-19 useful chars */
                switch (p->datarate) {
                    case DR_LORA_SF7:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF7", 12);
                        buff_index += 12;
                        break;
                    case DR_LORA_SF8:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF8", 12);
                        buff_index += 12;
                        break;
                    case DR_LORA_SF9:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF9", 12);
                        buff_index += 12;
                        break;
                    case DR_LORA_SF10:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF10", 13);
                        buff_index += 13;
                        break;
                    case DR_LORA_SF11:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF11", 13);
                        buff_index += 13;
                        break;
                    case DR_LORA_SF12:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF12", 13);
                        buff_index += 13;
                        break;
                    default:
                        MSG("ERROR: [up] lora packet with unknown datarate\n");
                        memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF?", 12);
                        buff_index += 12;
                        exit(EXIT_FAILURE);
                }
                switch (p->bandwidth) {
                    case BW_125KHZ:
                        memcpy((void *)(buff_up + buff_index), (void *)"BW125\"", 6);
                        buff_index += 6;
                        break;
                    case BW_250KHZ:
                        memcpy((void *)(buff_up + buff_index), (void *)"BW250\"", 6);
                        buff_index += 6;
                        break;
                    case BW_500KHZ:
                        memcpy((void *)(buff_up + buff_index), (void *)"BW500\"", 6);
                        buff_index += 6;
                        break;
                    default:
                        MSG("ERROR: [up] lora packet with unknown bandwidth\n");
                        memcpy((void *)(buff_up + buff_index), (void *)"BW?\"", 4);
                        buff_index += 4;
                        exit(EXIT_FAILURE);
                }

                /* Packet ECC coding rate, 11-13 useful chars */
                switch (p->coderate) {
                    case CR_LORA_4_5:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/5\"", 13);
                        buff_index += 13;
                        break;
                    case CR_LORA_4_6:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/6\"", 13);
                        buff_index += 13;
                        break;
                    case CR_LORA_4_7:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/7\"", 13);
                        buff_index += 13;
                        break;
                    case CR_LORA_4_8:
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/8\"", 13);
                        buff_index += 13;
                        break;
                    case 0: /* treat the CR0 case (mostly false sync) */
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"OFF\"", 13);
                        buff_index += 13;
                        break;
                    default:
                        MSG("ERROR: [up] lora packet with unknown coderate\n");
                        memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"?\"", 11);
                        buff_index += 11;
                        exit(EXIT_FAILURE);
                }

                /* Lora SNR, 11-13 useful chars */
                j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"lsnr\":%.1f", p->snr);
                if (j > 0) {
                    buff_index += j;
                } else {
                    MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                    exit(EXIT_FAILURE);
                }
            } else if (p->modulation == MOD_FSK) {
                memcpy((void *)(buff_up + buff_index), (void *)",\"modu\":\"FSK\"", 13);
                buff_index += 13;

                /* FSK datarate, 11-14 useful chars */
                j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"datr\":%u", p->datarate);
                if (j > 0) {
                    buff_index += j;
                } else {
                    MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                    exit(EXIT_FAILURE);
                }
            } else {
                MSG("ERROR: [up] received packet with unknown modulation\n");
                exit(EXIT_FAILURE);
            }

            /* Packet RSSI, payload size, 18-23 useful chars */
            j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, ",\"rssi\":%.0f,\"size\":%u", p->rssi, p->size);
            if (j > 0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 4));
                exit(EXIT_FAILURE);
            }

            /* Packet base64-encoded payload, 14-350 useful chars */
            memcpy((void *)(buff_up + buff_index), (void *)",\"data\":\"", 9);
            buff_index += 9;
            j = bin_to_b64(p->payload, p->size, (char *)(buff_up + buff_index), 341); /* 255 bytes = 340 chars in b64 + null char */
            if (j>=0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] bin_to_b64 failed line %u\n", (__LINE__ - 5));
                exit(EXIT_FAILURE);
            }
            localpkt_up(p);
            buff_up[buff_index] = '"';
            ++buff_index;

            /* End of packet serialization */
            buff_up[buff_index] = '}';
            ++buff_index;
            ++pkt_in_dgram;
        }

        /* restart fetch sequence without sending empty JSON if all packets have been filtered out */
        if (pkt_in_dgram == 0) {
            if (send_report == true) {
                /* need to clean up the beginning of the payload */
                buff_index -= 8; /* removes "rxpk":[ */
            } else {
                /* all packet have been filtered out and no report, restart loop */
                continue;
            }
        } else {
            /* end of packet array */
            buff_up[buff_index] = ']';
            ++buff_index;
            /* add separator if needed */
            if (send_report == true) {
                buff_up[buff_index] = ',';
                ++buff_index;
            }
        }

        /* add status report if a new one is available */
        if (send_report == true) {
            pthread_mutex_lock(&mx_stat_rep);
            report_ready = false;
            j = snprintf((char *)(buff_up + buff_index), TX_BUFF_SIZE-buff_index, "%s", status_report);
            pthread_mutex_unlock(&mx_stat_rep);
            if (j > 0) {
                buff_index += j;
            } else {
                MSG("ERROR: [up] snprintf failed line %u\n", (__LINE__ - 5));
                exit(EXIT_FAILURE);
            }
        }

        /* end of JSON datagram payload */
        buff_up[buff_index] = '}';
        ++buff_index;
        buff_up[buff_index] = 0; /* add string terminator, for safety */
#if VERBOSE==1
        printf("\nJSON up: %s\n", (char *)(buff_up + 12)); /* DEBUG: display JSON payload */
#endif
        /* send datagram to server */
        if(offline==0){
            send(sock_up, (void *)buff_up, buff_index, 0);
            clock_gettime(CLOCK_MONOTONIC, &send_time);
            pthread_mutex_lock(&mx_meas_up);
            meas_up_dgram_sent += 1;
            meas_up_network_byte += buff_index;

            /* wait for acknowledge (in 2 times, to catch extra packets) */
            for (i=0; i<2; ++i) {
                j = recv(sock_up, (void *)buff_ack, sizeof buff_ack, 0);
                clock_gettime(CLOCK_MONOTONIC, &recv_time);
                if (j == -1) {
                    if (errno == EAGAIN) { /* timeout */
                        continue;
                    } else { /* server connection error */
                        break;
                    }
                } else if ((j < 4) || (buff_ack[0] != PROTOCOL_VERSION) || (buff_ack[3] != PKT_PUSH_ACK)) {
                    //MSG("WARNING: [up] ignored invalid non-ACL packet\n");
                    continue;
                } else if ((buff_ack[1] != token_h) || (buff_ack[2] != token_l)) {
                    //MSG("WARNING: [up] ignored out-of sync ACK packet\n");
                    continue;
                } else {
#if VERBOSE==1
                    MSG("INFO: [up] PUSH_ACK received in %i ms\n", (int)(1000 * difftimespec(recv_time, send_time)));
#endif
                    meas_up_ack_rcv += 1;
                    break;
                }
            }
        }
        pthread_mutex_unlock(&mx_meas_up);
    }
    MSG("\nINFO: End of upstream thread\n");
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 2: POLLING SERVER AND ENQUEUING PACKETS IN JIT QUEUE ---------- */

void thread_down(void) {
    int i; /* loop variables */

    /* configuration and metadata for an outbound packet */
    struct lgw_pkt_tx_s txpkt;
    bool sent_immediate = false; /* option to sent the packet immediately */

    /* local timekeeping variables */
    struct timespec send_time; /* time of the pull request */
    struct timespec recv_time; /* time of return from recv socket call */

    /* data buffers */
    uint8_t buff_down[1000]; /* buffer to receive downstream packets */
    uint8_t buff_req[12]; /* buffer to compose pull requests */
    int msg_len;

    /* protocol variables */
    uint8_t token_h; /* random token for acknowledgement matching */
    uint8_t token_l; /* random token for acknowledgement matching */
    bool req_ack = false; /* keep track of whether PULL_DATA was acknowledged or not */

    /* JSON parsing variables */
    JSON_Value *root_val = NULL;
    JSON_Object *txpk_obj = NULL;
    JSON_Value *val = NULL; /* needed to detect the absence of some fields */
    const char *str; /* pointer to sub-strings in the JSON data */
    short x0, x1;
    uint64_t x2;
    double x3, x4;

    /* variables to send on GPS timestamp */
    struct tref local_ref; /* time reference used for GPS <-> timestamp conversion */
    struct timespec gps_tx; /* GPS time that needs to be converted to timestamp */

    /* beacon variables */
    struct lgw_pkt_tx_s beacon_pkt;
    uint8_t beacon_chan;
    uint8_t beacon_loop;
    size_t beacon_RFU1_size = 0;
    size_t beacon_RFU2_size = 0;
    uint8_t beacon_pyld_idx = 0;
    time_t diff_beacon_time;
    struct timespec next_beacon_gps_time; /* gps time of next beacon packet */
    struct timespec last_beacon_gps_time; /* gps time of last enqueued beacon packet */
    int retry;

    /* beacon data fields, byte 0 is Least Significant Byte */
    int32_t field_latitude; /* 3 bytes, derived from reference latitude */
    int32_t field_longitude; /* 3 bytes, derived from reference longitude */
    uint16_t field_crc1, field_crc2;

    /* auto-quit variable */
    uint32_t autoquit_cnt = 0; /* count the number of PULL_DATA sent since the latest PULL_ACK */

    /* Just In Time downlink */
    struct timeval current_unix_time;
    struct timeval current_concentrator_time;
    enum jit_error_e jit_result = JIT_ERROR_OK;
    enum jit_pkt_type_e downlink_type;

    /* pre-fill the pull request buffer with fixed fields */
    buff_req[0] = PROTOCOL_VERSION;
    buff_req[3] = PKT_PULL_DATA;
    *(uint32_t *)(buff_req + 4) = net_mac_h;
    *(uint32_t *)(buff_req + 8) = net_mac_l;

    /* beacon variables initialization */
    last_beacon_gps_time.tv_sec = 0;
    last_beacon_gps_time.tv_nsec = 0;

    /* beacon packet parameters */
    beacon_pkt.tx_mode = ON_GPS; /* send on PPS pulse */
    beacon_pkt.rf_chain = 0; /* antenna A */
    beacon_pkt.rf_power = beacon_power;
    beacon_pkt.modulation = MOD_LORA;
    switch (beacon_bw_hz) {
        case 125000:
            beacon_pkt.bandwidth = BW_125KHZ;
            break;
        case 500000:
            beacon_pkt.bandwidth = BW_500KHZ;
            break;
        default:
            /* should not happen */
            MSG("ERROR: unsupported bandwidth for beacon\n");
            //exit(EXIT_FAILURE);
    }
    switch (beacon_datarate) {
        case 8:
            beacon_pkt.datarate = DR_LORA_SF8;
            beacon_RFU1_size = 1;
            beacon_RFU2_size = 3;
            break;
        case 9:
            beacon_pkt.datarate = DR_LORA_SF9;
            beacon_RFU1_size = 2;
            beacon_RFU2_size = 0;
            break;
        case 10:
            beacon_pkt.datarate = DR_LORA_SF10;
            beacon_RFU1_size = 3;
            beacon_RFU2_size = 1;
            break;
        case 12:
            beacon_pkt.datarate = DR_LORA_SF12;
            beacon_RFU1_size = 5;
            beacon_RFU2_size = 3;
            break;
        default:
            /* should not happen */
            MSG("ERROR: unsupported datarate for beacon\n");
            //exit(EXIT_FAILURE);
    }
    beacon_pkt.size = beacon_RFU1_size + 4 + 2 + 7 + beacon_RFU2_size + 2;
    beacon_pkt.coderate = CR_LORA_4_5;
    beacon_pkt.invert_pol = false;
    beacon_pkt.preamble = 10;
    beacon_pkt.no_crc = true;
    beacon_pkt.no_header = true;

    /* network common part beacon fields (little endian) */
    for (i = 0; i < (int)beacon_RFU1_size; i++) {
        beacon_pkt.payload[beacon_pyld_idx++] = 0x0;
    }

    /* network common part beacon fields (little endian) */
    beacon_pyld_idx += 4; /* time (variable), filled later */
    beacon_pyld_idx += 2; /* crc1 (variable), filled later */

    /* calculate the latitude and longitude that must be publicly reported */
    field_latitude = (int32_t)((reference_coord.lat / 90.0) * (double)(1<<23));
    if (field_latitude > (int32_t)0x007FFFFF) {
        field_latitude = (int32_t)0x007FFFFF; /* +90 N is represented as 89.99999 N */
    } else if (field_latitude < (int32_t)0xFF800000) {
        field_latitude = (int32_t)0xFF800000;
    }
    field_longitude = (int32_t)((reference_coord.lon / 180.0) * (double)(1<<23));
    if (field_longitude > (int32_t)0x007FFFFF) {
        field_longitude = (int32_t)0x007FFFFF; /* +180 E is represented as 179.99999 E */
    } else if (field_longitude < (int32_t)0xFF800000) {
        field_longitude = (int32_t)0xFF800000;
    }

    /* gateway specific beacon fields */
    beacon_pkt.payload[beacon_pyld_idx++] = beacon_infodesc;
    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF &  field_latitude;
    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (field_latitude >>  8);
    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (field_latitude >> 16);
    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF &  field_longitude;
    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (field_longitude >>  8);
    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (field_longitude >> 16);

    /* RFU */
    for (i = 0; i < (int)beacon_RFU2_size; i++) {
        beacon_pkt.payload[beacon_pyld_idx++] = 0x0;
    }

    /* CRC of the beacon gateway specific part fields */
    field_crc2 = crc16((beacon_pkt.payload + 6 + beacon_RFU1_size), 7 + beacon_RFU2_size);
    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF &  field_crc2;
    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (field_crc2 >> 8);

    /* JIT queue initialization */
    jit_queue_init(&jit_queue);

    while (!exit_sig && !quit_sig) {

        i = setsockopt(sock_down, SOL_SOCKET, SO_RCVTIMEO, (void *)&pull_timeout, sizeof pull_timeout);
        if (i != 0) {
            //MSG("ERROR: [down] setsockopt returned %s\n", strerror(errno));
            offline=1;
            laststatus=1;
        }

        /* auto-quit if the threshold is crossed */
        if ((autoquit_threshold > 0) && (autoquit_cnt >= autoquit_threshold)) {
            //exit_sig = true;
            MSG("WARNING: [down] the last %u PULL_DATA were not ACKed\n", autoquit_threshold);
            break;
        }

        /* generate random token for request */
        token_h = (uint8_t)rand(); /* random token */
        token_l = (uint8_t)rand(); /* random token */
        buff_req[1] = token_h;
        buff_req[2] = token_l;

        /* send PULL request and record time */
        send(sock_down, (void *)buff_req, sizeof buff_req, 0);
        clock_gettime(CLOCK_MONOTONIC, &send_time);
        pthread_mutex_lock(&mx_meas_dw);
        meas_dw_pull_sent += 1;
        pthread_mutex_unlock(&mx_meas_dw);
        req_ack = false;
        autoquit_cnt++;

        /* listen to packets and process them until a new PULL request must be sent */
        recv_time = send_time;
        while ((int)difftimespec(recv_time, send_time) < keepalive_time) {

            /* try to receive a datagram */
            msg_len = recv(sock_down, (void *)buff_down, (sizeof buff_down)-1, 0);
            clock_gettime(CLOCK_MONOTONIC, &recv_time);

            /* Pre-allocate beacon slots in JiT queue, to check downlink collisions */
            beacon_loop = JIT_NUM_BEACON_IN_QUEUE - jit_queue.num_beacon;
            retry = 0;
            while (beacon_loop && (beacon_period != 0)) {
                pthread_mutex_lock(&mx_timeref);
                /* Wait for GPS to be ready before inserting beacons in JiT queue */
                if ((gps_ref_valid == true) && (xtal_correct_ok == true)) {

                    /* compute GPS time for next beacon to come      */
                    /*   LoRaWAN: T = k*beacon_period + TBeaconDelay */
                    /*            with TBeaconDelay = [1.5ms +/- 1µs]*/
                    if (last_beacon_gps_time.tv_sec == 0) {
                        /* if no beacon has been queued, get next slot from current GPS time */
                        diff_beacon_time = time_reference_gps.gps.tv_sec % ((time_t)beacon_period);
                        next_beacon_gps_time.tv_sec = time_reference_gps.gps.tv_sec +
                                                        ((time_t)beacon_period - diff_beacon_time);
                    } else {
                        /* if there is already a beacon, take it as reference */
                        next_beacon_gps_time.tv_sec = last_beacon_gps_time.tv_sec + beacon_period;
                    }
                    /* now we can add a beacon_period to the reference to get next beacon GPS time */
                    next_beacon_gps_time.tv_sec += (retry * beacon_period);
                    next_beacon_gps_time.tv_nsec = 0;

#if DEBUG_BEACON
                    {
                    time_t time_unix;

                    time_unix = time_reference_gps.gps.tv_sec + UNIX_GPS_EPOCH_OFFSET;
                    MSG_DEBUG(DEBUG_BEACON, "GPS-now : %s", ctime(&time_unix));
                    time_unix = last_beacon_gps_time.tv_sec + UNIX_GPS_EPOCH_OFFSET;
                    MSG_DEBUG(DEBUG_BEACON, "GPS-last: %s", ctime(&time_unix));
                    time_unix = next_beacon_gps_time.tv_sec + UNIX_GPS_EPOCH_OFFSET;
                    MSG_DEBUG(DEBUG_BEACON, "GPS-next: %s", ctime(&time_unix));
                    }
#endif

                    /* convert GPS time to concentrator time, and set packet counter for JiT trigger */
                    lgw_gps2cnt(time_reference_gps, next_beacon_gps_time, &(beacon_pkt.count_us));
                    pthread_mutex_unlock(&mx_timeref);

                    /* apply frequency correction to beacon TX frequency */
                    if (beacon_freq_nb > 1) {
                        beacon_chan = (next_beacon_gps_time.tv_sec / beacon_period) % beacon_freq_nb; /* floor rounding */
                    } else {
                        beacon_chan = 0;
                    }
                    /* Compute beacon frequency */
                    beacon_pkt.freq_hz = beacon_freq_hz + (beacon_chan * beacon_freq_step);

                    /* load time in beacon payload */
                    beacon_pyld_idx = beacon_RFU1_size;
                    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF &  next_beacon_gps_time.tv_sec;
                    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (next_beacon_gps_time.tv_sec >>  8);
                    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (next_beacon_gps_time.tv_sec >> 16);
                    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (next_beacon_gps_time.tv_sec >> 24);

                    /* calculate CRC */
                    field_crc1 = crc16(beacon_pkt.payload, 4 + beacon_RFU1_size); /* CRC for the network common part */
                    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & field_crc1;
                    beacon_pkt.payload[beacon_pyld_idx++] = 0xFF & (field_crc1 >> 8);

                    /* Insert beacon packet in JiT queue */
                    gettimeofday(&current_unix_time, NULL);
                    get_concentrator_time(&current_concentrator_time, current_unix_time);
                    jit_result = jit_enqueue(&jit_queue, &current_concentrator_time, &beacon_pkt, JIT_PKT_TYPE_BEACON);
                    if (jit_result == JIT_ERROR_OK) {
                        /* update stats */
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_nb_beacon_queued += 1;
                        pthread_mutex_unlock(&mx_meas_dw);

                        /* One more beacon in the queue */
                        beacon_loop--;
                        retry = 0;
                        last_beacon_gps_time.tv_sec = next_beacon_gps_time.tv_sec; /* keep this beacon time as reference for next one to be programmed */

                        /* display beacon payload */
                        MSG("INFO: Beacon queued (count_us=%u, freq_hz=%u, size=%u):\n", beacon_pkt.count_us, beacon_pkt.freq_hz, beacon_pkt.size);
                        printf( "   => " );
                        for (i = 0; i < beacon_pkt.size; ++i) {
                            MSG("%02X ", beacon_pkt.payload[i]);
                        }
                        MSG("\n");
                    } else {
                        MSG_DEBUG(DEBUG_BEACON, "--> beacon queuing failed with %d\n", jit_result);
                        /* update stats */
                        pthread_mutex_lock(&mx_meas_dw);
                        if (jit_result != JIT_ERROR_COLLISION_BEACON) {
                            meas_nb_beacon_rejected += 1;
                        }
                        pthread_mutex_unlock(&mx_meas_dw);
                        /* In case previous enqueue failed, we retry one period later until it succeeds */
                        /* Note: In case the GPS has been unlocked for a while, there can be lots of retries */
                        /*       to be done from last beacon time to a new valid one */
                        retry++;
                        MSG_DEBUG(DEBUG_BEACON, "--> beacon queuing retry=%d\n", retry);
                    }
                } else {
                    pthread_mutex_unlock(&mx_timeref);
                    break;
                }
            }

            /* if no network message was received, got back to listening sock_down socket */
            if (msg_len == -1) {
                //MSG("WARNING: [down] recv returned %s\n", strerror(errno)); /* too verbose */
                continue;
            }

            /* if the datagram does not respect protocol, just ignore it */
            if ((msg_len < 4) || (buff_down[0] != PROTOCOL_VERSION) || ((buff_down[3] != PKT_PULL_RESP) && (buff_down[3] != PKT_PULL_ACK))) {
                MSG("WARNING: [down] ignoring invalid packet len=%d, protocol_version=%d, id=%d\n",
                        msg_len, buff_down[0], buff_down[3]);
                continue;
            }

            /* if the datagram is an ACK, check token */
            if (buff_down[3] == PKT_PULL_ACK) {
                if ((buff_down[1] == token_h) && (buff_down[2] == token_l)) {
                    if (req_ack) {
                        MSG("INFO: [down] duplicate ACK received :)\n");
                    } else { /* if that packet was not already acknowledged */
                        req_ack = true;
                        autoquit_cnt = 0;
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_dw_ack_rcv += 1;
                        pthread_mutex_unlock(&mx_meas_dw);
#if VERBOSE==1
                        MSG("INFO: [down] PULL_ACK received in %i ms\n", (int)(1000 * difftimespec(recv_time, send_time)));
#endif
                    }
                } else { /* out-of-sync token */
                    MSG("INFO: [down] received out-of-sync ACK\n");
                }
                continue;
            }

            /* the datagram is a PULL_RESP */
            buff_down[msg_len] = 0; /* add string terminator, just to be safe */
#if VERBOSE==1
            MSG("INFO: [down] PULL_RESP received  - token[%d:%d] :)\n", buff_down[1], buff_down[2]); /* very verbose */
            printf("\nJSON down: %s\n", (char *)(buff_down + 4)); /* DEBUG: display JSON payload */
#endif
            /* initialize TX struct and try to parse JSON */
            memset(&txpkt, 0, sizeof txpkt);
            root_val = json_parse_string_with_comments((const char *)(buff_down + 4)); /* JSON offset */
            if (root_val == NULL) {
                MSG("WARNING: [down] invalid JSON, TX aborted\n");
                continue;
            }

            /* look for JSON sub-object 'txpk' */
            txpk_obj = json_object_get_object(json_value_get_object(root_val), "txpk");
            if (txpk_obj == NULL) {
                MSG("WARNING: [down] no \"txpk\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }

            /* Parse "immediate" tag, or target timestamp, or UTC time to be converted by GPS (mandatory) */
            i = json_object_get_boolean(txpk_obj,"imme"); /* can be 1 if true, 0 if false, or -1 if not a JSON boolean */
            if (i == 1) {
                /* TX procedure: send immediately */
                sent_immediate = true;
                downlink_type = JIT_PKT_TYPE_DOWNLINK_CLASS_C;
                MSG("INFO: [down] a packet will be sent in \"immediate\" mode\n");
            } else {
                sent_immediate = false;
                val = json_object_get_value(txpk_obj,"tmst");
                if (val != NULL) {
                    /* TX procedure: send on timestamp value */
                    txpkt.count_us = (uint32_t)json_value_get_number(val);

                    /* Concentrator timestamp is given, we consider it is a Class A downlink */
                    downlink_type = JIT_PKT_TYPE_DOWNLINK_CLASS_A;
                } else {
                    /* TX procedure: send on GPS time (converted to timestamp value) */
                    val = json_object_get_value(txpk_obj, "tmms");
                    if (val == NULL) {
                        MSG("WARNING: [down] no mandatory \"txpk.tmst\" or \"txpk.tmms\" objects in JSON, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                    }
                    if (gps_enabled == true) {
                        pthread_mutex_lock(&mx_timeref);
                        if (gps_ref_valid == true) {
                            local_ref = time_reference_gps;
                            pthread_mutex_unlock(&mx_timeref);
                        } else {
                            pthread_mutex_unlock(&mx_timeref);
                            MSG("WARNING: [down] no valid GPS time reference yet, impossible to send packet on specific GPS time, TX aborted\n");
                            json_value_free(root_val);

                            /* send acknoledge datagram to server */
                            send_tx_ack(buff_down[1], buff_down[2], JIT_ERROR_GPS_UNLOCKED);
                            continue;
                        }
                    } else {
                        MSG("WARNING: [down] GPS disabled, impossible to send packet on specific GPS time, TX aborted\n");
                        json_value_free(root_val);

                        /* send acknoledge datagram to server */
                        send_tx_ack(buff_down[1], buff_down[2], JIT_ERROR_GPS_UNLOCKED);
                        continue;
                    }

                    /* Get GPS time from JSON */
                    x2 = (uint64_t)json_value_get_number(val);

                    /* Convert GPS time from milliseconds to timespec */
                    x3 = modf((double)x2/1E3, &x4);
                    gps_tx.tv_sec = (time_t)x4; /* get seconds from integer part */
                    gps_tx.tv_nsec = (long)(x3 * 1E9); /* get nanoseconds from fractional part */

                    /* transform GPS time to timestamp */
                    i = lgw_gps2cnt(local_ref, gps_tx, &(txpkt.count_us));
                    if (i != LGW_GPS_SUCCESS) {
                        MSG("WARNING: [down] could not convert GPS time to timestamp, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                    } else {
                        MSG("INFO: [down] a packet will be sent on timestamp value %u (calculated from GPS time)\n", txpkt.count_us);
                    }

                    /* GPS timestamp is given, we consider it is a Class B downlink */
                    downlink_type = JIT_PKT_TYPE_DOWNLINK_CLASS_B;
                }
            }

            /* Parse "No CRC" flag (optional field) */
            val = json_object_get_value(txpk_obj,"ncrc");
            if (val != NULL) {
                txpkt.no_crc = (bool)json_value_get_boolean(val);
            }

            /* parse target frequency (mandatory) */
            val = json_object_get_value(txpk_obj,"freq");
            if (val == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.freq\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            txpkt.freq_hz = (uint32_t)((double)(1.0e6) * json_value_get_number(val));

            /* parse RF chain used for TX (mandatory) */
            val = json_object_get_value(txpk_obj,"rfch");
            if (val == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.rfch\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            txpkt.rf_chain = (uint8_t)json_value_get_number(val);

            /* parse TX power (optional field) */
            val = json_object_get_value(txpk_obj,"powe");
            if (val != NULL) {
                txpkt.rf_power = (int8_t)json_value_get_number(val) - antenna_gain;
            }

            /* Parse modulation (mandatory) */
            str = json_object_get_string(txpk_obj, "modu");
            if (str == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.modu\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            if (strcmp(str, "LORA") == 0) {
                /* Lora modulation */
                txpkt.modulation = MOD_LORA;

                /* Parse Lora spreading-factor and modulation bandwidth (mandatory) */
                str = json_object_get_string(txpk_obj, "datr");
                if (str == NULL) {
                    MSG("WARNING: [down] no mandatory \"txpk.datr\" object in JSON, TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                i = sscanf(str, "SF%2hdBW%3hd", &x0, &x1);
                if (i != 2) {
                    MSG("WARNING: [down] format error in \"txpk.datr\", TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                switch (x0) {
                    case  7: txpkt.datarate = DR_LORA_SF7;  break;
                    case  8: txpkt.datarate = DR_LORA_SF8;  break;
                    case  9: txpkt.datarate = DR_LORA_SF9;  break;
                    case 10: txpkt.datarate = DR_LORA_SF10; break;
                    case 11: txpkt.datarate = DR_LORA_SF11; break;
                    case 12: txpkt.datarate = DR_LORA_SF12; break;
                    default:
                        MSG("WARNING: [down] format error in \"txpk.datr\", invalid SF, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                }
                switch (x1) {
                    case 125: txpkt.bandwidth = BW_125KHZ; break;
                    case 250: txpkt.bandwidth = BW_250KHZ; break;
                    case 500: txpkt.bandwidth = BW_500KHZ; break;
                    default:
                        MSG("WARNING: [down] format error in \"txpk.datr\", invalid BW, TX aborted\n");
                        json_value_free(root_val);
                        continue;
                }

                /* Parse ECC coding rate (optional field) */
                str = json_object_get_string(txpk_obj, "codr");
                if (str == NULL) {
                    MSG("WARNING: [down] no mandatory \"txpk.codr\" object in json, TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                if      (strcmp(str, "4/5") == 0) txpkt.coderate = CR_LORA_4_5;
                else if (strcmp(str, "4/6") == 0) txpkt.coderate = CR_LORA_4_6;
                else if (strcmp(str, "2/3") == 0) txpkt.coderate = CR_LORA_4_6;
                else if (strcmp(str, "4/7") == 0) txpkt.coderate = CR_LORA_4_7;
                else if (strcmp(str, "4/8") == 0) txpkt.coderate = CR_LORA_4_8;
                else if (strcmp(str, "1/2") == 0) txpkt.coderate = CR_LORA_4_8;
                else {
                    MSG("WARNING: [down] format error in \"txpk.codr\", TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }

                /* Parse signal polarity switch (optional field) */
                val = json_object_get_value(txpk_obj,"ipol");
                if (val != NULL) {
                    txpkt.invert_pol = (bool)json_value_get_boolean(val);
                }

                /* parse Lora preamble length (optional field, optimum min value enforced) */
                val = json_object_get_value(txpk_obj,"prea");
                if (val != NULL) {
                    i = (int)json_value_get_number(val);
                    if (i >= MIN_LORA_PREAMB) {
                        txpkt.preamble = (uint16_t)i;
                    } else {
                        txpkt.preamble = (uint16_t)MIN_LORA_PREAMB;
                    }
                } else {
                    txpkt.preamble = (uint16_t)STD_LORA_PREAMB;
                }

            } else if (strcmp(str, "FSK") == 0) {
                /* FSK modulation */
                txpkt.modulation = MOD_FSK;

                /* parse FSK bitrate (mandatory) */
                val = json_object_get_value(txpk_obj,"datr");
                if (val == NULL) {
                    MSG("WARNING: [down] no mandatory \"txpk.datr\" object in JSON, TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                txpkt.datarate = (uint32_t)(json_value_get_number(val));

                /* parse frequency deviation (mandatory) */
                val = json_object_get_value(txpk_obj,"fdev");
                if (val == NULL) {
                    MSG("WARNING: [down] no mandatory \"txpk.fdev\" object in JSON, TX aborted\n");
                    json_value_free(root_val);
                    continue;
                }
                txpkt.f_dev = (uint8_t)(json_value_get_number(val) / 1000.0); /* JSON value in Hz, txpkt.f_dev in kHz */

                /* parse FSK preamble length (optional field, optimum min value enforced) */
                val = json_object_get_value(txpk_obj,"prea");
                if (val != NULL) {
                    i = (int)json_value_get_number(val);
                    if (i >= MIN_FSK_PREAMB) {
                        txpkt.preamble = (uint16_t)i;
                    } else {
                        txpkt.preamble = (uint16_t)MIN_FSK_PREAMB;
                    }
                } else {
                    txpkt.preamble = (uint16_t)STD_FSK_PREAMB;
                }

            } else {
                MSG("WARNING: [down] invalid modulation in \"txpk.modu\", TX aborted\n");
                json_value_free(root_val);
                continue;
            }

            /* Parse payload length (mandatory) */
            val = json_object_get_value(txpk_obj,"size");
            if (val == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.size\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            txpkt.size = (uint16_t)json_value_get_number(val);

            /* Parse payload data (mandatory) */
            str = json_object_get_string(txpk_obj, "data");
            if (str == NULL) {
                MSG("WARNING: [down] no mandatory \"txpk.data\" object in JSON, TX aborted\n");
                json_value_free(root_val);
                continue;
            }
            i = b64_to_bin(str, strlen(str), txpkt.payload, sizeof txpkt.payload);
#if VERBOSE==1
            MSG("INFO: [down] packet payload binary: \n");
            for(int y = 0; y < i; y++){
                print_binary(txpkt.payload[y]);
            }
#endif

            if (i != txpkt.size) {
                MSG("WARNING: [down] mismatch between .size and .data size once converter to binary\n");
            }

            /* free the JSON parse tree from memory */
            json_value_free(root_val);

            /* select TX mode */
            if (sent_immediate) {
                txpkt.tx_mode = IMMEDIATE;
            } else {
                txpkt.tx_mode = TIMESTAMPED;
            }

            /* record measurement data */
            pthread_mutex_lock(&mx_meas_dw);
            meas_dw_dgram_rcv += 1; /* count only datagrams with no JSON errors */
            meas_dw_network_byte += msg_len; /* meas_dw_network_byte */
            meas_dw_payload_byte += txpkt.size;
            pthread_mutex_unlock(&mx_meas_dw);

            /* check TX parameter before trying to queue packet */
            jit_result = JIT_ERROR_OK;
            if ((txpkt.freq_hz < tx_freq_min[txpkt.rf_chain]) || (txpkt.freq_hz > tx_freq_max[txpkt.rf_chain])) {
                jit_result = JIT_ERROR_TX_FREQ;
                MSG("ERROR: Packet REJECTED, unsupported frequency - %u (min:%u,max:%u)\n", txpkt.freq_hz, tx_freq_min[txpkt.rf_chain], tx_freq_max[txpkt.rf_chain]);
            }
            if (jit_result == JIT_ERROR_OK) {
                for (i=0; i<txlut.size; i++) {
                    if (txlut.lut[i].rf_power == txpkt.rf_power) {
                        /* this RF power is supported, we can continue */
                        break;
                    }
                }
                if (i == txlut.size) {
                    /* this RF power is not supported */
                    jit_result = JIT_ERROR_TX_POWER;
                    MSG("ERROR: Packet REJECTED, unsupported RF power for TX - %d\n", txpkt.rf_power);
                }
            }

            /* insert packet to be sent into JIT queue */

        /*uint32_t devaddrnow = txpkt.payload[1] | (txpkt.payload[2] << 8) | (txpkt.payload[3] << 16) | (txpkt.payload[4] << 24);
        uint32_t fcntnow = txpkt.payload[6] | (txpkt.payload[7] << 8) | (0 << 16) | (0 << 24);

        for (unsigned int i = 0; i < (sizeof(myuid)/8); i++) { //check if device is in list of our devices
            if(mydevaddr[i]==devaddrnow){
                if(fcntnow > myfcntdown[i]){
                    myfcntdown[i] = fcntnow;
                }
                break;
            }
        }*/


            if (jit_result == JIT_ERROR_OK) {
                gettimeofday(&current_unix_time, NULL);
                get_concentrator_time(&current_concentrator_time, current_unix_time);
                jit_result = jit_enqueue(&jit_queue, &current_concentrator_time, &txpkt, downlink_type);
                if (jit_result != JIT_ERROR_OK) {
                    printf("ERROR: Packet REJECTED (jit error=%d)\n", jit_result);
                }
                pthread_mutex_lock(&mx_meas_dw);
                meas_nb_tx_requested += 1;
                pthread_mutex_unlock(&mx_meas_dw);
            }

            /* Send acknoledge datagram to server */
            send_tx_ack(buff_down[1], buff_down[2], jit_result);
        }
    }
    MSG("\nINFO: End of downstream thread\n");
}

void print_tx_status(uint8_t tx_status) {
    switch (tx_status) {
        case TX_OFF:
            MSG("INFO: [jit] lgw_status returned TX_OFF\n");
            break;
        case TX_FREE:
            MSG("INFO: [jit] lgw_status returned TX_FREE\n");
            break;
        case TX_EMITTING:
            MSG("INFO: [jit] lgw_status returned TX_EMITTING\n");
            break;
        case TX_SCHEDULED:
            MSG("INFO: [jit] lgw_status returned TX_SCHEDULED\n");
            break;
        default:
            MSG("INFO: [jit] lgw_status returned UNKNOWN (%d)\n", tx_status);
            break;
    }
}


/* -------------------------------------------------------------------------- */
/* --- THREAD 3: CHECKING PACKETS TO BE SENT FROM JIT QUEUE AND SEND THEM --- */

void thread_jit(void) {
    int result = LGW_HAL_SUCCESS;
    struct lgw_pkt_tx_s pkt;
    int pkt_index = -1;
    struct timeval current_unix_time;
    struct timeval current_concentrator_time;
    enum jit_error_e jit_result;
    enum jit_pkt_type_e pkt_type;
    uint8_t tx_status;

    while (!exit_sig && !quit_sig) {
        wait_ms(10);

        /* transfer data and metadata to the concentrator, and schedule TX */
        gettimeofday(&current_unix_time, NULL);
        get_concentrator_time(&current_concentrator_time, current_unix_time);
        jit_result = jit_peek(&jit_queue, &current_concentrator_time, &pkt_index);
        if (jit_result == JIT_ERROR_OK) {
            if (pkt_index > -1) {
                jit_result = jit_dequeue(&jit_queue, pkt_index, &pkt, &pkt_type);
                if (jit_result == JIT_ERROR_OK) {
                    /* update beacon stats */
                    if (pkt_type == JIT_PKT_TYPE_BEACON) {
                        /* Compensate breacon frequency with xtal error */
                        pthread_mutex_lock(&mx_xcorr);
                        pkt.freq_hz = (uint32_t)(xtal_correct * (double)pkt.freq_hz);
                        MSG_DEBUG(DEBUG_BEACON, "beacon_pkt.freq_hz=%u (xtal_correct=%.15lf)\n", pkt.freq_hz, xtal_correct);
                        pthread_mutex_unlock(&mx_xcorr);

                        /* Update statistics */
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_nb_beacon_sent += 1;
                        pthread_mutex_unlock(&mx_meas_dw);
                        MSG("INFO: Beacon dequeued (count_us=%u)\n", pkt.count_us);
                    }

                    /* check if concentrator is free for sending new packet */
                    pthread_mutex_lock(&mx_concent); /* may have to wait for a fetch to finish */
                    result = lgw_status(TX_STATUS, &tx_status);
                    pthread_mutex_unlock(&mx_concent); /* free concentrator ASAP */
                    if (result == LGW_HAL_ERROR) {
                        MSG("WARNING: [jit] lgw_status failed\n");
                    } else {
                        if (tx_status == TX_EMITTING) {
                            MSG("ERROR: concentrator is currently emitting\n");
                            print_tx_status(tx_status);
                            continue;
                        } else if (tx_status == TX_SCHEDULED) {
                            MSG("WARNING: a downlink was already scheduled, overwritting it...\n");
                            print_tx_status(tx_status);
                        } else {
                            /* Nothing to do */
                        }
                    }

                    /* send packet to concentrator */
                    pthread_mutex_lock(&mx_concent); /* may have to wait for a fetch to finish */
                    result = lgw_send(pkt);
                    pthread_mutex_unlock(&mx_concent); /* free concentrator ASAP */
                    if (result == LGW_HAL_ERROR) {
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_nb_tx_fail += 1;
                        pthread_mutex_unlock(&mx_meas_dw);
                        MSG("WARNING: [jit] lgw_send failed\n");
                        continue;
                    } else {
                        pthread_mutex_lock(&mx_meas_dw);
                        meas_nb_tx_ok += 1;
                        pthread_mutex_unlock(&mx_meas_dw);
                        MSG_DEBUG(DEBUG_PKT_FWD, "lgw_send done: count_us=%u\n", pkt.count_us);
                    }
                } else {
                    MSG("ERROR: jit_dequeue failed with %d\n", jit_result);
                }
            }
        } else if (jit_result == JIT_ERROR_EMPTY) {
            /* Do nothing, it can happen */
        } else {
            MSG("ERROR: jit_peek failed with %d\n", jit_result);
        }
    }
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 4: PARSE GPS MESSAGE AND KEEP GATEWAY IN SYNC ----------------- */

static void gps_process_sync(void) {
    struct timespec gps_time;
    struct timespec utc;
    uint32_t trig_tstamp; /* concentrator timestamp associated with PPM pulse */
    int i = lgw_gps_get(&utc, &gps_time, NULL, NULL);

    /* get GPS time for synchronization */
    if (i != LGW_GPS_SUCCESS) {
        MSG("WARNING: [gps] could not get GPS time from GPS\n");
        return;
    }

    /* get timestamp captured on PPM pulse  */
    pthread_mutex_lock(&mx_concent);
    i = lgw_get_trigcnt(&trig_tstamp);
    pthread_mutex_unlock(&mx_concent);
    if (i != LGW_HAL_SUCCESS) {
        MSG("WARNING: [gps] failed to read concentrator timestamp\n");
        return;
    }

    /* try to update time reference with the new GPS time & timestamp */
    pthread_mutex_lock(&mx_timeref);
    i = lgw_gps_sync(&time_reference_gps, trig_tstamp, utc, gps_time);
    pthread_mutex_unlock(&mx_timeref);
    if (i != LGW_GPS_SUCCESS) {
        MSG("WARNING: [gps] GPS out of sync, keeping previous time reference\n");
    }
}

static void gps_process_coords(void) {
    /* position variable */
    struct coord_s coord;
    struct coord_s gpserr;
    int    i = lgw_gps_get(NULL, NULL, &coord, &gpserr);

    /* update gateway coordinates */
    pthread_mutex_lock(&mx_meas_gps);
    if (i == LGW_GPS_SUCCESS) {
        gps_coord_valid = true;
        meas_gps_coord = coord;
        meas_gps_err = gpserr;
        // TODO: report other GPS statistics (typ. signal quality & integrity)
    } else {
        gps_coord_valid = false;
    }
    pthread_mutex_unlock(&mx_meas_gps);
}

void thread_gps(void) {
    /* serial variables */
    char serial_buff[128]; /* buffer to receive GPS data */
    size_t wr_idx = 0;     /* pointer to end of chars in buffer */

    /* variables for PPM pulse GPS synchronization */
    enum gps_msg latest_msg; /* keep track of latest NMEA message parsed */

    /* initialize some variables before loop */
    memset(serial_buff, 0, sizeof serial_buff);

    while (!exit_sig && !quit_sig) {
        size_t rd_idx = 0;
        size_t frame_end_idx = 0;

        /* blocking non-canonical read on serial port */
        ssize_t nb_char = read(gps_tty_fd, serial_buff + wr_idx, LGW_GPS_MIN_MSG_SIZE);
        if (nb_char <= 0) {
            MSG("WARNING: [gps] read() returned value %d\n", nb_char);
            continue;
        }
        wr_idx += (size_t)nb_char;

        /*******************************************
         * Scan buffer for UBX/NMEA sync chars and *
         * attempt to decode frame if one is found *
         *******************************************/
        while(rd_idx < wr_idx) {
            size_t frame_size = 0;

            /* Scan buffer for UBX sync char */
            if(serial_buff[rd_idx] == (char)LGW_GPS_UBX_SYNC_CHAR) {

                /***********************
                 * Found UBX sync char *
                 ***********************/
                latest_msg = lgw_parse_ubx(&serial_buff[rd_idx], (wr_idx - rd_idx), &frame_size);

                if (frame_size > 0) {
                    if (latest_msg == INCOMPLETE) {
                        /* UBX header found but frame appears to be missing bytes */
                        frame_size = 0;
                    } else if (latest_msg == INVALID) {
                        /* message header received but message appears to be corrupted */
                        MSG("WARNING: [gps] could not get a valid message from GPS (no time)\n");
                        frame_size = 0;
                    } else if (latest_msg == UBX_NAV_TIMEGPS) {
                        gps_process_sync();
                    }
                }
            } else if(serial_buff[rd_idx] == LGW_GPS_NMEA_SYNC_CHAR) {
                /************************
                 * Found NMEA sync char *
                 ************************/
                /* scan for NMEA end marker (LF = 0x0a) */
                char* nmea_end_ptr = memchr(&serial_buff[rd_idx],(int)0x0a, (wr_idx - rd_idx));

                if(nmea_end_ptr) {
                    /* found end marker */
                    frame_size = nmea_end_ptr - &serial_buff[rd_idx] + 1;
                    latest_msg = lgw_parse_nmea(&serial_buff[rd_idx], frame_size);

                    if(latest_msg == INVALID || latest_msg == UNKNOWN) {
                        /* checksum failed */
                        frame_size = 0;
                    } else if (latest_msg == NMEA_RMC) { /* Get location from RMC frames */
                        gps_process_coords();
                    }
                }
            }

            if(frame_size > 0) {
                /* At this point message is a checksum verified frame
                   we're processed or ignored. Remove frame from buffer */
                rd_idx += frame_size;
                frame_end_idx = rd_idx;
            } else {
                rd_idx++;
            }
        } /* ...for(rd_idx = 0... */

        if(frame_end_idx) {
          /* Frames have been processed. Remove bytes to end of last processed frame */
          memcpy(serial_buff, &serial_buff[frame_end_idx], wr_idx - frame_end_idx);
          wr_idx -= frame_end_idx;
        } /* ...for(rd_idx = 0... */

        /* Prevent buffer overflow */
        if((sizeof(serial_buff) - wr_idx) < LGW_GPS_MIN_MSG_SIZE) {
            memcpy(serial_buff, &serial_buff[LGW_GPS_MIN_MSG_SIZE], wr_idx - LGW_GPS_MIN_MSG_SIZE);
            wr_idx -= LGW_GPS_MIN_MSG_SIZE;
        }
    }
    MSG("\nINFO: End of GPS thread\n");
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 5: CHECK TIME REFERENCE AND CALCULATE XTAL CORRECTION --------- */

void thread_valid(void) {

    /* GPS reference validation variables */
    long gps_ref_age = 0;
    bool ref_valid_local = false;
    double xtal_err_cpy;

    /* variables for XTAL correction averaging */
    unsigned init_cpt = 0;
    double init_acc = 0.0;
    double x;

    /* correction debug */
    // FILE * log_file = NULL;
    // time_t now_time;
    // char log_name[64];

    /* initialization */
    // time(&now_time);
    // strftime(log_name,sizeof log_name,"xtal_err_%Y%m%dT%H%M%SZ.csv",localtime(&now_time));
    // log_file = fopen(log_name, "w");
    // setbuf(log_file, NULL);
    // fprintf(log_file,"\"xtal_correct\",\"XERR_INIT_AVG %u XERR_FILT_COEF %u\"\n", XERR_INIT_AVG, XERR_FILT_COEF); // DEBUG

    /* main loop task */
    while (!exit_sig && !quit_sig) {
        wait_ms(1000);

        /* calculate when the time reference was last updated */
        pthread_mutex_lock(&mx_timeref);
        gps_ref_age = (long)difftime(time(NULL), time_reference_gps.systime);
        if ((gps_ref_age >= 0) && (gps_ref_age <= GPS_REF_MAX_AGE)) {
            /* time ref is ok, validate and  */
            gps_ref_valid = true;
            ref_valid_local = true;
            xtal_err_cpy = time_reference_gps.xtal_err;
            //printf("XTAL err: %.15lf (1/XTAL_err:%.15lf)\n", xtal_err_cpy, 1/xtal_err_cpy); // DEBUG
        } else {
            /* time ref is too old, invalidate */
            gps_ref_valid = false;
            ref_valid_local = false;
        }
        pthread_mutex_unlock(&mx_timeref);

        /* manage XTAL correction */
        if (ref_valid_local == false) {
            /* couldn't sync, or sync too old -> invalidate XTAL correction */
            pthread_mutex_lock(&mx_xcorr);
            xtal_correct_ok = false;
            xtal_correct = 1.0;
            pthread_mutex_unlock(&mx_xcorr);
            init_cpt = 0;
            init_acc = 0.0;
        } else {
            if (init_cpt < XERR_INIT_AVG) {
                /* initial accumulation */
                init_acc += xtal_err_cpy;
                ++init_cpt;
            } else if (init_cpt == XERR_INIT_AVG) {
                /* initial average calculation */
                pthread_mutex_lock(&mx_xcorr);
                xtal_correct = (double)(XERR_INIT_AVG) / init_acc;
                //printf("XERR_INIT_AVG=%d, init_acc=%.15lf\n", XERR_INIT_AVG, init_acc);
                xtal_correct_ok = true;
                pthread_mutex_unlock(&mx_xcorr);
                ++init_cpt;
                // fprintf(log_file,"%.18lf,\"average\"\n", xtal_correct); // DEBUG
            } else {
                /* tracking with low-pass filter */
                x = 1 / xtal_err_cpy;
                pthread_mutex_lock(&mx_xcorr);
                xtal_correct = xtal_correct - xtal_correct/XERR_FILT_COEF + x/XERR_FILT_COEF;
                pthread_mutex_unlock(&mx_xcorr);
                // fprintf(log_file,"%.18lf,\"track\"\n", xtal_correct); // DEBUG
            }
        }
        // printf("Time ref: %s, XTAL correct: %s (%.15lf)\n", ref_valid_local?"valid":"invalid", xtal_correct_ok?"valid":"invalid", xtal_correct); // DEBUG
    }
    MSG("\nINFO: End of validation thread\n");
}

int http_request(char *host, int portno, char *message, int msglen, char *resp){
    /*
    int portno =        80;
    char *host =        "api.somesite.com";
    char *message_fmt = "POST /apikey=%s&command=%s HTTP/1.0\r\n\r\n";
    */

    struct hostent *server;
    struct sockaddr_in serv_addr;
    int sockfd, bytes, sent, received, total;
    //char message[2048];
    char response[4096];

    /* fill in the parameters */
    //sprintf(message,message_fmt,argv[1],argv[2]);
    //sprintf(message,message_fmt);
#if VERBOSE==1
    printf("Request:\n%s\n",message);
#endif
    /* create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        MSG("ERROR opening socket ");
        return 1;
    }

    /* lookup the ip address */
    server = gethostbyname(host);
    if (server == NULL){
        MSG("ERROR, no such host ");
        return 1;
    }

    /* fill in the structure */
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

    /* connect the socket */
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0){
        MSG("ERROR connecting");
        return 1;
    }

    /* send the request */
    total = msglen;
    sent = 0;
    do {
        bytes = write(sockfd,message+sent,total-sent);
        if (bytes < 0){
            MSG("ERROR writing message to socket");
            return 1;
        }
        if (bytes == 0){
            break;
        }
        sent+=bytes;
    } while (sent < total);

    /* receive the response */
    memset(response,0,sizeof(response));
    total = sizeof(response)-1;
    received = 0;
    do {
        bytes = read(sockfd,response+received,total-received);
        if (bytes < 0){
            MSG("ERROR reading response from socket");
            return 1;
        }
        if (bytes == 0){
            break;
        }
        received+=bytes;
    } while (received < total);

    if (received == total){
        MSG("ERROR storing complete response from socket");
    }

    /* close the socket */
    close(sockfd);

    /* process response */
    //MSG("%s\n", response);
    memcpy(resp, &response, sizeof(response));
    return 0;
}

void ttn_data_exchange(){ //update data from gateway to TTN and vice versa
    char message[2048];
    int resp;
    uint32_t ttncnt=0;
    char response[4096];
    char response_update[4096];
    JSON_Value *root_val;
    JSON_Object *mainjson;
    const char *str;
    uint8_t appkeyhere[16];
    char *to_ttn_string = NULL;
    if(1){
        if((ttnapiport > 0) && (sizeof ttnapiurl > 0)){
            for(int current=0; current < 20; current++){
              if(mydevice[current][0] != '\0'){
#if VERBOSE==1
                MSG("Sending http request to TTN for device #%u\n", current);
                MSG("Dev name: %s\n", mydevice[current]);
                MSG("API URL: %s\n", ttnapiurl);
#endif
                char *message_fmt = "GET /applications/%s/devices/%s HTTP/1.0\r\nAuthorization: Key %s\r\n\r\n";
                sprintf(message, message_fmt, myapplication, mydevice[current], myauthkey);
                resp = http_request(&ttnapiurl[0], ttnapiport, message, strlen(message), &response[0]);
                if(resp==0){
#if VERBOSE==1
                    MSG("DONE!\n");
                    MSG("%s\n", strstr(response, "{"));
#endif
                    root_val = json_parse_string_with_comments(strstr(response, "{"));
                    mainjson = json_value_get_object(root_val);
                    //data = json_object_get_object(mainjson, "lorawan_device");
                    ttncnt = (uint32_t)json_object_dotget_number(mainjson, "lorawan_device.f_cnt_down");
#if VERBOSE==1
                    MSG("TTN fcnt_down: %u\n", ttncnt);
#endif
                    if(ttncnt > myfcntdown[current]){
                        myfcntdown[current] = ttncnt;
                        MSG("Local framecounter set to TTN fcnt: %u\n", myfcntdown[current]);
                    }else if(ttncnt < myfcntdown[current]){
                        MSG("Updating TTN framecounter to local framecounter: %u.......", myfcntdown[current]);
                        json_object_dotset_number(mainjson, "lorawan_device.f_cnt_down", (double)myfcntdown[current]);
                        to_ttn_string = json_serialize_to_string(root_val);
                        //MSG("%s\n", to_ttn_string);
                        char *message_fmt = "POST /applications/%s/devices/%s HTTP/1.0\r\nAuthorization: Key %s\r\nContent-Type: text/plain\r\nContent-Length: %u\r\n\r\n%s";
                        sprintf(message, message_fmt, myapplication, mydevice[current], myauthkey, strlen(to_ttn_string), to_ttn_string);
                        resp = http_request(&ttnapiurl[0], ttnapiport, message, strlen(message), &response_update[0]);
                        if(resp==0){
                            MSG("DONE!\n");
#if VERBOSE==1
                            MSG("%s\n", strstr(response_update, "{"));
#endif
                        }else{
                            MSG("ERROR!\n");
                        }
                        json_free_serialized_string(to_ttn_string);
                    }else{
                        MSG("Framecounters are equal, everything is OK.\n");
                    }
                    //MSG("Updating keys from TTN if changed...\n");

                    str = json_object_dotget_string(mainjson, "lorawan_device.dev_addr");
                    if (str != NULL) {
                        sscanf(str, "%X", &mydevaddr[current]);
                        //MSG("###Devaddr ");
                    }

                   str = json_object_dotget_string(mainjson, "lorawan_device.app_s_key");
                   if (str != NULL) {
                       //MSG("###Appskey\n");
                       for (size_t count = 0; count < sizeof appkeyhere/sizeof *appkeyhere; count++) {
                           sscanf(str, "%2hhx", &myappskey[current][count]);
                           str += 2;
                       }
                   }

                   str = json_object_dotget_string(mainjson, "lorawan_device.app_key");
                   if (str != NULL) {
                       //MSG("###Appkey: ");
                       for (size_t count = 0; count < sizeof appkeyhere/sizeof *appkeyhere; count++) {
                           sscanf(str, "%2hhx", &myappkey[current][count]);
                           str += 2;
                       }
                       /*for(size_t count = 0; count < sizeof (myappkey[current])/sizeof *(myappkey[current]); count++){
                           printf("%02x", myappkey[current][count]);
                       }
                       printf("\n");*/
                   }

                   str = json_object_dotget_string(mainjson, "lorawan_device.nwk_s_key");
                   if (str != NULL) {
                       //MSG("###Nwkskey: %X\n", ull1);
                       for (size_t count = 0; count < sizeof appkeyhere/sizeof *appkeyhere; count++) {
                           sscanf(str, "%2hhx", &mynwkskey[current][count]);
                           str += 2;
                       }
                   }
                
                   str = json_object_dotget_string(mainjson, "lorawan_device.dev_eui");
                   if (str != NULL) {
                       sscanf(str, "%llx", &myuid[current]);
                       //MSG("###Uid: %016llX\n", myuid[current]);
                   }


                    json_value_free(root_val);
                }else{
                    MSG("ERROR!\n");
                }
              }
            }
        }
    }
}

void state_change_online(){ //when internet status changet from offline to online
    if(offline==0 && laststatus==1){
        MSG("\n\n\n\nGateway is now online\n");
        ttn_data_exchange();
        system("python /etc/lora/upload_all.py &");
        laststatus=0;
    }
}

void thread_netstatus(void) {
    int i = 0;
    struct addrinfo hints;
    struct addrinfo *result; /* store result of getaddrinfo */
    struct addrinfo *q; /* pointer to move into *result data */
    char host_name[64];
    char port_name[64];
    while (!exit_sig && !quit_sig) {
        wait_ms(1000);
        offline=1;
#if VERBOSE==1
        MSG("\nChecking connection\n");
        MSG("Previous state: %u\n", offline);
#endif
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; // WA: Forcing IPv4 as AF_UNSPEC makes connection on localhost to fail 
        hints.ai_socktype = SOCK_DGRAM;

            i = getaddrinfo(serv_addr, serv_port_up, &hints, &result);
            if (i != 0) {
#if VERBOSE==1
                MSG("ERROR: [up] getaddrinfo on address %s (PORT %s) returned %s\n", serv_addr, serv_port_up, gai_strerror(i));
                MSG("\nOffline mode enabled!\n");
#endif
                offline=1;
                laststatus=1;
            }else{
                offline=0;
             if(laststatus==1){
                /* try to open socket for upstream traffic */
                for (q=result; q!=NULL; q=q->ai_next) {
                    //MSG("\nFor -------------------------------------\n");
                    sock_up = socket(q->ai_family, q->ai_socktype,q->ai_protocol);
                    if (sock_up == -1) continue; /* try next field */
                    else break; /* success, get out of loop */
                }
                if (q == NULL) {
                    MSG("ERROR: [up] failed to open socket to any of server %s addresses (port %s)\n", serv_addr, serv_port_up);
                    i = 1;
                    for (q=result; q!=NULL; q=q->ai_next) {
                        getnameinfo(q->ai_addr, q->ai_addrlen, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
                        MSG("INFO: [up] result %i host:%s service:%s\n", i, host_name, port_name);
                        ++i;
                    }
#if VERBOSE==1
                    MSG("\nOffline mode enabled!\n");
#endif
                    offline=1;
                    laststatus=1;
                }else{
                   MSG("socket created!");
                }
                /* connect so we can send/receive packet with the server only */
                i = connect(sock_up, q->ai_addr, q->ai_addrlen);
                if (i != 0) {
                    MSG("ERROR: [up] connect returned %s\n", strerror(errno));
                    //exit(EXIT_FAILURE);
#if VERBOSE==1
                    MSG("\nOffline mode enabled!\n");
#endif
                    offline=1;
                    laststatus=1;
                }
                freeaddrinfo(result);



            i = setsockopt(sock_up, SOL_SOCKET, SO_RCVTIMEO, (void *)&push_timeout_half, sizeof push_timeout_half);
            if (i != 0) {
                MSG("ERROR: [up] setsockopt from netstatus thread returned %s\n", strerror(errno));
                offline=1;
                laststatus=1;
            }else{
                offline=0;
                state_change_online();
            }

                /* look for server address w/ downstream port */
                i = getaddrinfo(serv_addr, serv_port_down, &hints, &result);
                if (i != 0) {
                    MSG("ERROR: [down] getaddrinfo on address %s (port %s) returned %s\n", serv_addr, serv_port_up, gai_strerror(i));
                    offline=1;
                    laststatus=1;
                    break;
                }
                /* try to open socket for downstream traffic */
                for (q=result; q!=NULL; q=q->ai_next) {
                    sock_down = socket(q->ai_family, q->ai_socktype,q->ai_protocol);
                    if (sock_down == -1) continue; /* try next field */
                    else break; /* success, get out of loop */
                }
                if (q == NULL) {
                    MSG("ERROR: [down] failed to open socket to any of server %s addresses (port %s)\n", serv_addr, serv_port_up);
                    i = 1;
                    for (q=result; q!=NULL; q=q->ai_next) {
                        getnameinfo(q->ai_addr, q->ai_addrlen, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
                        MSG("INFO: [down] result %i host:%s service:%s\n", i, host_name, port_name);
                        ++i;
                    }
                    offline=1;
                    laststatus=1;
                }

                /* connect so we can send/receive packet with the server only */
                i = connect(sock_down, q->ai_addr, q->ai_addrlen);
                if (i != 0) {
                    MSG("ERROR: [down] connect returned %s\n", strerror(errno));
                    offline=1;
                    laststatus=1;
                }
                i = setsockopt(sock_down, SOL_SOCKET, SO_RCVTIMEO, (void *)&pull_timeout, sizeof pull_timeout);
                if (i != 0) {
                    //MSG("ERROR: [down] setsockopt returned %s\n", strerror(errno));
                    offline=1;
                    //continue;
                }else{
                    offline=0;
                    //state_change_online();
                }
                freeaddrinfo(result);
                state_change_online();
             }
           }
                
    }
}

void get_binary(unsigned char c, unsigned char bin[])
{
 unsigned char i1 = (1 << (sizeof(c)*8-1)), i2=0;
 for(; i1; i1>>=1, i2++)
      bin[i2] = ((c&i1)!=0);
}

static int char_to_bin(char ch, int pos){
	int bin;
 	bin = ((ch << pos) & 0x80) ? 1 : 0;
	return bin;

}

uint64_t Uint8ArrtoUint64 (uint8_t* var, uint32_t lowest_pos)
{
    return  (((uint64_t)var[lowest_pos+7]) << 56) | 
            (((uint64_t)var[lowest_pos+6]) << 48) |
            (((uint64_t)var[lowest_pos+5]) << 40) | 
            (((uint64_t)var[lowest_pos+4]) << 32) |
            (((uint64_t)var[lowest_pos+3]) << 24) | 
            (((uint64_t)var[lowest_pos+2]) << 16) |
            (((uint64_t)var[lowest_pos+1]) << 8)  | 
            (((uint64_t)var[lowest_pos])   << 0);
}

void tohex(unsigned char * in, size_t insz, char * out, size_t outsz)
{
    unsigned char * pin = in;
    const char * hex = "0123456789ABCDEF";
    char * pout = out;
    for(; pin < in+insz; pout +=3, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
        pout[2] = ':';
        if ((size_t)(pout + 3 - out) > outsz){
            /* Better to truncate output string than overflow buffer */
            /* it would be still better to either return a status */
            /* or ensure the target buffer is large enough and it never happen */
            break;
        }
    }
    pout[-1] = 0;
}

void process_payload(uint8_t * p, uint16_t size, int poradi) {
    MSG("\n\n\n\n\n\n");
    MSG("\n--------Start payload data parsing function--------\n");
    MSG("Payload size: %u \n", size);
    MSG("Payload data: \n");
    for(int i = 0; i < size; i++){
        MSG("%02X ", *(p+i));
    }
    MSG("\nDecoder for this device is: %s\n", mydecoder[poradi]);
    char converted[size*2 + 1];
    char torun[(size*2 + 1)+64];
    for(int i=0;i<size;i++) {
      sprintf(&converted[i*2], "%02X", *(p+i));
    }
    sprintf(&torun[0], "%s %s &", mydecoder[poradi], converted);
 
    MSG("Starting: %s", torun);
    system(torun);
    MSG("\n-------------------------------------------------\n");
}

void localpkt_up(struct lgw_pkt_rx_s * p) {
    struct timeval current_unix_time;
    struct timeval current_concentrator_time;
    enum jit_error_e jit_result;
    enum jit_pkt_type_e downlink_type;
    int j = 0;
    struct lgw_pkt_tx_s txpkt;
#if VERBOSE==1
    MSG("Internet status: %u\n", offline);
    MSG("--------Localpkt: [up] received packet: status %u (size %u, modulation %u, BW %u, DR %u, RSSI %.1f)\n", p->status, p->size, p->modulation, p->bandwidth, p->datarate, p->rssi);
    MSG("Payload in HEX:\n");
    for (j = 0; j < p->size; ++j) {
         MSG(" %02X", p->payload[j]);
    }
    MSG("\nPayload in BIN:\n");
    for (j = 0; j < p->size; ++j) {
         uint8_t x = p->payload[j];
         int n;
         for(n=0; n<8; n++){
             if((x & 0x80) !=0){
                 printf("1");
             }else{
                 printf("0");
             }
             x = x<<1;
         }
    }
    MSG(" #\n");
    MSG("---------------------------------------\n");
#endif
    uint8_t x = p->payload[0];
    uint8_t appkey[16];
    uint32_t devaddr=0;
    uint64_t eui64 = 123456789;
    int poradi = 0;
    uint8_t tmppayload[33];
    uint8_t tmppayloadout[33];
    int fportlen;
    uint32_t time_us;
#if VERBOSE==1
    printf("MHDR: %d%d%d", char_to_bin(x, 0), char_to_bin(x, 1), char_to_bin(x, 2)); //print MHDR
#endif
    gettimeofday(&current_unix_time, NULL);
    if(char_to_bin(x, 0)==0 && char_to_bin(x, 1)==0 && char_to_bin(x, 2)==0){ //000 => join request
#if VERBOSE==1
        MSG(" => Join-request\n");
#endif
        uint8_t joinEui[8];
#if VERBOSE==1
        MSG("## Join_EUI: \n");
#endif
        for(int i = 1; i <= 8; i++){
            joinEui[i-1] = p->payload[i];
#if VERBOSE==1
            MSG(" %02X", p->payload[i]);
#endif
        }
        uint8_t devEui[8];
#if VERBOSE==1
        MSG("\n## Dev_EUI: \n");
#endif
        for(int i = 9; i <= 16; i++){
            devEui[i-9] = p->payload[i];
#if VERBOSE==1
            MSG(" %02X",  p->payload[i]);
#endif
        }
        
        eui64 = Uint8ArrtoUint64 (devEui, 0);
#if VERBOSE==1
        printf("\n##64bit eui: %llu\n", eui64);
#endif

        uint8_t devNonce[2];
#if VERBOSE==1
        MSG("\n## Dev_Nonce: \n");
#endif
        for(int i = 17; i <= 18; i++){
            devNonce[i-17] = p->payload[i];
#if VERBOSE==1
            MSG(" %02X", p->payload[i]);
#endif
        }

        //MSG("\n## mydevices array size:%u list: \n", (sizeof(myuid)/8));
        for (unsigned int i = 0; i < (sizeof(myuid)/8); i++) { //check if device is in list of our devices
            //printf("##Trying: %llu vs. %llu\n", myuid[i], eui64);
            if(myuid[i]==eui64){
                for(int k = 0; k < 16; k++) {
                    appkey[k] = myappkey[i][k];
                }
                devaddr = mydevaddr[i];
                myjoineui[i] = Uint8ArrtoUint64(joinEui, 0);
                mynonce[i] = Uint8ArrtoUint64(devNonce, 0);
                poradi = i;
                break;
            }
        }
        if((myuid[poradi]==eui64) && (myabp[poradi]==0)){ //it's our device
#if VERBOSE==1
            printf("\nDevice found in list, summary of information:\nDevice EUI: %02llX\nApp EUI (Join EUI): %02llX\nDevice Nonce: %02llX\nDevAddr: %02X\nAppKey:\n", eui64, myjoineui[poradi], mynonce[poradi], devaddr );
            for(int i = 0; i < 16; i++){
                MSG(" %02X", appkey[i]);
            }
            MSG("\n");
#endif
            uint8_t tmppayloadpart[29];
            joinnonce++;
            if(joinnonce==16777215){ //reset (maximum je 0xFFFFFF - join-nonce je dlouhý tři bajty)
                joinnonce = 1;
            }
            srand(time(NULL));
            devaddr = (uint32_t)rand();
            mydevaddr[poradi] = devaddr;
            // sestavení join-accept
            tmppayload[0]=0x20;
            tmppayload[1]=(joinnonce >> 0)  & 0xFF; //Join-Nonce random byte
            tmppayload[2]=(joinnonce >> 8)  & 0xFF; //Join-Nonce random byte
            tmppayload[3]=(joinnonce >> 16)  & 0xFF; //Join-Nonce random byte
            tmppayload[4]=0x11; //Net-ID 
            tmppayload[5]=0x12; //Net-ID 
            tmppayload[6]=0x13; //Net-ID 
            tmppayload[7]=(devaddr >> 0)  & 0xFF; //Dev_addr
            tmppayload[8]=(devaddr >> 8)  & 0xFF; //Dev_addr
            tmppayload[9]=(devaddr >> 16)  & 0xFF; //Dev_addr
            tmppayload[10]=(devaddr >> 24)  & 0xFF; //Dev_addr
            tmppayload[11]=0x03; //DL-settings
            tmppayload[12]=0x01; //Rx delay = 1 second
            tmppayload[13]=0x18; //CF-list (start) 18 4f 84 e8 56 84 b8 5e 84 88 66 84 58 6e 84 00 (8671000, 8673000, 8675000, 8677000, 8679000; RFU 00)
            tmppayload[14]=0x4F; //CF-list
            tmppayload[15]=0x84; //CF-list
            tmppayload[16]=0xE8; //CF-list
            tmppayload[17]=0x56; //CF-list
            tmppayload[18]=0x84; //CF-list
            tmppayload[19]=0xB8; //CF-list
            tmppayload[20]=0x5E; //CF-list
            tmppayload[21]=0x84; //CF-list
            tmppayload[22]=0x88; //CF-list
            tmppayload[23]=0x66; //CF-list
            tmppayload[24]=0x84; //CF-list
            tmppayload[25]=0x58; //CF-list
            tmppayload[26]=0x6E; //CF-list
            tmppayload[27]=0x84; //CF-list
            tmppayload[28]=0x00; //CF-list (end)

            for(int i = 0; i < 29; i++){
                tmppayloadpart[i] = tmppayload[i];
            }
            const uint8_t *tmppayloadptr = tmppayloadpart;
            uint8_t *tmppayloadoutptr = tmppayloadout;

            lw_key_t lwkey;
            uint8_t *keyptr = appkey;
            lwkey.aeskey = keyptr;
            lwkey.in = tmppayloadptr; //start from MHDR
            lwkey.len = 29; //frame without MIC, it will be generated in the next step
            lwkey.devaddr.data = devaddr;
            lwkey.link = LW_DOWNLINK;
            lwkey.fcnt32 = (uint32_t)0;

            lw_mic_t lwmic;
            lw_join_mic(&lwmic, &lwkey); //Generate MIC for frame
            tmppayload[29]=lwmic.buf[0]; //Set MIC before encryption
            tmppayload[30]=lwmic.buf[1];
            tmppayload[31]=lwmic.buf[2];
            tmppayload[32]=lwmic.buf[3];
#if VERBOSE==1
            MSG("\n MIC: %02X %02X %02X %02X", tmppayload[29], tmppayload[30], tmppayload[31], tmppayload[32]);
#endif
            tmppayloadptr = tmppayload; //pointer na rámec
            tmppayloadptr++; //start with payload (exclude MHDR)
            lwkey.len = 32; //include last 4 bytes of MIC, do not encrypt MHDR
            lwkey.in = tmppayloadptr; //set input to new pointer
#if VERBOSE==1
            MSG("\nPayload before encryption:\n");
                for (j = 0; j < 33; ++j) {
                    MSG(" %02X", tmppayload[j]);
                }
#endif
            lw_join_encrypt(tmppayloadoutptr, &lwkey); //encrypt frame

            uint8_t joinaccept[33];
            for (int i = 0 ; i < 32 ; i++){ //shift data and prepend MHDR (0x20)
                joinaccept[i+1] = tmppayloadout[i];
            }
            joinaccept[0] = 0x20;
#if VERBOSE==1
            MSG("Encrypted payload:\n");
            for (j = 0; j < 33; ++j) {
                MSG(" %02X", joinaccept[j]);
            }
#endif
            uint8_t *nwkskeyptr = mynwkskey[poradi];
            uint8_t *appskeyptr = myappskey[poradi];
            
            lw_get_skeys_from_arrays(nwkskeyptr, appskeyptr, &tmppayload[1], &tmppayload[4], &devNonce[0], keyptr); //generate session keys

            //setup data tramsmission
            txpkt.freq_hz = (uint32_t)((double)(1.0e6) * 869.525);
            txpkt.tx_mode = TIMESTAMPED;
            txpkt.rf_chain = (uint8_t)0;
            txpkt.modulation = MOD_LORA;
            txpkt.bandwidth = BW_125KHZ;
            txpkt.datarate = DR_LORA_SF12;
            txpkt.coderate = CR_LORA_4_5;
            txpkt.invert_pol = 1;
            txpkt.f_dev = (uint8_t)(869525000 / 1000.0);
            txpkt.preamble = (uint16_t)STD_LORA_PREAMB;
            txpkt.no_crc = 1;
            txpkt.rf_power = (int8_t)27;
            txpkt.size = (uint16_t)33;

            for(int i = 0; i <= (txpkt.size-1); i++){
                txpkt.payload[i] = joinaccept[i];
            }  
            mylastfcntup[poradi] = -1; //reset last fcnt on join
            downlink_type = JIT_PKT_TYPE_DOWNLINK_CLASS_A;
            gettimeofday(&current_unix_time, NULL);
            get_concentrator_time(&current_concentrator_time, current_unix_time);
            struct timeval *time = &current_concentrator_time;
            time_us = (time->tv_sec * 1000000UL + time->tv_usec) + 6000000; //between join-request and join-accept must be 10 seconds delay
            txpkt.count_us = time_us;
            //MSG("tmst: %ul\n", txpkt.count_us);
            jit_result = jit_enqueue(&jit_queue, &current_concentrator_time, &txpkt, downlink_type);
            if (jit_result != JIT_ERROR_OK) {
#if VERBOSE==1
                printf("ERROR: Packet REJECTED (jit error=%d)\n", jit_result);
#endif
            }

        }else{ //it is not our device
#if VERBOSE==1
            MSG("\nDevice is not in list, ignoring.\n");
#endif
        }
#if VERBOSE==1
        MSG("\n");
#endif
    }else if((((char_to_bin(x, 0)==0 && char_to_bin(x, 1)==1 && char_to_bin(x, 2)==0) || (char_to_bin(x, 0)==1 && char_to_bin(x, 1)==0 && char_to_bin(x, 2)==0)))  && (last_unix_time.tv_sec+1 <= current_unix_time.tv_sec)){ //010 => unconfirmed uplink, 100 => confirmed uplink
        gettimeofday(&last_unix_time, NULL);
#if VERBOSE==1
        MSG(" => uplink\n");
#endif
        int poradi = 0;
        uint8_t devaddrbytes[4]; //payload size = packet size - MHDR and MIC
#if VERBOSE==1
        MSG("## DevAddr: \n");
#endif
        for(int i = 1; i <= 4; i++){
            devaddrbytes[i-1] = p->payload[i];
#if VERBOSE==1
            MSG(" %02X", p->payload[i]);
#endif
        }
        uint32_t devaddrnow = devaddrbytes[0] | (devaddrbytes[1] << 8) | (devaddrbytes[2] << 16) | (devaddrbytes[3] << 24);

        uint8_t payloadbytes[p->size-9]; //payload size = packet size - MHDR and MIC
#if VERBOSE==1
        MSG("\n## MAC Payload: \n");
#endif
        for(int i = 5; i <= (p->size-5); i++){
            payloadbytes[i-5] = p->payload[i];
#if VERBOSE==1
            MSG(" %02X", p->payload[i]);
#endif
        }

        uint8_t micbytes[4];
#if VERBOSE==1
        MSG("\n## MIC: \n");
#endif
        for(int i = (p->size-4); i <= (p->size-1); i++){
            micbytes[i-(p->size-4)] = p->payload[i];
#if VERBOSE==1
            MSG(" %02X", p->payload[i]);
#endif
        }
        uint32_t micnow = micbytes[0] | (micbytes[1] << 8) | (micbytes[2] << 16) | (micbytes[3] << 24);

        for (unsigned int i = 0; i < (sizeof(myuid)/8); i++) { //check if device is in list of our devices
            //printf("##Trying: %llu vs. %llu\n", myuid[i], eui64);
            if(mydevaddr[i]==devaddrnow){
                poradi = i+1;
                break;
            }
        }

        if(poradi>0 && mynwkskey[poradi-1][0]>0){
            poradi = poradi-1;
#if VERBOSE==1
            MSG("\n## Device found in list, AppKey is: \n");
            for(int i = 0; i < 16; i++){
                MSG(" %02X", myappkey[poradi][i]);
            }
            MSG("\n## NwkSKey is: \n");
            for(int i = 0; i < 16; i++){
                MSG(" %02X", mynwkskey[poradi][i]);
            }
            MSG("\n## AppSKey is: \n");
            for(int i = 0; i < 16; i++){
                MSG(" %02X", myappskey[poradi][i]);
            }
#endif
            int foptslen = payloadbytes[0] & 0x7;//(payloadbytes[0] >> 5) & ((payloadbytes[0] << 3)-1);
#if VERBOSE==1
            MSG("\nFOptsLen: %u", foptslen);
            MSG("\n## Payload: \n");
#endif
            if(foptslen==0){
                fportlen = 1; //Fport is present only if there are no Fopts
            }else{
                fportlen = 1;
            }
            uint8_t fport = payloadbytes[foptslen+8];
            uint16_t payloadsize = p->size-12-foptslen-fportlen;
            uint8_t payload[payloadsize]; //payload size = packet size - MHDR and MIC
            for(int i = (3 + foptslen+fportlen); i <= (p->size-9-fportlen); i++){
                payload[i-3-foptslen-fportlen] = payloadbytes[i];
#if VERBOSE==1
                MSG(" %02X", payloadbytes[i]);
#endif
            }
            if(payloadsize>0){ //if payload contains data
#if VERBOSE==1
                MSG("\nPayload contains data\n");
                MSG("\nFPort: %u", fport);
                MSG("\nSelected key: ");
#endif
                /*
                if(fport==0){
                    skeyptr = mynwkskey[poradi];
                    MSG("NwkSKey\n");
                }else{
                    skeyptr = myappskey[poradi];
                    MSG("AppSKey\n");
                }
                */
#if VERBOSE==1
                MSG("\nPayload size in bytes: %u\n", payloadsize);
#endif
                lw_key_t lwkey1;
                lwkey1.aeskey = &myappskey[poradi][0];
                lwkey1.in = &payload[0];
                lwkey1.len = payloadsize;
                lwkey1.link = LW_UPLINK;
                lwkey1.devaddr.buf[0] = devaddrbytes[0];
                lwkey1.devaddr.buf[1] = devaddrbytes[1];
                lwkey1.devaddr.buf[2] = devaddrbytes[2];
                lwkey1.devaddr.buf[3] = devaddrbytes[3];
#if VERBOSE==1
                MSG("ADDR: %02X %02X %02X %02X\n", lwkey1.devaddr.buf[0], lwkey1.devaddr.buf[1], lwkey1.devaddr.buf[2], lwkey1.devaddr.buf[3]);
                MSG("Fcnt HEX: %02X %02X\n", p->payload[6], p->payload[7]);
#endif
                lwkey1.fcnt32 = (uint32_t)(p->payload[6] | (p->payload[7] << 8)); //payloadbytes[6], payloadbytes[7]
#if VERBOSE==1
                MSG("Fcnt: %u\n", lwkey1.fcnt32);
#endif
                uint8_t payloaddecrypted[payloadsize];
                if (lw_encrypt(&payloaddecrypted[0], &lwkey1) <= 0) {
                    MSG("\nDecryption error!\n");
                }else{
#if VERBOSE==1
                    MSG("\nPayload decrypted, data: \n");
                    for(int i = 0; i < payloadsize; i++){
                        MSG(" %02X", payloaddecrypted[i]);
                    }
#endif
                    lwkey1.aeskey = &mynwkskey[poradi][0];
                    lwkey1.in = p->payload;
                    lwkey1.len = (p->size)-4;
                    lw_mic_t mic1;
                    lw_msg_mic(&mic1, &lwkey1);
#if VERBOSE==1
                    MSG("\nMIC1: %02X %02X %02X %02X vs. MIC2: %02X %02X %02X %02X\n", mic1.buf[0], mic1.buf[1], mic1.buf[2], mic1.buf[3], micbytes[0], micbytes[1], micbytes[2], micbytes[3]);
#endif
                    if(mic1.data==micnow){
#if VERBOSE==1
                        MSG("\nMIC is OK\n");
#endif
                        if(char_to_bin(x, 0)==1 && char_to_bin(x, 1)==0 && char_to_bin(x, 2)==0){ //if confirmed uplink + duplicate correction
                          if(offline==1){
#if VERBOSE==1
                            MSG("Confirmed uplink\n");
#endif
                            uint8_t tmpconfirm[12];
                            tmpconfirm[0] = 0x60; //011 -> unconfirmed downlink
                            tmpconfirm[1] = devaddrbytes[0]; //devaddr
                            tmpconfirm[2] = devaddrbytes[1]; //devaddr
                            tmpconfirm[3] = devaddrbytes[2]; //devaddr
                            tmpconfirm[4] = devaddrbytes[3]; //devaddr
                            tmpconfirm[5] = 0x20; //Fctrl 00100000 (ACK bit must be set to 1)
                            tmpconfirm[6] = (myfcntdown[poradi] >> (8*0)) & 0xff; //Fcntdown (gateway side) must be device specific bit 3/4 of uint32
                            tmpconfirm[7] = (myfcntdown[poradi] >> (8*1)) & 0xff; //Fcntdown (gateway side) must be device specific bit 4/4 of uint32
                            lwkey1.in = &tmpconfirm[0];
                            lwkey1.len = 8;
                            lwkey1.link = LW_DOWNLINK;
                            lwkey1.fcnt32 = myfcntdown[poradi];
                            lw_msg_mic(&mic1, &lwkey1);
                            tmpconfirm[8] = mic1.buf[0]; //MIC
                            tmpconfirm[9] = mic1.buf[1]; //MIC
                            tmpconfirm[10] = mic1.buf[2]; //MIC
                            tmpconfirm[11] = mic1.buf[3]; //MIC
#if VERBOSE==1
                            MSG("\n## Data to send: \n");
                            for(int i = 0; i < 12; i++){
                                MSG(" %02X", tmpconfirm[i]);
                            }
#endif
                            txpkt.freq_hz = (uint32_t)((double)p->freq_hz); //same frequency as in previous uplink
                            txpkt.tx_mode = TIMESTAMPED;
                            txpkt.rf_chain = (uint8_t)0;
                            txpkt.modulation = MOD_LORA;
                            txpkt.bandwidth = BW_125KHZ;
                            txpkt.datarate = DR_LORA_SF12;
                            txpkt.coderate = CR_LORA_4_5;
                            txpkt.invert_pol = 1;
                            txpkt.f_dev = (uint8_t)(869525000 / 1000.0);
                            txpkt.preamble = (uint16_t)STD_LORA_PREAMB;
                            txpkt.no_crc = 1;
                            txpkt.rf_power = (int8_t)27;
                            txpkt.size = (uint16_t)12;

                            for(int i = 0; i <= (txpkt.size-1); i++){
                                txpkt.payload[i] = tmpconfirm[i];
                            }  

                            downlink_type = JIT_PKT_TYPE_DOWNLINK_CLASS_A;
                            gettimeofday(&current_unix_time, NULL);
                            get_concentrator_time(&current_concentrator_time, current_unix_time);
                            struct timeval *time = &current_concentrator_time;
                            time_us = (time->tv_sec * 1000000UL + time->tv_usec)+ 1000000; //RX_DELAY1 = 1 second
                            txpkt.count_us = time_us;
                            jit_result = jit_enqueue(&jit_queue, &current_concentrator_time, &txpkt, downlink_type);
                            if (jit_result != JIT_ERROR_OK) {
                                printf("ERROR: Packet REJECTED (jit error=%d)\n", jit_result);
                            }
                          }
                          myfcntdown[poradi]++;
                          MSG("##########################Fcnt Down value: %u\n", myfcntdown[poradi]);
                          if(myfcntdown[poradi]==4294967295){
                              myfcntdown[poradi]=0; //but the device will stop working
                          }
                          
                        }
                        if(mylastfcntup[poradi] != ((uint32_t)(p->payload[6] | (p->payload[7] << 8)))){ //ignore packet if repeated
                            process_payload(&payloaddecrypted[0], payloadsize, poradi);
                            mylastfcntup[poradi] = (uint32_t)(p->payload[6] | (p->payload[7] << 8));
                        }
                    }
                    

                }
                
            }else{
#if VERBOSE==1
                MSG("\nPayload contains only MAC commands, ignoring\n");
#endif
            }
            
        }
    }
    MSG("\n--------------------------------------------------\n");
}
/* --- EOF ------------------------------------------------------------------ */
