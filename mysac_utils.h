#ifndef __MYSAC_UTILS_H__
#define __MYSAC_UTILS_H__

#include <stdint.h>

/*
static inline float from_my_float_32(char *m) {
	uint32_t i;
	i  = (unsigned char)m[3]; i <<= 8;
	i |= (unsigned char)m[2]; i <<= 8;
	i |= (unsigned char)m[1]; i <<= 8;
	i |= (unsigned char)m[0];
	return *(float *)&i;
}
static inline double from_my_float_64(char *m) {
	uint64_t i;
	i  = (unsigned char)m[7]; i <<= 8;
	i |= (unsigned char)m[6]; i <<= 8;
	i |= (unsigned char)m[5]; i <<= 8;
	i |= (unsigned char)m[4]; i <<= 8;
	i |= (unsigned char)m[3]; i <<= 8;
	i |= (unsigned char)m[2]; i <<= 8;
	i |= (unsigned char)m[1]; i <<= 8;
	i |= (unsigned char)m[0];
	return *(double *)&i;
}
*/
static inline void to_my_2(int value, char *m) {
	m[1] = value >> 8;
	m[0] = value;
}
static inline void to_my_3(int value, char *m) {
	m[2] = value >> 16;
	m[1] = value >> 8;
	m[0] = value;
}
static inline void to_my_4(int value, char *m) {
	m[3] = value >> 24;
	m[2] = value >> 16;
	m[1] = value >> 8;
	m[0] = value;
}

/* length coded binary
  0-250        0           = value of first byte
  251          0           column value = NULL
	                        only appropriate in a Row Data Packet
  252          2           = value of following 16-bit word
  253          3           = value of following 24-bit word
  254          8           = value of following 64-bit word
*/
static inline int my_lcb(char *m, unsigned long *r,  char *nul) {
	switch ((unsigned char)m[0]) {
	case 251: *r = 0;                   *nul=1; return 1;
	case 252: *r = uint2korr(&m[1]);    *nul=0; return 3;
	case 253: *r = uint4korr(&m[1]);    *nul=0; return 5;
	case 254: *r = uint8korr(&m[1]);    *nul=0; return 9;
	default:  *r = (unsigned char)m[0]; *nul=0; return 1;
	}
}

static inline void strncpyz(char *d, char *s, int l) {
	memcpy(d, s, l);
	d[l] = '\0';
}

#endif
