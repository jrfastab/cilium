/*
 *  Copyright (C) 2017 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __LIB_HASH_H_
#define __LIB_HASH_H_

#include <stdbool.h>

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

struct __una_u32 { __u32 x; } __packed;

static inline __u32 __get_unaligned_cpu32(const void *p)
{
	const struct __una_u32 *ptr = (const struct __una_u32 *)p;
	return ptr->x;
}

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((__u32)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline __u32  __attribute__((always_inline)) jhash(const void *key, __u32 length, __u32 initval)
{
	__u32 a, b, c;
	const __u8 *k = key;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += __get_unaligned_cpu32(k);
		b += __get_unaligned_cpu32(k + 4);
		c += __get_unaligned_cpu32(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}
	/* Last block: affect all 32 bits of (c) */
	/* All the case statements fall through */
	switch (length) {
	case 12: c += (__u32)k[11]<<24;
	case 11: c += (__u32)k[10]<<16;
	case 10: c += (__u32)k[9]<<8;
	case 9:  c += k[8];
	case 8:  b += (__u32)k[7]<<24;
	case 7:  b += (__u32)k[6]<<16;
	case 6:  b += (__u32)k[5]<<8;
	case 5:  b += k[4];
	case 4:  a += (__u32)k[3]<<24;
	case 3:  a += (__u32)k[2]<<16;
	case 2:  a += (__u32)k[1]<<8;
	case 1:  a += k[0];
		 __jhash_final(a, b, c);
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

/* jhash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline __u32  __attribute__((always_inline)) jhash2(const __u32 *k, __u32 length, __u32 initval)
{
	__u32 a, b, c;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + (length<<2) + initval;

	/* Handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		__jhash_mix(a, b, c);
		length -= 3;
		k += 3;
	}

	/* Handle the last 3 u32's: all the case statements fall through */
	switch (length) {
	case 3: c += k[2];
	case 2: b += k[1];
	case 1: a += k[0];
		__jhash_final(a, b, c);
	case 0:	/* Nothing left to add */
		break;
	}

	return c;
}

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static inline unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

static inline __u32 csum_partial(const void *buff, int len, __u32 wsum)
{
	unsigned int sum = (unsigned int)wsum;
	unsigned int result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return (__u32)result;
}

static inline __u16 csum_fold(__u32 csum)
{
	__u32 sum = (__u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}

static inline __u32 csum_add(__u32 res, __u32 addend)
{
	res += addend;
	return (res + (res < addend));
}

static inline __u32 csum_sub(__u32 csum, __u32 addend)
{
	return csum_add(csum, ~addend);
}

static inline __u32 csum_unfold(__u16 n)
{
	return (__u32)n;
}

static inline void csum_replace4(__u16 *sum, __be32 from, __be32 to)
{
	__u32 tmp = csum_sub(~csum_unfold(*sum), (__u32)from);

	*sum = csum_fold(csum_add(tmp, (__u32)to));
}

static inline void inet_proto_csum_replace4(__sum16 *sum, struct xdp_md *xdp,
					    __be32 from, __be32 to,
					    int pseudohdr)
{
	//csum_replace4(sum, from, to);
}

static inline void inet_proto_csum_replace2(__u16 *sum, struct xdp_md *xdp,
					    __be16 from, __be16 to,
					    bool pseudohdr)
{
	//inet_proto_csum_replace4(sum, xdp, (__be32)from, (__be32)to, pseudohdr);
}

static inline int inet_proto_csum_replace_by_diff(__u16 *sum,
						   struct xdp_md *xdp,
						   __u16 csum,
						   __u32 diff,
						   bool pseudohdr)
{
	void *data = (void *)(long) xdp->data;
	void *end = (void *)(long) xdp->data_end;
	__u32 unfold;

	if (csum > 0x7fff || csum & 1)
		return -1;

	if (data + csum > end)
		return -1;

	//csum = csum_add(diff, csum);
	//csum_fold(csum);
	//if (csum < 0xffff)
	//	*sum = (csum & 0xffff);
	//memcpy(sum, &csum, sizeof(csum));
	//*sum = csum_fold(csum_add(diff, unfold));
	csum = csum_fold(csum_add(diff, (__u32)csum));
	//*sum = csum;
	return csum;
}

#define MAX_BPF_STACK 512 // kernel parameter

static inline __be32 xdp_csum_diff(__be32 *from, __u32 from_size,
				   __be32 *to, __u32 to_size, __u32 seed)
{
	__be32 diff[MAX_BPF_STACK / sizeof(__be32)] = {};
	__u32 diff_size = from_size + to_size;
	int i, j = 0;

	/* This is quite flexible, some examples:
	 *
	 * from_size == 0, to_size > 0,  seed := csum --> pushing data
	 * from_size > 0,  to_size == 0, seed := csum --> pulling data
	 * from_size > 0,  to_size > 0,  seed := 0    --> diffing data
	 *
	 * Even for diffing, from_size and to_size don't need to be equal.
	 */
	if (unlikely(((from_size | to_size) & (sizeof(__be32) - 1)) ||
		     diff_size > sizeof(diff)))
		return DROP_INVALID;

	for (i = 0; i < from_size / sizeof(__be32); i++, j++)
		diff[j] = ~from[i];
	for (i = 0; i <   to_size / sizeof(__be32); i++, j++)
		diff[j] = to[i];

	return csum_partial(diff, diff_size, seed);
	return 0;
}

#define CSUM_MANGLED_0 ((__u16)0xffff)

static inline int xdp_l4_csum_replace(struct xdp_md *xdp, __u16 offset,
				      __u64 from, __u64 to, __u64 flags)
{
#if 0
	bool is_pseudo = flags & BPF_F_PSEUDO_HDR;
	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
	bool do_mforce = flags & BPF_F_MARK_ENFORCE;
#endif
	void *data = (void *)(long) xdp->data;
	void *end = (void *)(long) xdp->data_end;
	__u16 *ptr;
	__u16 csum;

#if 0
	if (flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_MARK_ENFORCE |
		      BPF_F_PSEUDO_HDR | BPF_F_HDR_FIELD_MASK))
		return DROP_INVALID;

	if (offset > 0xffff || offset & 1)
		return DROP_INVALID;

	if (data + offset + sizeof(*ptr) > end)
		return DROP_INVALID;
#endif
	if (data + sizeof(*ptr) > end)
		return DROP_INVALID;

	ptr = data;// + offset;
	csum = 1;
	*ptr = csum;
	//*(__u16 *) data = 1;//csum;
	//csum = 1;//to;

#if 0
	if (is_mmzero && !do_mforce && !*ptr)
		return DROP_INVALID;

	//csum = csum_add(to, csum);
	//to += csum;
	//csum = (to + (to < csum));
	csum = inet_proto_csum_replace_by_diff(ptr, xdp, csum, to, is_pseudo);
#endif

#if 0
	switch (flags & BPF_F_HDR_FIELD_MASK) {
	case 0:
		if (from != 0)
			return DROP_INVALID;

		csum = *ptr;

		if (data + offset + sizeof(*ptr) > end)
			return DROP_INVALID;

		ptr = (__u16 *)(data + offset);

		*ptr = csum;

		break;
	case 2:
		inet_proto_csum_replace2(ptr, xdp, from, to, is_pseudo);
		break;
	case 4:
		inet_proto_csum_replace4(ptr, xdp, from, to, is_pseudo);
		break;
	default:
		return DROP_INVALID;
	}

	if (is_mmzero && !*ptr)
		*ptr = CSUM_MANGLED_0;
#endif

	return 0;
}

static inline int xdp_l3_csum_replace(struct xdp_md *xdp, __u32 offset,
				      __u64 from, __u64 to, __u64 flags)
{
	return 0;
}
#endif
