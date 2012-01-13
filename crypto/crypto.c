#include <unistd.h>
#include <fcntl.h>

#include "crypto.h"

#ifdef LTC_DES

static int urandom_fd;

static const unsigned char odd_parity[256] = {
		1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
	 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	 97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
	112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
	128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
	145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
	161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
	176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
	193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
	208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
	224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
	241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
};

void DES_set_odd_parity(DES_cblock *key)
{
	unsigned int i;

	for (i = 0; i < sizeof(DES_cblock); i++)
		(*key)[i] =  odd_parity[(*key)[i]];
}

int DES_check_key_parity(const_DES_cblock *key)
{
	unsigned int i;

	for (i = 0; i < sizeof(DES_cblock); i++) {
		if ((*key)[i] != odd_parity[(*key)[i]])
			return 0;
	}

	return 1;
}

static const DES_cblock weak_keys[] = {
	/* weak keys */
	{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
	{0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
	{0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E},
	{0xE0,0xE0,0xE0,0xE0,0xF1,0xF1,0xF1,0xF1},
	/* semi-weak keys */
	{0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
	{0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},
	{0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
	{0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},
	{0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
	{0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},
	{0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
	{0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},
	{0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
	{0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},
	{0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
	{0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1}
};

int DES_is_weak_key(const_DES_cblock *key)
{
	int i;

	for (i = 0; i < sizeof(weak_keys); i++)
		if (!memcmp(weak_keys[i], key, sizeof(DES_cblock)))
			return 1;

	return 0;
}

int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule)
{
	if (!DES_check_key_parity(key))
		return -1;

	if (DES_is_weak_key(key))
		return -2;

	return des_setup((const unsigned char *)key, 8, 0, schedule);
}

int DES_random_key(DES_cblock *ret)
{
	while (1) {
		read(urandom_fd, ret, sizeof(DES_cblock));
		if (DES_is_weak_key(ret))
			continue;
		break;
	}

	DES_set_odd_parity(ret);

	return 0;
}

void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc)
{
	if (enc == DES_ENCRYPT)
		des_ecb_encrypt((const unsigned char *) input, (unsigned char *) output, ks);
	else
	if (enc == DES_DECRYPT)
		des_ecb_decrypt((const unsigned char *) input, (unsigned char *) output, ks);
	des_done(ks);
}

static void __attribute__((constructor)) init(void)
{
	urandom_fd = open("/dev/urandom", O_RDONLY);
	fcntl(urandom_fd, F_SETFD, fcntl(urandom_fd, F_GETFD) | FD_CLOEXEC);
}
#endif
