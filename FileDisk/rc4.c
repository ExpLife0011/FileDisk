#include "rc4.h"

#define DEENCRYPT_LENGTH               ( 512 )

void rc4_setup(struct rc4_state *s, unsigned char *key, int length)
{
	int  i, j, k;
	unsigned char  *m, a;

	s->x = 0;
	s->y = 0;
	m = s->m;

	for (i = 0; i < 256; i++)
	{
		m[i] = (unsigned char)i;
	}

	j = k = 0;

	for (i = 0; i < 256; i++)
	{
		a = m[i];
		j = (unsigned char)(j + a + key[k]);
		m[i] = m[j]; m[j] = a;
		if (++k >= length) k = 0;
	}
}

void rc4_crypt(struct rc4_state *s, unsigned char *data, int length)
{
	int i, x, y;
	unsigned char  *m, a, b;

	x = s->x;
	y = s->y;
	m = s->m;

	for (i = 0; i < length; i++)
	{
		x = (unsigned char)(x + 1); a = m[x];
		y = (unsigned char)(y + a);
		m[x] = b = m[y];
		m[y] = a;
		data[i] ^= m[(unsigned char)(a + b)];
	}

	s->x = x;
	s->y = y;
}

void rc4_encode(unsigned char *data, int datalen, unsigned char *key, int keylen)
{
	struct rc4_state m_state;
	rc4_setup(&m_state, key, keylen);
	rc4_crypt(&m_state, data, datalen);
}

void RC4_EnDecrypt(unsigned char *data, int datalen, unsigned char *key, int keylen)
{
	int nResidualLength = datalen;
	while (nResidualLength > DEENCRYPT_LENGTH)
	{
		rc4_encode(data, DEENCRYPT_LENGTH, key, keylen);
		data += DEENCRYPT_LENGTH;
		nResidualLength -= DEENCRYPT_LENGTH;
	}
	rc4_encode(data, nResidualLength, key, keylen);
}
