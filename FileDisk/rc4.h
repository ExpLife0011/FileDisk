#ifndef _RC4_H_
#define _RC4_H_

typedef struct rc4_state
{
	int  x, y;
	char m[256];
}RC4STATE, *PRC4STATE;

//加密数据，数据长度，密钥，密钥长度
void rc4_setup(struct rc4_state *s, unsigned char *key, int length);
void rc4_crypt(struct rc4_state *s, unsigned char *data, int length);

void rc4_encode(unsigned char *data, int datalen, unsigned char *key, int keylen);

void RC4_EnDecrypt(unsigned char *data, int datalen, unsigned char *key, int keylen);


#endif //_RC4_H_




