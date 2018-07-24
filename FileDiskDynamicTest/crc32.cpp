#include "stdafx.h"
#include "crc32.h"


ULONG32 crc32(const unsigned char *buf, ULONG32 size)
{
	ULONG32 i, crc;
	crc = 0xFFFFFFFF;
	for (i = 0; i < size; i++)
		crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}