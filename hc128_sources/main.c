#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "ecrypt-sync.h"

#define BUFLEN	10000000

struct timeval t1, t2;

uint8_t buf[BUFLEN];
uint8_t out1[BUFLEN];
uint8_t out2[BUFLEN];
uint8_t key[16];
uint8_t iv[16];

static void
time_start(void)
{
	gettimeofday(&t1, NULL);
}

static uint32_t
time_stop(void)
{
	gettimeofday(&t2, NULL);

	t2.tv_sec -= t1.tv_sec;
	t2.tv_usec -= t1.tv_usec;

	if(t2.tv_usec < 0) {
		t2.tv_sec--;
		t2.tv_usec += 1000000;
	}

	return (t2.tv_sec * 1000 + t2.tv_usec/1000);
}

int
main()
{
	ECRYPT_ctx x;

	memset(buf, 'q', sizeof(buf));
	memset(key, 'k', sizeof(key));
	memset(iv, 'i', sizeof(iv));
	
	time_start();
	ECRYPT_init();

	ECRYPT_keysetup(&x, key, 128, 128);
	ECRYPT_ivsetup(&x, iv);
	
	ECRYPT_process_bytes(0, &x, buf, out1, BUFLEN);

	ECRYPT_ivsetup(&x, iv);

	ECRYPT_process_bytes(1, &x, out1, out2, BUFLEN);
	
	printf("Run time = %d\n\n", time_stop());

	return 0;
}

