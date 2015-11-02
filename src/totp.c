/*
 * totp.c
 * Copyright (C) 2015  James Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "totp.h"

#ifdef __cplusplus
extern "C" {
#endif

const int DIGITS_POWER[]
//  0  1   2    3     4      5       6        7         8
= { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

void hmac_sha(const hash_t *key, const hash_t *msg, hash_t *hash, const evp_md_t *md)
{
    hmac_ctx_t ctx;
    hmac_ctx_init(&ctx);
    hmac_init(&ctx, key, strlen((char *)key), md);
    hmac_update(&ctx, msg, strlen((char *)msg));
    hmac_final(&ctx, hash, NULL);
    hmac_ctx_cleanup(&ctx);
}

void hmac_sha1(const hash_t *key, const hash_t *msg, hash_t *hash)
{
    hmac_sha(key, msg, hash, evp_sha1());
}

void hmac_sha256(const hash_t *key, const hash_t *msg, hash_t *hash)
{
    hmac_sha(key, msg, hash, evp_sha256());
}

void hmac_sha512(const hash_t *key, const hash_t *msg, hash_t *hash)
{
    hmac_sha(key, msg, hash, evp_sha512());
}

void totp_hmac(const char *seed, time_t t, size_t len, char *token, void (*hmac_f)(const hash_t *, const hash_t *, hash_t *))
{
    char key[KEY_LEN];

    sprintf(key, "%016ld", t / 30);

    hash_t hash[HASH_LEN];
    hmac_f((hash_t *)seed, (hash_t *)key, hash);

    int os = hash[len - 1] & 0xf;

    int bin = ((hash[os + 0] & 0x7f) << 24) |
              ((hash[os + 1] & 0xff) << 16) |
              ((hash[os + 2] & 0xff) <<  8) |
              ((hash[os + 3] & 0xff) <<  0) ;

    int otp = bin % DIGITS_POWER[len];

    char format[5];
    sprintf(format, "%c0%ldd", '%', len);

    sprintf(token, format, otp);
}

void totp_hmac_sha1(const char *seed, const time_t t, const size_t len, char *token)
{
    totp_hmac(seed, t, len, token, &hmac_sha1);
}
void totp_hmac_sha256(const char *seed, const time_t t, const size_t len, char *token)
{
    totp_hmac(seed, t, len, token, &hmac_sha256);
}
void totp_hmac_sha512(const char *seed, const time_t t, const size_t len, char *token)
{
    totp_hmac(seed, t, len, token, &hmac_sha512);
}

#ifdef __cplusplus
}
#endif