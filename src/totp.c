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

size_t hmac_sha(const hash_t *key, const hash_t *msg, hash_t *hash, const evp_md_t *md)
{
    size_t len;
    hash_t buff[MAX_LEN];
    hmac_ctx_t ctx;
    hmac_ctx_init(&ctx);
    hmac_init(&ctx, key, strlen((char *)key), md);
    hmac_update(&ctx, msg, strlen((char *)msg));
    hmac_final(&ctx, buff, (unsigned int *)&len);
    hmac_ctx_cleanup(&ctx);
    memcpy(hash, buff, len);
    return len;
}

size_t hmac_sha1(const hash_t *key, const hash_t *msg, hash_t *hash)
{
    return hmac_sha(key, msg, hash, evp_sha1());
}

size_t hmac_sha256(const hash_t *key, const hash_t *msg, hash_t *hash)
{
    return hmac_sha(key, msg, hash, evp_sha256());
}

size_t hmac_sha512(const hash_t *key, const hash_t *msg, hash_t *hash)
{
    return hmac_sha(key, msg, hash, evp_sha512());
}

void totp_hmac(const char *seed, time_t t, size_t len, char *token, size_t (*hmac_f)(const hash_t *, const hash_t *, hash_t *))
{
    if (len > 8) {
        fprintf(stderr, "ERROR: selected length (%ld) exceeds maximum boundary.\n", len);
        return;
    }

    // RFC4226
    char key_buff[KEY_LEN + 1];
    sprintf(key_buff, "%016ld", t / 30);
    char key[KEY_LEN];
    memcpy(key, key_buff, KEY_LEN);

    hash_t hash[MAX_LEN];

    // use passed hash function
    size_t hash_len;
    hash_len = hmac_f((hash_t *)seed, (hash_t *)key, hash);

    int os = hash[len - 1] & 0xf;

    int bin = ((hash[os + 0] & 0x7f) << 24) |
              ((hash[os + 1] & 0xff) << 16) |
              ((hash[os + 2] & 0xff) <<  8) |
              ((hash[os + 3] & 0xff) <<  0) ;

    int otp = bin % DIGITS_POWER[len];

    // generate format string like "%06d" to fix digits using 0
    char format[5];
    sprintf(format, "%c0%ldd", '%', len);

    char token_buff[len + 1];
    sprintf(token_buff, format, otp);
    memcpy(token, token_buff, len);
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