/*
 * totp.h
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

#ifndef TOTP_H__
#define TOTP_H__

#include <string.h>

#include <openssl/hmac.h>

#define hmac_ctx_init HMAC_CTX_init
#define hmac_init HMAC_Init
#define hmac_update HMAC_Update
#define hmac_final HMAC_Final
#define hmac_ctx_cleanup HMAC_CTX_cleanup

#define evp_sha1 EVP_sha1
#define evp_sha256 EVP_sha256
#define evp_sha512 EVP_sha512

#ifndef KEY_LEN
#define KEY_LEN 17
#endif

#ifndef HASH_LEN
#define HASH_LEN 21
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef HMAC_CTX hmac_ctx_t;
typedef EVP_MD evp_md_t;

typedef unsigned char hash_t;

void hmac_sha(const hash_t *key, const hash_t *msg, hash_t *hash, const evp_md_t *md);

void hmac_sha1(const hash_t *key, const hash_t *msg, hash_t *hash);
void hmac_sha256(const hash_t *key, const hash_t *msg, hash_t *hash);
void hmac_sha512(const hash_t *key, const hash_t *msg, hash_t *hash);

void totp_hmac(const char *seed, const time_t t, const size_t len, char *token, void (*hmac_f)(const hash_t *, const hash_t *, hash_t *));
void totp_hmac_sha1(const char *seed, const time_t t, const size_t len, char *token);
void totp_hmac_sha256(const char *seed, const time_t t, const size_t len, char *token);
void totp_hmac_sha512(const char *seed, const time_t t, const size_t len, char *token);

#ifdef __cplusplus
}
#endif

#endif  // TOTP_H__