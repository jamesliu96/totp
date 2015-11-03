/* test.c */

#include <totp.h>

int main(int argc, char **argv, char **env)
{
    // hmac-sha test

    printf("***** HMAC-SHA TEST *****\n");

    hash_t *hash;

    hash = (hash_t *)malloc(sizeof(hash_t) * MAX_LEN);

    char *key = "testkeyhellofoobar";
    char *msg = "testmsghellofoobar";

    size_t hash_len;

    int i;

    hash_len = hmac_sha1((hash_t *)key, (hash_t *)msg, hash);
    printf("SHA1(%s, %s) (len = %ld)\n= ", key, msg, hash_len);
    for (i = 0; i < hash_len; i++) printf("%02x", hash[i]);
    printf("\n");

    hash_len = hmac_sha256((hash_t *)key, (hash_t *)msg, hash);
    printf("SHA256(%s, %s) (len = %ld)\n= ", key, msg, hash_len);
    for (i = 0; i < hash_len; i++) printf("%02x", hash[i]);
    printf("\n");

    hash_len = hmac_sha512((hash_t *)key, (hash_t *)msg, hash);
    printf("SHA512(%s, %s) (len = %ld)\n= ", key, msg, hash_len);
    for (i = 0; i < hash_len; i++) printf("%02x", hash[i]);
    printf("\n");

    free(hash);

    // totp test

    printf("\n***** TOTP TEST *****\n");

    time_t t;
    t = time(NULL);

    char *token;

    size_t len;
    len = 6;

    token = (char *)malloc(sizeof(char) * len);

    printf("len = %ld\n", len);
    printf("t = %ld\n", t);

    totp_hmac_sha1(key, t, len, token);
    printf("sha1(%s):   %s\n", key, token);

    totp_hmac_sha256(key, t, len, token);
    printf("sha256(%s): %s\n", key, token);

    totp_hmac_sha512(key, t, len, token);
    printf("sha512(%s): %s\n", key, token);

    free(token);

    return 0;
}