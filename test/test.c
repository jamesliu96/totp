/* test.c */

#include <totp.h>

int main(int argc, char **argv, char **env)
{
    time_t t;
    t = time(NULL);

    char *token;

    size_t len;
    len = 6;

    token = (char *)malloc(sizeof(char) * (len + 1));

    printf("t = %ld\n", t);

    totp_hmac_sha1("testkeyhellofoobar", t, len, token);
    printf("sha1:   %s\n", token);

    totp_hmac_sha256("testkeyhellofoobar", t, len, token);
    printf("sha256: %s\n", token);

    totp_hmac_sha512("testkeyhellofoobar", t, len, token);
    printf("sha512: %s\n", token);

    free(token);

    return 0;
}