#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/rtnetlink.h>

// authenc necesita clave en formato RTA
static int set_authenc_key(int sfd, const void *akey, int akeylen,
                            const void *ekey, int ekeylen) {
    struct rtattr *rta;
    char *buf;
    int buflen = RTA_SPACE(akeylen) + RTA_SPACE(ekeylen);
    buf = calloc(1, buflen);

    rta = (struct rtattr*)buf;
    rta->rta_type = 1; // CRYPTO_AUTHENC_KEYA_PARAM
    rta->rta_len  = RTA_LENGTH(akeylen);
    memcpy(RTA_DATA(rta), akey, akeylen);

    rta = (struct rtattr*)(buf + RTA_SPACE(akeylen));
    rta->rta_type = 0;
    rta->rta_len  = RTA_LENGTH(ekeylen);
    memcpy(RTA_DATA(rta), ekey, ekeylen);

    int r = setsockopt(sfd, 279, ALG_SET_KEY, buf, buflen);
    free(buf);
    return r;
}

int main() {
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "authencesn(hmac(sha256),cbc(aes))",
    };
    int sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (bind(sfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind"); return 1;
    }
    setsockopt(sfd, 279, ALG_SET_AEAD_AUTHSIZE, NULL, 16);

    unsigned char akey[32], ekey[16];
    memset(akey, 0x41, sizeof(akey));
    memset(ekey, 0x42, sizeof(ekey));

    if (set_authenc_key(sfd, akey, 32, ekey, 16) == 0)
        printf("[+] authencesn key OK! hmac=32 aes=16\n");
    else
        perror("[-] key fallo");

    return 0;
}
