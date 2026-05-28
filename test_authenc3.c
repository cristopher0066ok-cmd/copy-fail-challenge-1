#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

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

    int akeylen = 32; // hmac-sha256
    int ekeylen = 16; // aes-128

    // RTA header + param (4 bytes enckeylen) + authkey + enckey
    struct {
        struct rtattr rta;
        uint32_t enckeylen; // be32
    } hdr;

    hdr.rta.rta_type = 1; // CRYPTO_AUTHENC_KEYA_PARAM
    hdr.rta.rta_len  = RTA_LENGTH(sizeof(uint32_t)); // hdr+4bytes
    hdr.enckeylen    = htonl(ekeylen);

    int buflen = hdr.rta.rta_len + akeylen + ekeylen;
    char *buf = calloc(1, buflen);
    memcpy(buf, &hdr, sizeof(hdr));
    memset(buf + hdr.rta.rta_len, 0x41, akeylen);
    memset(buf + hdr.rta.rta_len + akeylen, 0x42, ekeylen);

    printf("[*] rta_len=%d buflen=%d\n", hdr.rta.rta_len, buflen);

    if (setsockopt(sfd, 279, ALG_SET_KEY, buf, buflen) == 0)
        printf("[+] authencesn key OK!\n");
    else
        perror("[-] key fallo");

    free(buf);
    return 0;
}
