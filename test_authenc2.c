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

    // Formato: RTA_HDR(CRYPTO_AUTHENC_KEYA_PARAM) + enckeylen(be32) + authkey + enckey
    int akeylen = 32; // hmac-sha256
    int ekeylen = 16; // aes-128
    
    struct rtattr *rta;
    struct {
        uint16_t rta_len;
        uint16_t rta_type;
        uint32_t enckeylen; // big-endian
    } hdr;
    
    hdr.rta_len   = htons(sizeof(hdr));
    hdr.rta_type  = htons(1); // CRYPTO_AUTHENC_KEYA_PARAM
    hdr.enckeylen = htonl(ekeylen);

    int buflen = sizeof(hdr) + akeylen + ekeylen;
    char *buf = calloc(1, buflen);
    memcpy(buf, &hdr, sizeof(hdr));
    memset(buf + sizeof(hdr), 0x41, akeylen);           // authkey
    memset(buf + sizeof(hdr) + akeylen, 0x42, ekeylen); // enckey

    if (setsockopt(sfd, 279, ALG_SET_KEY, buf, buflen) == 0)
        printf("[+] authencesn key OK!\n");
    else
        perror("[-] key fallo");

    free(buf);
    return 0;
}
