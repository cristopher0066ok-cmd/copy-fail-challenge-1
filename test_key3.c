#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

int main() {
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "authencesn(hmac(sha256),cbc(aes))",
    };
    int sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    bind(sfd, (struct sockaddr*)&sa, sizeof(sa));
    setsockopt(sfd, 279, ALG_SET_AEAD_AUTHSIZE, NULL, 16);

    unsigned char key[256];
    memset(key, 0x41, sizeof(key));
    for (int i = 1; i <= 128; i++) {
        if (setsockopt(sfd, 279, ALG_SET_KEY, key, i) == 0)
            printf("[+] key size valido: %d\n", i);
    }
    printf("done\n");
    return 0;
}
