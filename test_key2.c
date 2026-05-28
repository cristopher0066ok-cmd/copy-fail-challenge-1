#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int main() {
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "authencesn(hmac(sha256),cbc(aes))",
    };
    int sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sfd < 0) { perror("socket"); return 1; }
    if (bind(sfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }

    // authencesn necesita: clave_hmac(32) + clave_aes(16|24|32) + authsize(4 bytes via AEAD_AUTHSIZE)
    // Primero setear authsize
    int authsize = 16;
    if (setsockopt(sfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, authsize) < 0)
        perror("authsize");
    else
        printf("[+] authsize=16 OK\n");

    unsigned char key[128];
    memset(key, 0x41, sizeof(key));
    int sizes[] = {48, 56, 64, 80};
    for (int i = 0; i < 4; i++) {
        if (setsockopt(sfd, SOL_ALG, ALG_SET_KEY, key, sizes[i]) == 0)
            printf("[+] key size valido: %d\n", sizes[i]);
        else
            printf("[-] key size %d fallo\n", sizes[i]);
    }
    return 0;
}
