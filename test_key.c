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
    
    unsigned char key[128];
    memset(key, 0x41, sizeof(key));
    
    int sizes[] = {16,20,24,32,36,48,52,64,80,84,96,100,112};
    for (int i = 0; i < 13; i++) {
        if (setsockopt(sfd, 279, 1, key, sizes[i]) == 0)
            printf("[+] Tamano valido: %d\n", sizes[i]);
    }
    return 0;
}
