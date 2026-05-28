#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

void test(const char* name, int keysize) {
    struct sockaddr_alg sa = { .salg_family = AF_ALG, .salg_type = "aead" };
    strncpy((char*)sa.salg_name, name, 63);
    int sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (bind(sfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        printf("[-] bind %s: fallo\n", name); close(sfd); return;
    }
    setsockopt(sfd, 279, ALG_SET_AEAD_AUTHSIZE, NULL, 16);
    unsigned char key[64]; memset(key, 0x41, keysize);
    if (setsockopt(sfd, 279, ALG_SET_KEY, key, keysize) == 0)
        printf("[+] OK: %s keysize=%d\n", name, keysize);
    else
        printf("[-] key fallo: %s\n", name);
    close(sfd);
}

int main() {
    test("gcm(aes)", 16);
    test("gcm(aes)", 32);
    test("ccm(aes)", 16);
    test("chacha20-poly1305", 32);
    test("authenc(hmac(sha256),cbc(aes))", 48);
    test("authenc(hmac(sha256),cbc(aes))", 52);
    test("authencesn(hmac(sha256),cbc(aes))", 48);
    test("authencesn(hmac(sha256),cbc(aes))", 52);
    return 0;
}
