#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <pbc/pbc.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

typedef struct
{
    char type[32];
    char ID[256];
    int port;
} regRequest;

typedef struct
{
    int paramSize;
    char paramBuffer[1024];
    char g1Buffer[65];
    char g2Buffer[65];
    char mpkBuffer[65];
    char alphaBuffer[20];
    char betaBuffer[20];
    char sigmaBuffer[65];
    char skBuffer[65];
    int s;
    char RSIP[16];
    int RSPort;
    char designatedIP[16];
    int designatedPort;
    int witnessNumber;
    char witnessIP[100][16];
    int witnessPort[100];
    char nodeIP[16];
    int nodePort;
} responsePMN;

typedef struct
{
    char NID[256];
    char FID[256];
    int OP;
    int nb;
    char ts[16];
    char IDSBuffer[130];
} request;

typedef struct
{
    char ID[256];
    int BCHeight;
    char result;
    char IDSBuffer[130];
} responseVerifier;

int sendTo(int fd, char *buffer, int size)
{
    int remain = size;
    int sendSize;
    while (remain > 0)
    {
        sendSize = write(fd, buffer, remain);
        if (sendSize < 0)
        {
            if (errno == EINTR)
            {
                sendSize = 0;
            }
            else
            {
                printf("write() executes failed (errno: %d)!\n", errno);
                return -1;
            }
        }
        remain -= sendSize;
        buffer += sendSize;
    }
    return 0;
}

int receiveFrom(int fd, char *buffer, int size)
{
    int remain = size;
    int recvSize;
    while (remain > 0)
    {
        recvSize = read(fd, buffer, remain);
        if (recvSize < 0)
        {
            if (errno == EINTR)
            {
                recvSize = 0;
            }
            else
            {
                printf("read() executes failed! (errno: %d)!\n", errno);
                return -1;
            }
        }
        remain -= recvSize;
        buffer += recvSize;
    }
    return 0;
}

void computeSHA256(unsigned char *hash, char *str, long length)
{
    SHA256_CTX c;
    SHA256((unsigned char*)str, length, hash);
    SHA256_Init(&c);
    SHA256_Update(&c, str, length);
    SHA256_Final(hash, &c);
    OPENSSL_cleanse(&c, sizeof(c));
}

void hashStrToElement(element_t &e, char *str, long length)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    computeSHA256(hash, str, length);
    element_from_hash(e, (void*)hash, SHA256_DIGEST_LENGTH);
}

void hashElementToElement(element_t &h, element_t &e)
{
    int length = element_length_in_bytes(e);
    char *str = (char*)malloc(sizeof(char) * length);
    element_to_bytes((unsigned char*)str, e);
    hashStrToElement(h, str, length);
    free(str);
}

void f(element_t &f, char *nonce, char *NID, int i)
{
    char str[1024];
    sprintf(str, "%s%s%d", nonce, NID, i);
    int length = strlen(str);
    hashStrToElement(f, str, length);
}

void IDS(char *IDSBuffer1, char *IDSBuffer2, char *message, int length, char *ID, element_t &sk, pairing_t &pairing)
{
    element_t IDS1;
    element_t IDS2;
    element_init_G1(IDS1, pairing);
    element_init_G1(IDS2, pairing);
    element_t pk;
    element_init_G1(pk, pairing);
    hashStrToElement(pk, ID, strlen(ID));
    element_t temp;
    element_init_Zr(temp, pairing);
    element_random(temp);
    element_pow_zn(IDS1, pk, temp);
    element_t h;
    element_init_Zr(h, pairing);
    hashStrToElement(h, message, length);
    element_add(temp, temp, h);
    element_pow_zn(IDS2, sk, temp);
    element_to_bytes_compressed((unsigned char*)IDSBuffer1, IDS1);
    element_to_bytes_compressed((unsigned char*)IDSBuffer2, IDS2);
    element_clear(IDS1);
    element_clear(IDS2);
    element_clear(pk);
    element_clear(temp);
    element_clear(h);
}

int verifyIDS(char *IDSBuffer1, char *IDSBuffer2, char *message, int length, char *ID, element_t &mpk, element_t &g, pairing_t &pairing)
{
    element_t IDS1;
    element_t IDS2;
    element_init_G1(IDS1, pairing);
    element_init_G1(IDS2, pairing);
    element_from_bytes_compressed(IDS1, (unsigned char*)IDSBuffer1);
    element_from_bytes_compressed(IDS2, (unsigned char*)IDSBuffer2);
    element_t pk;
    element_init_G1(pk, pairing);
    hashStrToElement(pk, ID, strlen(ID));
    element_t h;
    element_init_Zr(h, pairing);
    hashStrToElement(h, message, length);
    element_t temp;
    element_init_G1(temp, pairing);
    element_pow_zn(temp, pk, h);
    element_mul(temp, IDS1, temp);
    element_t left;
    element_init_GT(left, pairing);
    element_pairing(left, temp, mpk);
    element_t right;
    element_init_GT(right, pairing);
    element_pairing(right, IDS2, g);
    int result = element_cmp(left, right);
    element_clear(IDS1);
    element_clear(IDS2);
    element_clear(pk);
    element_clear(h);
    element_clear(temp);
    element_clear(left);
    element_clear(right);
    if (result == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int verifySig(char *sigBuffer, char *message, int length, element_t &pk, element_t &g, pairing_t &pairing)
{
    element_t sig;
    element_init_G1(sig, pairing);
    element_from_bytes_compressed(sig, (unsigned char*)sigBuffer);
    element_t h;
    element_init_G1(h, pairing);
    hashStrToElement(h, message, length);
    element_t left;
    element_init_GT(left, pairing);
    element_pairing(left, sig, g);
    element_t right;
    element_init_GT(right, pairing);
    element_pairing(right, h, pk);
    int result = element_cmp(left, right);
    element_clear(sig);
    element_clear(h);
    element_clear(left);
    element_clear(right);
    if (result == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

char verifyProof(char *P, char *NID, char *FID, int nb, char *ts, int s, element_t &mpk, element_t &g2, pairing_t &pairing)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        if (ts[i] != P[s * 85 + 323 + i])
        {
            return -1;
        }
    }
    element_t spk;
    element_init_G2(spk, pairing);
    element_from_bytes_compressed(spk, (unsigned char*)P + s * 85 + 404);
    if (verifySig(P + s * 85 + 339, P, s * 85 + 339, spk, g2, pairing) == 0)
    {
        return -2;
    }
    char *HBuffer = (char*)calloc(1, strlen(NID) + 65 + s * 65);
    memcpy(HBuffer, NID, strlen(NID));
    memcpy(HBuffer + strlen(NID), P + s * 20 + 193, 65 + s * 65);
    if (verifySig(P + s * 85 + 258, HBuffer, strlen(NID) + 65 + s * 65, mpk, g2, pairing) == 0)
    {
        return 0;
    }
    free(HBuffer);
    element_t M;
    element_init_Zr(M, pairing);
    element_t T;
    element_init_G1(T, pairing);
    element_from_bytes_compressed(T, (unsigned char*)P + s * 20);
    element_t Gamma;
    element_init_GT(Gamma, pairing);
    element_from_bytes(Gamma, (unsigned char*)P + s * 20 + 65);
    element_t v;
    element_init_G2(v, pairing);
    element_from_bytes_compressed(v, (unsigned char*)P + s * 20 + 193);
    char str[1024];
    element_t delta;
    element_t H2;
    element_t a;
    element_t left;
    element_t right;
    element_t prod_H;
    element_t temp1;
    element_t temp2;
    element_init_Zr(delta, pairing);
    element_init_G1(H2, pairing);
    element_init_Zr(a, pairing);
    element_init_GT(left, pairing);
    element_init_GT(right, pairing);
    element_init_G1(prod_H, pairing);
    element_set1(prod_H);
    element_init_G1(temp1, pairing);
    element_init_GT(temp2, pairing);
    hashElementToElement(delta, Gamma);
    element_pairing(left, T, g2);
    element_pow_zn(left, left, delta);
    element_mul(left, left, Gamma);
    for (i = 0; i < nb; i++)
    {
        sprintf(str, "%s%s%d", NID, FID, i);
        hashStrToElement(H2, str, strlen(str));
        f(a, ts, NID, i);
        element_pow_zn(temp1, H2, a);
        element_mul(prod_H, prod_H, temp1);
    }
    element_pairing(right, prod_H, v);
    element_pow_zn(right, right, delta);

    char *ThetaBuffer = (char*)calloc(s, 128);
    element_t *u = (element_t*)malloc(sizeof(element_t) * s);
    element_t *Theta = (element_t*)malloc(sizeof(element_t) * s);
    i = 0;
    FILE *fp = NULL;
    fp = fopen("PreStored", "r");
    if (fp != NULL)
    {
        char str[128];
        memset(str, 0, 128);
        fread(str, 128, 1, fp);
        element_init_G1(u[0], pairing);
        element_from_bytes_compressed(u[0], (unsigned char*)P + s * 20 + 258);
        element_init_GT(Theta[0], pairing);
        element_pairing(Theta[0], u[0], v);
        char str1[128];
        memset(str1, 0, 128);
        element_to_bytes((unsigned char*)str1, Theta[0]);
        for (; i < 128; i++)
        {
            if (str[i] != str1[i])
            {
                break;
            }
        }
        element_clear(u[0]);
        element_clear(Theta[0]);
        fclose(fp);
        fp = NULL;
    }
    int j;
    if (i == 128)
    {
        fp = fopen("PreStored", "r");
        fread(ThetaBuffer, 128, s, fp);
        for (j = 0; j < s; j++)
        {
            element_init_GT(Theta[j], pairing);
            element_from_bytes(Theta[j], (unsigned char*)ThetaBuffer + j * 128);
        }
        fclose(fp);
        fp = NULL;
    }
    else
    {
        for (j = 0; j < s; j++)
        {
            element_init_G1(u[j], pairing);
            element_from_bytes_compressed(u[j], (unsigned char*)P + s * 20 + 258 + j * 65);
            element_init_GT(Theta[j], pairing);
            element_pairing(Theta[j], u[j], v);
            element_to_bytes((unsigned char*)ThetaBuffer + j * 128, Theta[j]);
            element_clear(u[j]);
        }
        fp = fopen("PreStored", "w");
        fwrite(ThetaBuffer, 128, s, fp);
        fclose(fp);
        fp = NULL;
    }

    for (j = 0; j < s; j++)
    {
        element_from_bytes(M, (unsigned char*)P + j * 20);
        element_pow_zn(temp2, Theta[j], M);
        element_mul(right, right, temp2);
    }
    char result = element_cmp(left, right);
    element_clear(spk);
    element_clear(M);
    element_clear(T);
    element_clear(Gamma);
    element_clear(v);
    element_clear(delta);
    element_clear(H2);
    element_clear(a);
    element_clear(left);
    element_clear(right);
    element_clear(prod_H);
    element_clear(temp1);
    element_clear(temp2);
    free(ThetaBuffer);
    for (j = 0; j < s; j++)
    {
        element_clear(Theta[j]);
    }
    free(u);
    free(Theta);
    if (result == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int main(int argc, char *argv[])
{
//  Init:

    printf("Witness verifier emulation starts.\n");
    char PMNIP[16];
    memset(PMNIP, 0, 16);
    int PMNPort;
    int witnessPort;
    if (argc > 1)
    {
        strcpy(PMNIP, argv[1]);
        PMNPort = atoi(argv[2]);
        witnessPort = atoi(argv[3]);
    }
    else
    {
        printf("Input the IP of the PMN:\n");
        scanf("%s", PMNIP);
        printf("Input the port of the PMN:\n");
        scanf("%d", &PMNPort);
        printf("Input the port of this witness verifier:\n");
        scanf("%d", &witnessPort);
    }
    regRequest rr;
    memset(&rr, 0, sizeof(regRequest));
    strcpy(rr.type, "witness verifier");
    char WVID[256];
    memset(WVID, 0, 256);
    sprintf(WVID, "witness verifier-%lx", time(NULL));
    memcpy(rr.ID, WVID, 256);
    rr.port = witnessPort;
    responsePMN rPMN;
    memset(&rPMN, 0, sizeof(responsePMN));

    struct sockaddr_in srvAddr;
    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = inet_addr(PMNIP);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(PMNPort);
    int clientSocket;
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == clientSocket)
    {
        printf("socket() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    if (0 != connect(clientSocket, (struct sockaddr*)&srvAddr, sizeof(srvAddr)))
    {
        printf("connect() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    sendTo(clientSocket, (char*)&rr, sizeof(regRequest));
    receiveFrom(clientSocket, (char*)&rPMN, sizeof(responsePMN));
    close(clientSocket);

    pairing_t pairing;
    pairing_init_set_buf(pairing, rPMN.paramBuffer, rPMN.paramSize);
    element_t g2;
    element_init_G2(g2, pairing);
    element_from_bytes_compressed(g2, (unsigned char*)rPMN.g2Buffer);
    element_printf("g2 = %B\n", g2);
    element_t mpk;
    element_init_G2(mpk, pairing);
    element_from_bytes_compressed(mpk, (unsigned char*)rPMN.mpkBuffer);
    element_printf("mpk = %B\n", mpk);
    element_t sk;
    element_init_G1(sk, pairing);
    element_from_bytes_compressed(sk, (unsigned char*)rPMN.skBuffer);
    element_printf("sk = %B\n", sk);
    int s = rPMN.s;

    request rt;
    char NID[256];
    char FID[256];
    int nb;
    char ts[16];
    char rtIDSBuffer[130];
    int PSize = s * 85 + 469;
    char result;
    char resultBuffer[17];
    char *BC[1000];
    int BCHeight = 0;
    int BlockSize = sizeof(request) + PSize + SHA256_DIGEST_LENGTH + 265;
    BC[BCHeight] = (char*)calloc(1, BlockSize);
    char BlockIDSBuffer[130];
    char DVID[256];
    memset(DVID, 0, 256);
    strcpy(DVID, "designated verifier");
    unsigned char prevHash[SHA256_DIGEST_LENGTH];
    responseVerifier rv;
    int i;

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        printf("socket() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(witnessPort);
    if (0 != bind(serverSocket, (struct sockaddr*)&srvAddr, sizeof(srvAddr)))
    {
        printf("bind() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    if (-1 == listen(serverSocket, 10))
    {
        printf("listen() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    struct sockaddr_in clientAddr;
    memset(&clientAddr, 0, sizeof(clientAddr));
    socklen_t len = sizeof(clientAddr);
    printf("Waiting for the new block...\n");
    int connSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &len);
    if (-1 == connSocket)
    {
        printf("accept() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    else
    {
        printf("Receiving the new block from the designated verifier...\n");
        receiveFrom(connSocket, (char*)BC[BCHeight], BlockSize);
        memset(&rv, 0, sizeof(responseVerifier));
        strcpy(rv.ID, WVID);
        rv.result = 1;
        memcpy(BlockIDSBuffer, BC[BCHeight] + sizeof(request) + PSize + SHA256_DIGEST_LENGTH + 135, 130);
        memset(BC[BCHeight] + sizeof(request) + PSize + SHA256_DIGEST_LENGTH + 135, 0, 130);
        if (verifyIDS(BlockIDSBuffer, BlockIDSBuffer + 65, BC[BCHeight], BlockSize, DVID, mpk, g2, pairing) == 0)
        {
            printf("The signature of the block is invalid.\n");
            rv.result = 0;
        }
        memset(prevHash, 0, SHA256_DIGEST_LENGTH);
        if (BCHeight > 0)
        {
            computeSHA256(prevHash, BC[BCHeight - 1], BlockSize);
        }
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            if (prevHash[i] != BC[BCHeight][sizeof(request) + PSize + 135 + i])
            {
                printf("PrevHash is invalid.\n");
                rv.result = 0;
            }
        }
        if (BlockSize != *(int*)(BC[BCHeight] + sizeof(request) + PSize + 131))
        {
            printf("Blocksize is invalid.\n");
            rv.result = 0;
        }
        memcpy(&rt, BC[BCHeight], sizeof(request));
        memset(NID, 0, 256);
        strcpy(NID, rt.NID);
        memset(FID, 0, 256);
        strcpy(FID, rt.FID);
        nb = rt.nb;
        memcpy(ts, rt.ts, 16);
        memcpy(rtIDSBuffer, rt.IDSBuffer, 130);
        memset(rt.IDSBuffer, 0, 130);
        if (verifyIDS(rtIDSBuffer, rtIDSBuffer + 65, (char*)&rt, sizeof(request), NID, mpk, g2, pairing) == 0)
        {
            printf("The IDS of the request is invalid.\n");
            rv.result = 0;
        }
        memcpy(rt.IDSBuffer, rtIDSBuffer, 130);
        result = BC[BCHeight][sizeof(request) + PSize];
        resultBuffer[0] = result;
        memcpy(resultBuffer + 1, ts, 16);
        if (verifyIDS(BC[BCHeight] + sizeof(request) + PSize + 1, BC[BCHeight] + sizeof(request) + PSize + 66, resultBuffer, 17, DVID, mpk, g2, pairing) == 0)
        {
            printf("The IDS of the result is invalid.\n");
            rv.result = 0;
        }
        struct timeval start, end;
        printf("Checking...\n");
        gettimeofday(&start, NULL);
        if (result != verifyProof(BC[BCHeight] + sizeof(request), NID, FID, nb, ts, s, mpk, g2, pairing))
        {
            printf("The result is invalid.\n");
            rv.result = 0;
        }
        gettimeofday(&end, NULL);
        printf("Time: %.3lfms\n", 1000 * (double)(end.tv_sec - start.tv_sec) + 0.001 * (double)(end.tv_usec - start.tv_usec));
        if (rv.result == 1)
        {
            BCHeight++;
            rv.BCHeight = BCHeight;
        }
        else
        {
            free(BC[BCHeight]);
        }
        IDS(rv.IDSBuffer, rv.IDSBuffer + 65, (char*)&rv, sizeof(responseVerifier), WVID, sk, pairing);
        sendTo(connSocket, (char*)&rv, sizeof(responseVerifier));
        close(connSocket);
        printf("Responded to the designated verifier.\n");
    }
    close(serverSocket);

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = inet_addr(PMNIP);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(PMNPort);
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == clientSocket)
    {
        printf("socket() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    if (0 != connect(clientSocket, (struct sockaddr*)&srvAddr, sizeof(srvAddr)))
    {
        printf("connect() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    strcpy(rr.type, "witness verifier down");
    sendTo(clientSocket, (char*)&rr, sizeof(regRequest));
    receiveFrom(clientSocket, (char*)&rPMN, sizeof(responsePMN));
    close(clientSocket);

    element_clear(g2);
    element_clear(mpk);
    element_clear(sk);
    for (i = 0; i < BCHeight; i++)
    {
        free(BC[i]);
    }
    pairing_clear(pairing);
    sleep(5);
    return 0;
}
