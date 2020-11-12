#include <stdio.h>
#include <time.h>
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

void getRandomBytes(unsigned char *l, long length)
{
    for (long i = 0; i < length; i++)
    {
        l[i] = rand() % 256;
    }
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

void binaryToZr(element_t &f, char *buffer, char *sector, int sector_size)
{
    for (int i = 0; i < sector_size; i++)
    {
        buffer[i] = sector[i];
    }
    element_from_bytes(f, (unsigned char*)buffer);
}

void IDS(char *IDSBuffer1, char *IDSBuffer2, char *message, int length, char *ID, element_t &sk, pairing_t &pairing)
{
    element_t sig1;
    element_t sig2;
    element_init_G1(sig1, pairing);
    element_init_G1(sig2, pairing);
    element_t pk;
    element_init_G1(pk, pairing);
    hashStrToElement(pk, ID, strlen(ID));
    element_t temp;
    element_init_Zr(temp, pairing);
    element_random(temp);
    element_pow_zn(sig1, pk, temp);
    element_t h;
    element_init_Zr(h, pairing);
    hashStrToElement(h, message, length);
    element_add(temp, temp, h);
    element_pow_zn(sig2, sk, temp);
    element_to_bytes_compressed((unsigned char*)IDSBuffer1, sig1);
    element_to_bytes_compressed((unsigned char*)IDSBuffer2, sig2);
    element_clear(sig1);
    element_clear(sig2);
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

void generateHVTs(element_t *t, char *mBuffer, char *NID, char *FID, int nb, int s, element_t &g1, element_t &alpha, element_t *h1, pairing_t &pairing)
{
    int i;
    int j;
    char str[1024];
    char buffer[20];
    element_t H2;
    element_t m;
    element_pp_t g1_pp;
    element_t temp1;
    element_t temp2;
    element_init_G1(H2, pairing);
    element_init_Zr(m, pairing);
    element_pp_init(g1_pp, g1);
    element_init_Zr(temp1, pairing);
    element_init_Zr(temp2, pairing);
    for (i = 0; i < nb; i++)
    {
        sprintf(str, "%s%s%d", NID, FID, i);
        hashStrToElement(H2, str, strlen(str));
        element_set0(temp1);
        for (j = 0; j < s; j++)
        {
            memset(buffer, 0, 20);
            binaryToZr(m, buffer, mBuffer + i * j * 16, 16);
            element_mul(temp2, h1[j], m);
            element_add(temp1, temp1, temp2);
        }
        element_pp_pow_zn(t[i], temp1, g1_pp);
        element_mul(t[i], t[i], H2);
        element_pow_zn(t[i], t[i], alpha);
    }
    element_clear(H2);
    element_clear(m);
    element_pp_clear(g1_pp);
    element_clear(temp1);
    element_clear(temp2);
}

int main(int argc, char *argv[])
{
//  Init:

    printf("Node emulation starts.\n");
    char PMNIP[16];
    memset(PMNIP, 0, 16);
    int PMNPort;
    int nodePort;
    char NID[256];
    memset(NID, 0, 256);
    char FID[256];
    memset(FID, 0, 256);
    int nb;
    if (argc > 1)
    {
        strcpy(PMNIP, argv[1]);
        PMNPort = atoi(argv[2]);
        nodePort = atoi(argv[3]);
        strcpy(NID, argv[4]);
        strcpy(FID, argv[5]);
        nb = atoi(argv[6]);
    }
    else
    {
        printf("Input the IP of the PMN:\n");
        scanf("%s", PMNIP);
        printf("Input the port of the PMN:\n");
        scanf("%d", &PMNPort);
        printf("Input the port of this node:\n");
        scanf("%d", &nodePort);
        printf("Input NID:\n");
        scanf("%s", NID);
        printf("Input the FID of the new file:\n");
        scanf("%s", FID);
        printf("Input the block number of %s:\n", FID);
        scanf("%d", &nb);
    }
    regRequest rr;
    memset(&rr, 0, sizeof(regRequest));
    strcpy(rr.type, "node");
    strcpy(rr.ID, NID);
    rr.port = nodePort;
    responsePMN rPMN;
    memset(&rPMN, 0, sizeof(responsePMN));

    struct sockaddr_in srvAddr;
    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = inet_addr(PMNIP);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(PMNPort);
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
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
    printf("Waiting for the private key...\n");
    receiveFrom(clientSocket, (char*)&rPMN, sizeof(responsePMN));
    close(clientSocket);

    pairing_t pairing;
    pairing_init_set_buf(pairing, rPMN.paramBuffer, rPMN.paramSize);
    element_t g1;
    element_init_G1(g1, pairing);
    element_from_bytes_compressed(g1, (unsigned char*)rPMN.g1Buffer);
    element_printf("g1 = %B\n", g1);
    element_t g2;
    element_init_G2(g2, pairing);
    element_from_bytes_compressed(g2, (unsigned char*)rPMN.g2Buffer);
    element_printf("g2 = %B\n", g2);
    element_t mpk;
    element_init_G2(mpk, pairing);
    element_from_bytes_compressed(mpk, (unsigned char*)rPMN.mpkBuffer);
    element_printf("mpk = %B\n", mpk);
    element_t alpha;
    element_init_Zr(alpha, pairing);
    element_from_bytes(alpha, (unsigned char*)rPMN.alphaBuffer);
    element_printf("alpha = %B\n", alpha);
    element_t beta;
    element_init_Zr(beta, pairing);
    element_from_bytes(beta, (unsigned char*)rPMN.betaBuffer);
    element_printf("beta = %B\n", beta);
    element_t sigma;
    element_init_G1(sigma, pairing);
    element_from_bytes_compressed(sigma, (unsigned char*)rPMN.sigmaBuffer);
    element_printf("sigma = %B\n", sigma);
    element_t sk;
    element_init_G1(sk, pairing);
    element_from_bytes_compressed(sk, (unsigned char*)rPMN.skBuffer);
    element_printf("sk = %B\n", sk);
    element_t v;
    element_init_G2(v, pairing);
    element_pow_zn(v, g2, alpha);
    element_printf("v = %B\n", v);
    char vBuffer[65];
    memset(vBuffer, 0, 65);
    element_to_bytes_compressed((unsigned char*)vBuffer, v);
    int s = rPMN.s;
    element_t *h1 = (element_t*)malloc(sizeof(element_t) * s);
    element_t *u = (element_t*)malloc(sizeof(element_t) * s);
    char *h1Buffer = (char*)calloc(s, 20);
    char *uBuffer = (char*)calloc(s, 65);
    int i = 0;
    FILE *fp = NULL;
    fp = fopen("PreStored", "r");
    if (fp != NULL)
    {
        char str[20];
        memset(str, 0, 20);
        fread(str, 20, 1, fp);
        element_init_Zr(h1[0], pairing);
        hashElementToElement(h1[0], beta);
        char str1[20];
        memset(str1, 0, 20);
        element_to_bytes((unsigned char*)str1, h1[0]);
        element_clear(h1[0]);
        for (; i < 20; i++)
        {
            if (str[i] != str1[i])
            {
                break;
            }
        }
        fclose(fp);
        fp = NULL;
    }
    int j;
    if (i == 20)
    {
        fp = fopen("PreStored", "r");
        fread(h1Buffer, 20, s, fp);
        fread(uBuffer, 65, s, fp);
        fclose(fp);
        fp = NULL;
        for (j = 0; j < s; j++)
        {
            element_init_Zr(h1[j], pairing);
            element_from_bytes(h1[j], (unsigned char*)h1Buffer + j * 20);
            element_init_G1(u[j], pairing);
            element_from_bytes_compressed(u[j], (unsigned char*)uBuffer + j * 65);
        }
    }
    else
    {
        printf("Initializing...\n");
        element_pp_t g1_pp;
        element_pp_init(g1_pp, g1);
        int j;
        for (j = 0; j < s; j++)
        {
            element_init_Zr(h1[j], pairing);
            element_add_ui(h1[j], beta, j);
            hashElementToElement(h1[j], h1[j]);
            element_to_bytes((unsigned char*)h1Buffer + j * 20, h1[j]);
            element_init_G1(u[j], pairing);
            element_pp_pow_zn(u[j], h1[j], g1_pp);
            element_to_bytes_compressed((unsigned char*)uBuffer + j * 65, u[j]);
        }
        element_pp_clear(g1_pp);
        fp = fopen("PreStored", "w");
        fwrite(h1Buffer, 20, s, fp);
        fwrite(uBuffer, 65, s, fp);
        fclose(fp);
        fp = NULL;
    }
    char sigmaBuffer[65];
    memcpy(sigmaBuffer, rPMN.sigmaBuffer, 65);
    char RSIP[16];
    memcpy(RSIP, rPMN.RSIP, 16);
    int RSPort = rPMN.RSPort;
    char designatedIP[16];
    memcpy(designatedIP, rPMN.designatedIP, 16);
    int designatedPort = rPMN.designatedPort;

//  Generate file and HVTs:

    char *mBuffer = (char*)calloc(nb * s, 16);
    printf("Creating %s...\n", FID);
    srand(time(NULL));
    getRandomBytes((unsigned char*)mBuffer, nb * s * 16);
    char *tBuffer = (char*)calloc(nb, 65);
    element_t *t = (element_t*)malloc(sizeof(element_t) * nb);
    struct timeval start, end;
    for (i = 0; i < nb; i++)
    {
        element_init_G1(t[i], pairing);
    }
    printf("Generating the HVTs of %s...\n", FID);
    gettimeofday(&start, NULL);
    generateHVTs(t, mBuffer, NID, FID, nb, s, g1, alpha, h1, pairing);
    for (i = 0; i < nb; i++)
    {
        element_to_bytes_compressed((unsigned char*)tBuffer + i * 65, t[i]);
    }
    gettimeofday(&end, NULL);
    printf("Time: %.3lfms\n", 1000 * (double)(end.tv_sec - start.tv_sec) + 0.001 * (double)(end.tv_usec - start.tv_usec));
    fp = fopen("Node.csv", "a");
    fprintf(fp, "%d,%d,%.3lf,", s, nb, 1000 * (double)(end.tv_sec - start.tv_sec) + 0.001 * (double)(end.tv_usec - start.tv_usec));

//  CREATE:

    request rt;
    responseVerifier rv;
    memset(&rt, 0, sizeof(request));
    strcpy(rt.NID, NID);
    strcpy(rt.FID, FID);
    rt.OP = 0;
    rt.nb = nb;
    sprintf(rt.ts, "%lx", time(NULL));
    IDS(rt.IDSBuffer, rt.IDSBuffer + 65, (char*)&rt, sizeof(request), NID, sk, pairing);

    while (strcmp(RSIP, "") == 0)
    {
        memset(&rPMN, 0, sizeof(responsePMN));
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
        strcpy(rr.type, "query");
        sendTo(clientSocket, (char*)&rr, sizeof(regRequest));
        receiveFrom(clientSocket, (char*)&rPMN, sizeof(responsePMN));
        close(clientSocket);
        memcpy(RSIP, rPMN.RSIP, 16);
        RSPort = rPMN.RSPort;
        if (strcmp(RSIP, "") == 0)
        {
            printf("The RS is not ready, retry after 5 seconds...\n");
            sleep(5);
        }
    }

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = inet_addr(RSIP);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(RSPort);
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
    printf("Sending the blocks and HVTs of %s...\n", FID);
    sendTo(clientSocket, (char*)&rt, sizeof(request));
    sendTo(clientSocket, mBuffer, nb * s * 16);
    sendTo(clientSocket, tBuffer, nb * 65);
    sendTo(clientSocket, vBuffer, 65);
    sendTo(clientSocket, uBuffer, s * 65);
    sendTo(clientSocket, sigmaBuffer, 65);
    close(clientSocket);
    printf("%d bytes blocks, %d bytes HVTs, and %d bytes extra authentication information have been sent.\n", nb * s * 16, nb * 65, s * 65 + 130);

    while (strcmp(designatedIP, "") == 0)
    {
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
        strcpy(rr.type, "query");
        sendTo(clientSocket, (char*)&rr, sizeof(regRequest));
        receiveFrom(clientSocket, (char*)&rPMN, sizeof(responsePMN));
        close(clientSocket);
        memcpy(designatedIP, rPMN.designatedIP, 16);
        designatedPort = rPMN.designatedPort;
        if (strcmp(designatedIP, "") == 0)
        {
            printf("The designated verifier is not ready, retry after 5 seconds...\n");
            sleep(5);
        }
    }

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = inet_addr(designatedIP);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(designatedPort);
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
    gettimeofday(&start, NULL);
    sendTo(clientSocket, (char*)&rt, sizeof(request));
    close(clientSocket);
    printf("The request has been sent to the designated verifier.\n");

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        printf("socket() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(nodePort);
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
    printf("Waiting for the checking result...\n");
    int connSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &len);
    if (-1 == connSocket)
    {
        printf("accept() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    else
    {
        receiveFrom(connSocket, (char*)&rv, sizeof(responseVerifier));
        close(connSocket);
    }
    close(serverSocket);

    gettimeofday(&end, NULL);
    printf("Time: %.3lfms\n", 1000 * (double)(end.tv_sec - start.tv_sec) + 0.001 * (double)(end.tv_usec - start.tv_usec));
    fprintf(fp, "%.3lf\n", 1000 * (double)(end.tv_sec - start.tv_sec) + 0.001 * (double)(end.tv_usec - start.tv_usec));
    fclose(fp);
    fp = NULL;
    char IDSBuffer[130];
    memcpy(IDSBuffer, rv.IDSBuffer, 130);
    memset(rv.IDSBuffer, 0, 130);
    if (verifyIDS(IDSBuffer, IDSBuffer + 65, (char*)&rv, sizeof(responseVerifier), rv.ID, mpk, g2, pairing) && rv.result == 1)
    {
        printf("Checking result: passed.\n");
    }
    else
    {
        printf("Checking result: failed.\n");
    }

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
    strcpy(rr.type, "node down");
    sendTo(clientSocket, (char*)&rr, sizeof(regRequest));
    receiveFrom(clientSocket, (char*)&rPMN, sizeof(responsePMN));
    close(clientSocket);

    element_clear(g1);
    element_clear(g2);
    element_clear(mpk);
    element_clear(alpha);
    element_clear(beta);
    element_clear(sigma);
    element_clear(sk);
    element_clear(v);
    free(h1Buffer);
    free(uBuffer);
    for (j = 0; j < s; j++)
    {
        element_clear(h1[j]);
        element_clear(u[j]);
    }
    free(h1);
    free(u);
    if (nb > 0)
    {
        free(mBuffer);
        free(tBuffer);
    }
    for (i = 0; i < nb; i++)
    {
        element_clear(t[i]);
    }
    free(t);
    pairing_clear(pairing);
    sleep(5);
    return 0;
}
