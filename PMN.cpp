#include <stdio.h>
#include <string.h>
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

int main(int argc, char *argv[])
{
    printf("PMN emulation starts.\n");
    int PMNPort;
    responsePMN rPMN;
    memset(&rPMN, 0, sizeof(responsePMN));
    if (argc > 1)
    {
        PMNPort = atoi(argv[1]);
        rPMN.s = atoi(argv[2]);
    }
    else
    {
        printf("Input the port of this PMN:\n");
        scanf("%d", &PMNPort);
        printf("Input the sector number of each file block:\n");
        scanf("%d", &rPMN.s);
    }
    pairing_t pairing;
    FILE* fp = NULL;
    fp = fopen("a.param", "r");
    if (fp == NULL)
    {
        printf("Cannot find the file \"a.param\"!\n");
        return -1;
    }
    rPMN.paramSize = fread(rPMN.paramBuffer, 1, 1024, fp);
    fclose(fp);
    fp = NULL;
    pairing_init_set_buf(pairing, rPMN.paramBuffer, rPMN.paramSize);
    element_t g1;
    element_init_G1(g1, pairing);
    element_random(g1);
    element_printf("g1 = %B\n", g1);
    element_t g2;
    element_init_G2(g2, pairing);
    element_random(g2);
    element_printf("g2 = %B\n", g2);
    element_t x;
    element_init_Zr(x, pairing);
    element_random(x);
    element_printf("x = %B\n", x);
    element_t mpk;
    element_init_G2(mpk, pairing);
    element_pow_zn(mpk, g2, x);
    element_printf("mpk = %B\n", mpk);
    element_t alpha;
    element_init_Zr(alpha, pairing);
    element_t beta;
    element_init_Zr(beta, pairing);
    element_t sigma;
    element_init_G1(sigma, pairing);
    element_t v;
    element_init_G2(v, pairing);
    element_t *u = (element_t*)malloc(sizeof(element_t) * rPMN.s);
    int j;
    for (j = 0; j < rPMN.s; j++)
    {
        element_init_G1(u[j], pairing);
    }
    element_t sk;
    element_init_G1(sk, pairing);
    element_t h1;
    element_init_Zr(h1, pairing);
    element_to_bytes_compressed((unsigned char*)rPMN.g1Buffer, g1);
    element_to_bytes_compressed((unsigned char*)rPMN.g2Buffer, g2);
    element_to_bytes_compressed((unsigned char*)rPMN.mpkBuffer, mpk);
    element_pp_t g1_pp;
    element_pp_init(g1_pp, g1);
    rPMN.witnessNumber = 0;
    regRequest rr;
    char NID[256];
    memset(NID, 0, 256);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        printf("socket() executes failed (errno: %d)!\n", errno);
        return -1;
    }
    struct sockaddr_in srvAddr;
    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(PMNPort);
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
    printf("Waiting for queries of keys...\n");
    while (true)
    {
        int connSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &len);
        if (-1 == connSocket)
        {
            printf("accept() executes failed (errno: %d)!\n", errno);
            return -1;
        }
        else
        {
            receiveFrom(connSocket, (char*)&rr, sizeof(regRequest));
            char IP[16];
            memset(IP, 0, 16);
            memcpy(IP, inet_ntoa(clientAddr.sin_addr), strlen(inet_ntoa(clientAddr.sin_addr)));
            memset(rPMN.skBuffer, 0, 65);
            if (strcmp(rr.type, "RS") == 0)
            {
                memcpy(rPMN.RSIP, IP, 16);
                rPMN.RSPort = rr.port;
            }
            if (strcmp(rr.type, "RS down") == 0)
            {
                memset(rPMN.RSIP, 0, 16);
                rPMN.RSPort = 0;
            }
            if (strcmp(rr.type, "designated verifier") == 0)
            {
                memcpy(rPMN.designatedIP, IP, 16);
                rPMN.designatedPort = rr.port;
            }
            if (strcmp(rr.type, "designated verifier down") == 0)
            {
                memset(rPMN.designatedIP, 0, 16);
                rPMN.designatedPort = 0;
            }
            if (strcmp(rr.type, "witness verifier") == 0)
            {
                int i;
                for (i = 0; i < rPMN.witnessNumber; i++)
                {
                    if (strcmp(rPMN.witnessIP[i], IP) == 0 && rPMN.witnessPort[i] == rr.port)
                    {
                        break;
                    }
                }
                if (i == rPMN.witnessNumber)
                {
                    memcpy(rPMN.witnessIP[rPMN.witnessNumber], IP, 16);
                    rPMN.witnessPort[rPMN.witnessNumber] = rr.port;
                    rPMN.witnessNumber++;
                }
            }
            if (strcmp(rr.type, "witness verifier down") == 0)
            {
                int i;
                for (i = 0; i < rPMN.witnessNumber; i++)
                {
                    if (strcmp(rPMN.witnessIP[i], IP) == 0 && rPMN.witnessPort[i] == rr.port)
                    {
                        break;
                    }
                }
                for (; i < rPMN.witnessNumber; i++)
                {
                    memcpy(rPMN.witnessIP[i], rPMN.witnessIP[i + 1], 16);
                    rPMN.witnessPort[i] = rPMN.witnessPort[i + 1];
                }
                rPMN.witnessNumber--;
            }
            if (strcmp(rr.type, "node") == 0)
            {
                if (strcmp(NID, rr.ID))
                {
                    printf("Generating the private key...\n");
                    element_random(alpha);
                    element_to_bytes((unsigned char*)rPMN.alphaBuffer, alpha);
                    element_random(beta);
                    element_to_bytes((unsigned char*)rPMN.betaBuffer, beta);
                    char *HBuffer = (char*)calloc(1, strlen(rr.ID) + 65 + rPMN.s * 65);
                    memcpy(HBuffer, rr.ID, strlen(rr.ID));
                    element_pow_zn(v, g2, alpha);
                    element_to_bytes_compressed((unsigned char*)HBuffer + strlen(rr.ID), v);
                    for (j = 0; j < rPMN.s; j++)
                    {
                        element_add_ui(h1, beta, j);
                        hashElementToElement(h1, h1);
                        element_pp_pow_zn(u[j], h1, g1_pp);
                        element_to_bytes_compressed((unsigned char*)HBuffer + strlen(rr.ID) + 65 + j * 65, u[j]);
                    }
                    hashStrToElement(sigma, HBuffer, strlen(rr.ID) + 65 + rPMN.s * 65);
                    element_pow_zn(sigma, sigma, x);
                    element_to_bytes_compressed((unsigned char*)rPMN.sigmaBuffer, sigma);
                    memcpy(NID, rr.ID, 256);
                    free(HBuffer);
                }
                memcpy(rPMN.nodeIP, IP, 16);
                rPMN.nodePort = rr.port;
            }
            if (strcmp(rr.type, "node down") == 0)
            {
                memset(rPMN.nodeIP, 0, 16);
                rPMN.nodePort = 0;
            }
            if (strcmp(rr.type, "query") != 0 && strcmp(rr.type, "RS down") != 0 && strcmp(rr.type, "designated verifier down") != 0 && strcmp(rr.type, "witness verifier down") != 0 && strcmp(rr.type, "node down") != 0)
            {
                hashStrToElement(sk, rr.ID, strlen(rr.ID));
                element_pow_zn(sk, sk, x);
                element_to_bytes_compressed((unsigned char*)rPMN.skBuffer, sk);
            }
            sendTo(connSocket, (char*)&rPMN, sizeof(responsePMN));
            printf("Responded to a %s. IP: %s, port: %d.\n", rr.type, IP, rr.port);
            close(connSocket);
        }
    }
    return 0;
}
