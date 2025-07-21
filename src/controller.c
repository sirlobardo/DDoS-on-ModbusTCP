/*
 * Projeto: Desenvolvimento de uma arquitetura de cibersegurança para uma planta de manufatura avançada
 * Autor: Eduardo Lôbo Teixeira Filho
 * Ano: 2025
 * 
 * Desenvolvido com apoio da FAPESB (Edital 009/2024 - PIBIC/SENAI CIMATEC)
 *
 * Este programa é software livre: você pode redistribuí-lo e/ou modificá-lo
 * sob os termos da Licença Pública Geral GNU, conforme publicada pela Free Software Foundation,
 * na versão 3 da Licença, ou qualquer versão posterior.
 *
 * Este programa é distribuído na expectativa de que seja útil,
 * mas SEM QUALQUER GARANTIA; sem mesmo a garantia implícita de
 * COMERCIALIZAÇÃO ou ADEQUAÇÃO A UM DETERMINADO PROPÓSITO.
 * Veja a Licença Pública Geral GNU para mais detalhes.
 *
 * Você deve ter recebido uma cópia da Licença Pública Geral GNU
 * junto com este programa. Se não, veja <https://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <modbus.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <errno.h>
// #include <time.h>
// #include <fcntl.h>    
// #include <unistd.h>   

#pragma pack(1)

#define array_length(arr) (sizeof(arr) / sizeof((arr)[0]))
#define TARGET_HOST_MAXLEN 20
// #define TRUE 1
// #define BIT_MASK 0x01

typedef enum {
    READ,
    WRITE
} OperationType;

typedef struct {
    char targetHost[TARGET_HOST_MAXLEN];
    uint64_t startTime;
    uint64_t floodingPeriod;
    uint32_t timeoutAtk;
    unsigned int delayBtwRequestsAtk;
    OperationType operation;
} Parametros;

int criar_socket();
void conectar_servidor(int sock, const char *ip, int porta, struct sockaddr_in *server_addr);
void enviar_pacote(int sock, Parametros *p);
int ler_config(const char *filename, Parametros *p, char ***hosts, int *numHosts);
// uint64_t get_current_time_ms();
// void preencher_tab_reg_aleatorio(uint8_t *tab_reg, size_t tamanho);

int main() {
    Parametros p;
    char **hostAttackers = NULL;
    // int numAttackers = 0, rslt;
    int numAttackers = 0;
    // modbus_t *ctx;
    // uint8_t tab_reg[coils];
    // uint64_t startExecTime = get_current_time_ms();

    if (ler_config("../configs/controller.json", &p, &hostAttackers, &numAttackers) != 0) {
        fprintf(stderr, "Erro ao ler configuração do arquivo JSON.\n");
        return EXIT_FAILURE;
    }

    for(int i = 0; i < numAttackers; i++) {
        int sock;
        struct sockaddr_in server;

        sock = criar_socket();
        conectar_servidor(sock, hostAttackers[i], 12345, &server);
        enviar_pacote(sock, &p);
        close(sock);
        free(hostAttackers[i]);
    }
    free(hostAttackers);
    printf("Pacotes enviados com sucesso para todos os atacantes.\n");
    
    // while (TRUE)
    // {      
    //     memset(tab_reg, 0, sizeof(tab_reg)); 
    //     ctx = modbus_new_tcp(p.targetHost, 502);

    //     if (ctx == NULL) {
    //         fprintf(stderr, "Erro ao criar contexto Modbus: %s\n", modbus_strerror(errno));
    //         sleep(1); 
    //         continue;
    //     }

    //     modbus_set_response_timeout(ctx, &timeoutLegalQuerier);

    //     if (modbus_connect(ctx) == -1) {
    //         fprintf(stderr, "Falha ao conectar: %s\n", modbus_strerror(errno));
    //         modbus_free(ctx);
    //         sleep(1); 
    //         continue;
    //     }

    //     while (get_current_time_ms() - startExecTime < endOfExperiment) {
    //         printf("Enviando pacote Modbus...\n");
    //         if (p.operation == READ) {
    //             rslt = modbus_read_bits(ctx, 0, array_length(tab_reg), tab_reg);
    //             if (rslt == -1) {
    //                 fprintf(stderr, "Erro em modbus_read_bits: %s\n", modbus_strerror(errno));
    //                 continue;; 
    //             }
    //         } else if (p.operation == WRITE) {
    //             preencher_tab_reg_aleatorio(tab_reg, array_length(tab_reg));
    //             rslt = modbus_write_bits(ctx, 0, array_length(tab_reg), tab_reg);
    //             if (rslt == -1) {
    //                 fprintf(stderr, "Erro em modbus_write_bits: %s\n", modbus_strerror(errno));
    //                 continue;; 
    //             }
    //         }

    //         sleep(delayBtwRequestsLegalQuerier);
    //     }
    //     modbus_close(ctx);
    //     modbus_free(ctx);
    //     printf("Conexão Modbus fechada.\n");
    // }
    
    return 0;
}

int criar_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Erro ao criar socket");
        exit(EXIT_FAILURE);
    }
    return sock;
}

void conectar_servidor(int sock, const char *ip, int porta, struct sockaddr_in *server_addr) {
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(porta);

    if (inet_pton(AF_INET, ip, &server_addr->sin_addr) <= 0) {
        perror("Erro ao converter endereço IP");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("Erro ao conectar");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Conectado a %s:%d\n", ip, porta);
}

void enviar_pacote(int sock, Parametros *p) {
    ssize_t enviados = send(sock, p, sizeof(Parametros), 0);
    if (enviados < 0) {
        perror("Erro ao enviar struct");
        close(sock);
        exit(EXIT_FAILURE);
    } else if ((size_t)enviados < sizeof(Parametros)) {
        fprintf(stderr, "Aviso: struct enviada parcialmente (%zd de %zu bytes)\n",
                enviados, sizeof(Parametros));
    } else {
        printf("Struct enviada com sucesso.\n");
    }
}

int ler_config(const char *filename, Parametros *p, char ***hosts, int *numHosts) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Erro ao abrir config.json");
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);
    char *data = malloc(len + 1);
    if (!data) {
        fprintf(stderr, "Erro ao alocar memória\n");
        fclose(f);
        return -1;
    }
    size_t read_bytes = fread(data, 1, len, f);
    if (read_bytes != (size_t)len) {
        fprintf(stderr, "Erro ao ler arquivo de configuração\n");
        free(data);
        fclose(f);
        return -1;
    }
    data[len] = '\0';
    fclose(f);

    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) {
        fprintf(stderr, "Erro ao fazer parse do JSON\n");
        return -1;
    }

    cJSON *param = cJSON_GetObjectItem(json, "parametros");
    if (!param) { cJSON_Delete(json); return -1; }

    // Corrige o uso do strncpy para garantir terminação nula
    strncpy(p->targetHost, cJSON_GetObjectItem(param, "targetHost")->valuestring, sizeof(p->targetHost) - 1);
    p->targetHost[sizeof(p->targetHost) - 1] = '\0';

    p->startTime = cJSON_GetObjectItem(param, "startTime")->valueint;
    p->floodingPeriod = cJSON_GetObjectItem(param, "floodingPeriod")->valueint;
    p->timeoutAtk = cJSON_GetObjectItem(param, "timeoutAtk")->valuedouble;
    p->delayBtwRequestsAtk = cJSON_GetObjectItem(param, "delayBtwRequestsAtk")->valueint;
    const char *op = cJSON_GetObjectItem(param, "operation")->valuestring;
    p->operation = (strcmp(op, "READ") == 0) ? READ : WRITE;

    cJSON *arr = cJSON_GetObjectItem(json, "hostAttackers");
    *numHosts = cJSON_GetArraySize(arr);
    *hosts = malloc(sizeof(char*) * (*numHosts));
    for (int i = 0; i < *numHosts; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        (*hosts)[i] = strdup(item->valuestring);
    }

    cJSON_Delete(json);
    return 0;
}

// uint64_t get_current_time_ms() {
//     struct timespec ts;
//     clock_gettime(CLOCK_MONOTONIC, &ts);
//     return (uint64_t)(ts.tv_sec) * 1000 + (ts.tv_nsec / 1000000);
// }

// void preencher_tab_reg_aleatorio(uint8_t *tab_reg, size_t tamanho) {
//     int fd = open("/dev/urandom", O_RDONLY);
//     if (fd < 0) {
//         perror("Erro ao abrir /dev/urandom");
//         // fallback para rand()
//         for (size_t i = 0; i < tamanho; i++) {
//             tab_reg[i] = rand() % 2;
//         }
//         return;
//     }
//     ssize_t lidos = read(fd, tab_reg, tamanho);
//     if (lidos < 0) {
//         perror("Erro ao ler /dev/urandom");
//         // fallback para rand()
//         for (size_t i = 0; i < tamanho; i++) {
//             tab_reg[i] = rand() % 2;
//         }
//         close(fd);
//         return;
//     }
//     for (size_t i = 0; i < tamanho; i++) {
//         tab_reg[i] = tab_reg[i] & BIT_MASK;
//     }
//     close(fd);
// }