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
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <modbus.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>    
#include <unistd.h>   

#pragma pack(1)

#define array_length(arr) (sizeof(arr) / sizeof((arr)[0]))
#define TARGET_HOST_MAXLEN 20
#define TRUE 1
#define BIT_MASK 0x01
#define LOG_FILE "../logs/modbus_log.csv"

typedef struct {
    int portaServidor;
    int portaModbus;
    int coils;
} Config;

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
int conectar_servidor(int sock, const char *ip, int porta, struct sockaddr_in *server_addr);
int enviar_pacote(int sock, Parametros *p);
int ler_config(const char *filename, Config *cfg, Parametros *p, char ***hosts, int *numHosts);
uint64_t get_current_time_ms();
void preencher_tab_reg_aleatorio(uint8_t *tab_reg, size_t tamanho);
void salvar_log_csv(const char *arquivo, const char *operacao, const char *status);

int main() {
    FILE *fp = fopen(LOG_FILE, "r");
    if (!fp) {
        fp = fopen(LOG_FILE, "w");
        if (fp) {
            fprintf(fp, "\"timestamp\",\"operacao\",\"status\"\n");
            fclose(fp);
        }
    }

    Parametros p;
    Config cfg;
    char **hostAttackers = NULL;
    int numAttackers = 0, sock;

    if (ler_config("../configs/controller.json", &cfg, &p, &hostAttackers, &numAttackers) != 0) {
        fprintf(stderr, "Erro ao ler configuração do arquivo JSON.\n");
        return EXIT_FAILURE;
    }


    modbus_t *ctx;
    uint8_t tab_reg[cfg.coils];
    uint64_t startExecTime = get_current_time_ms();
    uint64_t endOfExperiment = startExecTime + p.floodingPeriod;
    unsigned int delayBtwRequestsLegalQuerier = p.delayBtwRequestsAtk;
    const uint32_t timeoutLegalQuerier = 1000;

    for (int i = 0; i < numAttackers; i++) {
        struct sockaddr_in server;

        while ((sock = criar_socket()) < 0) {
            perror("Erro ao criar socket. Tentando novamente...");
            sleep(1); // evita uso excessivo da CPU
        }

        while (conectar_servidor(sock, hostAttackers[i], cfg.portaServidor, &server) < 0) {
            perror("Erro ao conectar com o servidor. Tentando novamente...");
            close(sock); 
            sleep(1);
            while ((sock = criar_socket()) < 0) {
                perror("Erro ao recriar socket após falha de conexão. Tentando novamente...");
                sleep(1);
            }
        }

        while (enviar_pacote(sock, &p) < 0) {
            perror("Erro ao enviar pacote. Tentando novamente...");
            sleep(1);
        }

        close(sock);
        free(hostAttackers[i]);
    }

    free(hostAttackers);
    printf("Pacotes enviados com sucesso para todos os atacantes.\n");
    
    while (TRUE)
    {      
        memset(tab_reg, 0, sizeof(tab_reg)); 
        ctx = modbus_new_tcp(p.targetHost, cfg.portaModbus);

        if (ctx == NULL) {
            fprintf(stderr, "Erro ao criar contexto Modbus: %s\n", modbus_strerror(errno));
            sleep(1); 
            continue;
        }

        modbus_set_response_timeout(ctx, 0, timeoutLegalQuerier);

        if (modbus_connect(ctx) == -1) {
            fprintf(stderr, "Falha ao conectar: %s\n", modbus_strerror(errno));
            modbus_free(ctx);
            sleep(1); 
            continue;
        }

        while (get_current_time_ms() - startExecTime < endOfExperiment) {
            printf("Enviando pacote Modbus...\n");
            if (p.operation == READ) {
                if (modbus_read_bits(ctx, 0, array_length(tab_reg), tab_reg) == -1) {
                    fprintf(stderr, "Erro em modbus_read_bits: %s\n", modbus_strerror(errno));
                    salvar_log_csv(LOG_FILE, "READ", "ERRO");
                    continue;
                }
                else salvar_log_csv(LOG_FILE, "READ", "SUCESSO");
            } else if (p.operation == WRITE) {
                preencher_tab_reg_aleatorio(tab_reg, array_length(tab_reg));
                if (modbus_write_bits(ctx, 0, array_length(tab_reg), tab_reg) == -1) {
                    fprintf(stderr, "Erro em modbus_write_bits: %s\n", modbus_strerror(errno));
                    salvar_log_csv(LOG_FILE, "WRITE", "ERRO");
                    continue;
                }
                else salvar_log_csv(LOG_FILE, "WRITE", "SUCESSO");
            }

            sleep(delayBtwRequestsLegalQuerier);
        }

        modbus_close(ctx);
        modbus_free(ctx);
        printf("Conexão Modbus fechada.\n");
    }
    
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

int conectar_servidor(int sock, const char *ip, int porta, struct sockaddr_in *server_addr) {
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(porta);

    if (inet_pton(AF_INET, ip, &server_addr->sin_addr) <= 0) {
        perror("Erro ao converter endereço IP");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("Erro ao conectar");
        return -1;
    }

    printf("Conectado a %s:%d\n", ip, porta);
    return 0;
}

int enviar_pacote(int sock, Parametros *p) {
    ssize_t enviados = send(sock, p, sizeof(Parametros), 0);
    if (enviados < 0) {
        perror("Erro ao enviar struct");
        return -1;
    } else if ((size_t)enviados < sizeof(Parametros)) {
        fprintf(stderr, "Aviso: struct enviada parcialmente (%zd de %zu bytes)\n",
                enviados, sizeof(Parametros));
        return -1;
    } else {
        printf("Struct enviada com sucesso.\n");
        return 0;
    }
}

int ler_config(const char *filename, Config *cfg, Parametros *p, char ***hosts, int *numHosts) {
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
    fclose(f);
    if (read_bytes != (size_t)len) {
        fprintf(stderr, "Erro ao ler arquivo de configuração\n");
        free(data);
        return -1;
    }
    data[len] = '\0';

    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) {
        fprintf(stderr, "Erro ao fazer parse do JSON\n");
        return -1;
    }

    // ------------------ Lê o bloco "config" ------------------
    cJSON *config = cJSON_GetObjectItem(json, "config");
    if (!cJSON_IsObject(config)) {
        fprintf(stderr, "Campo 'config' ausente ou inválido\n");
        cJSON_Delete(json);
        return -1;
    }

    cJSON *portaServ = cJSON_GetObjectItem(config, "portaServidor");
    cJSON *portaMod = cJSON_GetObjectItem(config, "portaModbus");
    cJSON *coils = cJSON_GetObjectItem(config, "coils");

    if (!cJSON_IsNumber(portaServ) || !cJSON_IsNumber(portaMod) || !cJSON_IsNumber(coils)) {
        fprintf(stderr, "Valores inválidos em 'config'\n");
        cJSON_Delete(json);
        return -1;
    }

    cfg->portaServidor = portaServ->valueint;
    cfg->portaModbus   = portaMod->valueint;
    cfg->coils         = coils->valueint;

    // ------------------ Lê o bloco "parametros" ------------------
    cJSON *param = cJSON_GetObjectItem(json, "parametros");
    if (!cJSON_IsObject(param)) {
        fprintf(stderr, "Campo 'parametros' ausente ou inválido\n");
        cJSON_Delete(json);
        return -1;
    }

    cJSON *hostItem = cJSON_GetObjectItem(param, "targetHost");
    if (!cJSON_IsString(hostItem)) goto erro_param;
    strncpy(p->targetHost, hostItem->valuestring, sizeof(p->targetHost) - 1);
    p->targetHost[sizeof(p->targetHost) - 1] = '\0';

    cJSON *start = cJSON_GetObjectItem(param, "startTime");
    cJSON *period = cJSON_GetObjectItem(param, "floodingPeriod");
    cJSON *timeout = cJSON_GetObjectItem(param, "timeoutAtk");
    cJSON *delay = cJSON_GetObjectItem(param, "delayBtwRequestsAtk");
    cJSON *op = cJSON_GetObjectItem(param, "operation");

    if (!cJSON_IsNumber(start) || !cJSON_IsNumber(period) ||
        !cJSON_IsNumber(timeout) || !cJSON_IsNumber(delay) || !cJSON_IsString(op)) {
        goto erro_param;
    }

    p->startTime = start->valueint;
    p->floodingPeriod = period->valueint;
    p->timeoutAtk = timeout->valuedouble;
    p->delayBtwRequestsAtk = delay->valueint;
    p->operation = (strcmp(op->valuestring, "READ") == 0) ? READ : WRITE;

    // ------------------ Lê o bloco "hostAttackers" ------------------
    cJSON *arr = cJSON_GetObjectItem(json, "hostAttackers");
    if (!cJSON_IsArray(arr)) {
        fprintf(stderr, "Campo 'hostAttackers' ausente ou inválido\n");
        goto erro_json;
    }

    *numHosts = cJSON_GetArraySize(arr);
    *hosts = malloc(sizeof(char*) * (*numHosts));
    if (!*hosts) {
        fprintf(stderr, "Erro ao alocar memória para hosts\n");
        goto erro_json;
    }

    for (int i = 0; i < *numHosts; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        if (!cJSON_IsString(item)) {
            fprintf(stderr, "Host inválido no índice %d\n", i);
            goto erro_hosts;
        }
        (*hosts)[i] = strdup(item->valuestring);
        if (!(*hosts)[i]) {
            fprintf(stderr, "Erro ao duplicar host\n");
            goto erro_hosts;
        }
    }

    cJSON_Delete(json);
    return 0;

erro_hosts:
    for (int i = 0; i < *numHosts; i++) {
        if ((*hosts)[i]) free((*hosts)[i]);
    }
    free(*hosts);
    *hosts = NULL;
erro_param:
    fprintf(stderr, "Erro ao extrair campos de 'parametros'\n");
erro_json:
    cJSON_Delete(json);
    return -1;
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

void salvar_log_csv(const char *arquivo, const char *operacao, const char *status) {
    FILE *fp = fopen(arquivo, "a");
    if (!fp) {
        perror("Erro ao abrir arquivo de log CSV");
        return;
    }

    time_t agora = time(NULL);
    struct tm *infoTempo = localtime(&agora);
    char horario[64];
    strftime(horario, sizeof(horario), "%Y-%m-%d %H:%M:%S", infoTempo);

    fprintf(fp, "\"%s\",\"%s\",\"%s\"\n", horario, operacao, status);
    fclose(fp);
}
