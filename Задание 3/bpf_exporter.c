#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>

#define DEFAULT_PORT 9100
#define BUFFER_SIZE 4096

/*
 * Данные, которые приходят из bpftrace.
 */
struct metrics {
    unsigned long long processes;
    unsigned long long scheduler_switches;
    unsigned long long interrupts;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned long long fs_io_bytes;
};

/*
 * Общая структура метрик.
 *
 * bpftrace-поток пишет сюда,
 * HTTP-поток читает отсюда.
 */
static struct metrics current_metrics;

static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

static volatile sig_atomic_t stop_requested = 0;

static int server_fd = -1;

/*
 * Обработка SIGINT/SIGTERM.
 */
static void handle_signal(int signal)
{
    (void)signal;
    stop_requested = 1;

    /*
     * close() из signal handler формально не является
     * идеальным вариантом с точки зрения async-signal-safety,
     * поэтому здесь просто меняем флаг.
     *
     * server socket имеет SO_RCVTIMEO, поэтому accept()
     * периодически просыпается и проверяет stop_requested.
     */
}

/*
 * Обновить одну метрику.
 */
static void update_metric(const char *name,
                          unsigned long long value)
{
    pthread_mutex_lock(&metrics_mutex);

    if (strcmp(name, "processes") == 0) {
        current_metrics.processes = value;
    }
    else if (strcmp(name, "scheduler_switches") == 0) {
        current_metrics.scheduler_switches = value;
    }
    else if (strcmp(name, "interrupts") == 0) {
        current_metrics.interrupts = value;
    }
    else if (strcmp(name, "rx_bytes") == 0) {
        current_metrics.rx_bytes = value;
    }
    else if (strcmp(name, "tx_bytes") == 0) {
        current_metrics.tx_bytes = value;
    }
    else if (strcmp(name, "fs_io_bytes") == 0) {
        current_metrics.fs_io_bytes = value;
    }

    pthread_mutex_unlock(&metrics_mutex);
}

/*
 * Поток, который читает stdout bpftrace.
 *
 * Ожидаемый вывод:
 *
 * processes 123
 * scheduler_switches 45678
 * interrupts 12345
 * rx_bytes 123456
 * tx_bytes 654321
 * fs_io_bytes 99999
 */
static void *bpftrace_reader(void *arg)
{
    FILE *pipe = (FILE *)arg;

    char line[BUFFER_SIZE];

    while (!stop_requested &&
           fgets(line, sizeof(line), pipe) != NULL) {

        char name[128];
        unsigned long long value;

        /*
         * Разбираем:
         *
         * <имя> <значение>
         */
        if (sscanf(line,
                   "%127s %llu",
                   name,
                   &value) == 2) {

            update_metric(name, value);

            /*
             * Можно раскомментировать для отладки:
             *
             * fprintf(stderr,
             *         "bpftrace: %s = %llu\n",
             *         name, value);
             */
        }
    }

    if (!stop_requested) {
        fprintf(stderr,
                "bpftrace process finished or stdout was closed\n");
    }

    return NULL;
}

/*
 * Создаём snapshot метрик.
 *
 * Это важно: не держим mutex во время отправки HTTP.
 */
static struct metrics get_metrics_snapshot(void)
{
    struct metrics snapshot;

    pthread_mutex_lock(&metrics_mutex);

    snapshot = current_metrics;

    pthread_mutex_unlock(&metrics_mutex);

    return snapshot;
}

/*
 * Отправка HTTP ответа.
 */
static void send_http_response(int client_fd,
                               const char *content_type,
                               const char *body)
{
    char header[1024];

    size_t body_length = strlen(body);

    int header_length = snprintf(
        header,
        sizeof(header),

        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",

        content_type,
        body_length
    );

    if (header_length <= 0) {
        return;
    }


send(client_fd,
         header,
         (size_t)header_length,
         0);

    send(client_fd,
         body,
         body_length,
         0);
}

/*
 * 404.
 */
static void send_404(int client_fd)
{
    const char *body =
        "404 Not Found\n";

    char header[512];

    int header_length = snprintf(
        header,
        sizeof(header),

        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",

        strlen(body)
    );

    send(client_fd,
         header,
         (size_t)header_length,
         0);

    send(client_fd,
         body,
         strlen(body),
         0);
}

/*
 * Формируем Prometheus metrics.
 *
 * Используется Prometheus text exposition format.
 */
static void build_metrics_response(char *buffer,
                                   size_t buffer_size)
{
    struct metrics m = get_metrics_snapshot();

    snprintf(
        buffer,
        buffer_size,

        /*
         * processes в твоём bpftrace на самом деле
         * является количеством fork/exec событий,
         * поэтому называем его process_events_total.
         */
        "# HELP ebpf_process_events_total Number of process fork/exec events observed by eBPF\n"
        "# TYPE ebpf_process_events_total counter\n"
        "ebpf_process_events_total %llu\n"
        "\n"

        "# HELP ebpf_scheduler_switches_total Number of scheduler context switches\n"
        "# TYPE ebpf_scheduler_switches_total counter\n"
        "ebpf_scheduler_switches_total %llu\n"
        "\n"

        "# HELP ebpf_interrupts_total Number of interrupt handler entries\n"
        "# TYPE ebpf_interrupts_total counter\n"
        "ebpf_interrupts_total %llu\n"
        "\n"

        "# HELP ebpf_network_receive_bytes_total Number of received network bytes\n"
        "# TYPE ebpf_network_receive_bytes_total counter\n"
        "ebpf_network_receive_bytes_total %llu\n"
        "\n"

        "# HELP ebpf_network_transmit_bytes_total Number of transmitted network bytes\n"
        "# TYPE ebpf_network_transmit_bytes_total counter\n"
        "ebpf_network_transmit_bytes_total %llu\n"
        "\n"

        "# HELP ebpf_filesystem_io_bytes_total Number of filesystem/block I/O bytes\n"
        "# TYPE ebpf_filesystem_io_bytes_total counter\n"
        "ebpf_filesystem_io_bytes_total %llu\n",

        m.processes,
        m.scheduler_switches,
        m.interrupts,
        m.rx_bytes,
        m.tx_bytes,
        m.fs_io_bytes
    );
}

/*
 * Обработка одного HTTP клиента.
 */
static void handle_http_client(int client_fd)
{
    char request[BUFFER_SIZE];

    ssize_t received = recv(
        client_fd,
        request,
        sizeof(request) - 1,
        0
    );

    if (received <= 0) {
        return;
    }

    request[received] = '\0';

    /*
     * Нас интересует:
     *
     * GET /metrics HTTP/1.1
     */
    if (strncmp(request,
                "GET /metrics ",
                strlen("GET /metrics ")) == 0) {

        char response[8192];

        build_metrics_response(
            response,
            sizeof(response)
        );

        /*
         * Prometheus text format.
         *
         * Prometheus требует корректный Content-Type
         * для endpoint метрик.
         */
        send_http_response(
            client_fd,
            "text/plain; version=0.0.4; charset=utf-8",
            response
        );
    }
    else if (strncmp(request,
                     "GET / ",
                     strlen("GET / ")) == 0) {

        const char *body =
            "eBPF Prometheus exporter is running\n"
            "\n"
            "Metrics: /metrics\n";

        send_http_response(
            client_fd,
            "text/plain; charset=utf-8",
            body
        );
    }
    else {
        send_404(client_fd);
    }
}

/*
 * Создание HTTP сервера.
 */
static int create_server(int port)
{
    int fd;

    fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (fd < 0) {
        perror("socket");
        return -1;
    }


/*
     * Позволяем сразу перезапустить exporter
     * после остановки.
     */
    int reuse = 1;

    if (setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            sizeof(reuse)) < 0) {

        perror("setsockopt(SO_REUSEADDR)");
        close(fd);
        return -1;
    }

    /*
     * Timeout для accept().
     *
     * Благодаря этому программа регулярно проверяет
     * stop_requested.
     */
    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            sizeof(timeout)) < 0) {

        perror("setsockopt(SO_RCVTIMEO)");
        close(fd);
        return -1;
    }

    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)port);

    if (bind(
            fd,
            (struct sockaddr *)&address,
            sizeof(address)) < 0) {

        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * main
 *
 * Использование:
 *
 *     ./exporter ./processes.bt
 *
 * или:
 *
 *     sudo ./exporter ./processes.bt
 */
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(
            stderr,
            "Usage: %s <bpftrace_script> [port]\n",
            argv[0]
        );

        fprintf(
            stderr,
            "\nExample:\n"
            "    sudo %s ./processes.bt\n"
            "    sudo %s ./processes.bt 9100\n\n",
            argv[0],
            argv[0]
        );

        return EXIT_FAILURE;
    }

    const char *script = argv[1];

    int port = DEFAULT_PORT;

    if (argc >= 3) {
        port = atoi(argv[2]);

        if (port <= 0 || port > 65535) {
            fprintf(stderr,
                    "Invalid port: %s\n",
                    argv[2]);

            return EXIT_FAILURE;
        }
    }

    /*
     * Обработчики сигналов.
     */
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_signal;

    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /*
     * Формируем команду bpftrace.
     *
     * ВАЖНО:
     *
     * script передаётся пользователем, поэтому здесь
     * намеренно используется простая конструкция.
     *
     * Для имени файла без пробелов этого достаточно.
     */
    char command[1024];

    snprintf(
        command,
        sizeof(command),
        "stdbuf -oL -eL bpftrace -q \"%s\" 2>&1",
        script
    );

    printf(
        "Starting bpftrace:\n"
        "  %s\n\n",
        command
    );

    /*
     * Запускаем bpftrace.
     *
     * stdout bpftrace становится FILE*.
     */
    FILE *pipe = popen(command, "r");

    if (pipe == NULL) {
        perror("popen");

        return EXIT_FAILURE;
    }

    /*
     * Запускаем поток чтения bpftrace.
     */
    pthread_t reader_thread;

    if (pthread_create(
            &reader_thread,
            NULL,
            bpftrace_reader,
            pipe) != 0) {

        perror("pthread_create");

        pclose(pipe);

        return EXIT_FAILURE;
    }

    /*
     * Запускаем HTTP сервер.
     */
    server_fd = create_server(port);

    if (server_fd < 0) {
        stop_requested = 1;

        pthread_cancel(reader_thread);
        pthread_join(reader_thread, NULL);

        pclose(pipe);

        return EXIT_FAILURE;
    }

    printf(
        "eBPF Prometheus exporter started\n"
        "Prometheus endpoint: http://localhost:%d/metrics\n"
        "\n"
        "Press Ctrl+C to stop.\n\n",
        port
    );

    /*
     * Основной HTTP loop.
     */
    while (!stop_requested) {

        struct sockaddr_in client_address;

        socklen_t client_length =
            sizeof(client_address);

        int client_fd = accept(
            server_fd,
            (struct sockaddr


*)&client_address,
            &client_length
        );

        if (client_fd < 0) {

            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN ||
                errno == EWOULDBLOCK) {

                continue;
            }

            if (stop_requested) {
                break;
            }

            perror("accept");

            continue;
        }

        handle_http_client(client_fd);

        close(client_fd);
    }

    /*
     * Останавливаемся.
     */
    printf("\nStopping exporter...\n");

    stop_requested = 1;

    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }

    /*
     * Ждём reader.
     *
     * bpftrace может ещё находиться в popen().
     */
    pthread_cancel(reader_thread);

    pthread_join(
        reader_thread,
        NULL
    );

    /*
     * Закрываем pipe.
     *
     * Это также завершает bpftrace child process.
     */
    pclose(pipe);

    pthread_mutex_destroy(&metrics_mutex);

    printf("Exporter stopped.\n");

   return EXIT_SUCCESS;

}
