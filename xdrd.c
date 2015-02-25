/*
 *  xdrd 0.2
 *  Copyright (C) 2013-2014  Konrad Kosmatka
 *  http://fmdx.pl/

 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sha1.h"

#ifdef __WIN32__
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define MSG_NOSIGNAL 0
#define strcasecmp _stricmp
#define LOG_ERR  0
#define LOG_INFO 1
#define DEFAULT_SERIAL "COM3"
#else
#include <termios.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#define closesocket(x) close(x)
#define DEFAULT_SERIAL "/dev/ttyUSB0"
#endif

#define DEFAULT_PORT   7373
#define DEFAULT_USERS  10
#define SERIAL_BUFFER  8192
#define VERSION        "0.2"

#define RDS_BUFF_RDS_LEN sizeof("xxxxyyyyzzzz00")
#define RDS_BUFF_PI_LEN  sizeof("xxxx?")
#define RDS_BUFF_STATE_EMPTY 0
#define RDS_BUFF_STATE_PI    1
#define RDS_BUFF_STATE_RDS   2
#define RDS_BUFF_STATE_PIRDS 3
#define RDS_BUFF_STATE_RDSPI 4

typedef struct rds_buffer
{
    int state;
    char pi[RDS_BUFF_PI_LEN];
    char rds[RDS_BUFF_RDS_LEN];
} rds_buffer_t;

typedef struct user
{
    int fd;
    int auth;
    struct user* next;
    struct user* prev;
} user_t;


typedef struct server
{
#ifdef __WIN32__
    HANDLE serialfd;
#else
    int serialfd;
#endif
    pthread_mutex_t mutex; // users mutex
    pthread_mutex_t mutex_s; // serial mutex
    int background; // run in background
    int guest; // allow users without auth
    char* password; // server password
    int maxusers; // number of allowed users at the same time
    int poweroff; // power tuner off when nobody is connected

    int online; // online users counter
    int online_auth;

    // tuner settings
    int mode;
    int volume;
    int freq;
    int deemphasis;
    int agc;
    int filter;
    int ant;
    int gain;
    int daa;
    int squelch;
    int rotator;

    rds_buffer_t rds;

    user_t* head;
} server_t;

typedef struct thread
{
    int fd;
    char* salt;
    char* ip;
    uint16_t port;
} thread_t;

server_t server;

void show_usage(char*);
void server_log(int prio, char* msg, ...);
void server_init(int);
void* server_thread(void*);
void* server_conn(void*);
void serial_init(char*);
void serial_loop();
void serial_write(char*, int);
user_t* user_add(server_t*, int, int);
void user_remove(server_t*, user_t*);
void msg_parse_client(char*, int);
int msg_parse_serial(char*);
void msg_send(char*, int, int);
char* auth_salt();
int auth_hash(char*, char*, char*);
void tuner_defaults();
void tuner_reset();

int main(int argc, char* argv[])
{
    char serial[50] = DEFAULT_SERIAL;
    int port = DEFAULT_PORT;
    int c;

    server.background = 0;
    server.guest = 0;
    server.password = NULL;
    server.maxusers = DEFAULT_USERS;
    server.online = 0;
    server.online_auth = 0;
    server.head = NULL;

#ifdef __WIN32__
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData))
    {
        server_log(LOG_ERR, "main: WSAStartup");
        exit(EXIT_FAILURE);
    }
#else
    if(getuid() == 0)
    {
        fprintf(stderr, "error: running the server as the root user is a BAD idea, giving up!\n");
        exit(EXIT_FAILURE);
    }
#endif

    while ((c = getopt(argc, argv, "hbgxt:s:u:p:")) != -1)
    {
        switch(c)
        {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);

#ifndef __WIN32__
        case 'b':
            server.background = 1;
            break;
#endif

        case 'g':
            server.guest = 1;
            break;

        case 'x':
            server.poweroff = 1;
            break;

        case 't':
            port = atoi(optarg);
            break;

        case 's':
#ifdef __WIN32__
            snprintf(serial, sizeof(serial), "\\\\.\\%s", optarg);
#else
            snprintf(serial, sizeof(serial), "/dev/%s", optarg);
#endif
            break;

        case 'u':
            server.maxusers = atoi(optarg);
            break;

        case 'p':
            server.password = strdup(optarg);
            break;

        case ':':
        case '?':
            show_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if(port < 1024 || port > 65535)
    {
        fprintf(stderr, "error: the tcp port must be in 1024-65535 range\n");
        show_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if(!server.password || !strlen(server.password))
    {
        fprintf(stderr, "error: no password specified\n");
        show_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

#ifndef __WIN32__
    if(server.background)
    {
        switch(fork())
        {
        case -1:
            server_log(LOG_ERR, "fork");
            exit(EXIT_FAILURE);

        case 0:
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            umask(0);
            break;

        default:
            exit(EXIT_SUCCESS);
        }

        if(setsid() < 0)
        {
            server_log(LOG_ERR, "setsid");
            exit(EXIT_FAILURE);
        }

        if(chdir("/") < 0)
        {
            server_log(LOG_ERR, "chdir");
            exit(EXIT_FAILURE);
        }
    }
#endif
    server_log(LOG_INFO, "xdrd %s is starting using %s and TCP port: %d", VERSION, serial, port);
    server_init(port);
    serial_init(serial);
    serial_loop();
#ifdef __WIN32__
    WSACleanup();
#endif
    return -1;
}

void show_usage(char* arg)
{
    printf("xdrd %s\n", VERSION);
#ifndef __WIN32__
    printf("usage: %s [ -s serial ] [ -t port ] [ -u users ] [ -p password ] [ -hgxb ]\n", arg);
#else
    printf("usage: %s [ -s serial ] [ -t port ] [ -u users ] [ -p password ] [ -hgx ]\n", arg);
#endif
    printf("options:\n");
    printf("  -s  serial port (default %s)\n", DEFAULT_SERIAL);
    printf("  -t  tcp/ip port (default %d)\n", DEFAULT_PORT);
    printf("  -u  max users   (default %d)\n", DEFAULT_USERS);
    printf("  -p  specify password (required)\n");
    printf("  -h  show this help list\n");
    printf("  -g  allow guest login (read-only access)\n");
    printf("  -x  power the tuner off when nobody is connected\n");
#ifndef __WIN32__
    printf("  -b  run server in the background\n");
#endif
}

void server_log(int prio, char* msg, ...)
{
    va_list myargs;
    va_start(myargs, msg);
#ifndef __WIN32__
    if(server.background)
    {
        vsyslog(prio, msg, myargs);
    }
    else
#endif
    {
        switch(prio)
        {
        case LOG_ERR:
            fprintf(stderr, "error: ");
            vfprintf(stderr, msg, myargs);
            fprintf(stderr, "\n");
            break;
        default:
            vfprintf(stdout, msg, myargs);
            fprintf(stdout, "\n");
            break;
        }
    }
    va_end(myargs);
}

void server_init(int port)
{
    int sockfd;
    struct sockaddr_in addr;
    pthread_t thread;

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        server_log(LOG_ERR, "server_init: socket");
        exit(EXIT_FAILURE);
    }

#ifndef __WIN32__
    int value = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&value, sizeof(value)) < 0)
    {
        server_log(LOG_ERR, "server_init: SO_REUSEADDR");
        exit(EXIT_FAILURE);
    }
#endif

    memset((char*)&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if(bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        server_log(LOG_ERR, "server_init: bind");
        exit(EXIT_FAILURE);
    }

    listen(sockfd, 4);

    pthread_mutex_init(&server.mutex, NULL);
    pthread_mutex_init(&server.mutex_s, NULL);

    tuner_reset();

    if(pthread_create(&thread, NULL, server_thread, (void*)(long)sockfd))
    {
        server_log(LOG_ERR, "server_init: pthread_create");
        exit(EXIT_FAILURE);
    }
}

void* server_thread(void* sockfd)
{
    pthread_t thread;
    pthread_attr_t attr;
    int connfd;
    thread_t *t_data;
    struct sockaddr_in dest;
    socklen_t dest_size = sizeof(struct sockaddr_in);

    if(pthread_attr_init(&attr))
    {
        server_log(LOG_ERR, "server_thread: pthread_attr_init");
        exit(EXIT_FAILURE);
    }

    if(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
    {
        server_log(LOG_ERR, "server_thread: pthread_attr_setdetachstate");
        exit(EXIT_FAILURE);
    }

    srand((unsigned)time(NULL));

    while((connfd = accept((int)(long)sockfd, (struct sockaddr *)&dest, &dest_size)) >= 0)
    {
        if(server.online >= server.maxusers)
        {
            closesocket(connfd);
            continue;
        }

        t_data = malloc(sizeof(thread_t));
        t_data->fd = connfd;
        t_data->salt = auth_salt();
        t_data->ip = strdup(inet_ntoa(dest.sin_addr));
        t_data->port = ntohs(dest.sin_port);
        if(pthread_create(&thread, &attr, server_conn, (void*)t_data))
        {
            server_log(LOG_ERR, "server_thread: pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    pthread_attr_destroy(&attr);
    server_log(LOG_ERR, "server_thread: accept");
    exit(EXIT_FAILURE);
    return NULL;
}

void* server_conn(void* t_data)
{
    int connfd = ((thread_t*)t_data)->fd;
    char* salt = ((thread_t*)t_data)->salt;
    char* ip = ((thread_t*)t_data)->ip;
    uint16_t port = ((thread_t*)t_data)->port;

    user_t *u;
    fd_set input;
    char buffer[100], c;
    int pos = 0, auth = 0;

    free(t_data);

    snprintf(buffer, sizeof(buffer), "%s\n", salt);
    send(connfd, buffer, strlen(buffer), MSG_NOSIGNAL);
    if(recv(connfd, buffer, 41, MSG_NOSIGNAL) == 41)
    {
        buffer[40] = 0;
        auth = auth_hash(salt, server.password, buffer);
    }

    free(salt);

    if(!auth && !server.guest)
    {
        snprintf(buffer, sizeof(buffer), "a0\n");
        send(connfd, buffer, strlen(buffer), MSG_NOSIGNAL);
#ifdef __WIN32__
        Sleep(2000);
#endif
        closesocket(connfd);
        free(ip);
        return NULL;
    }

    if(!auth && server.guest)
    {
        snprintf(buffer, sizeof(buffer), "a1\n");
        send(connfd, buffer, strlen(buffer), MSG_NOSIGNAL);
    }

#ifdef __WIN32__
    unsigned long on = 1;
    if (ioctlsocket(connfd, FIONBIO, &on) != NO_ERROR)
    {
        server_log(LOG_ERR, "server_conn: ioctlsocket");
        free(ip);
        exit(EXIT_FAILURE);
    }
#else
    fcntl(connfd, F_SETFL, O_NONBLOCK);
#endif

    server_log(LOG_INFO, "user connected: %s:%u%s", ip, port, (auth ? "" : " (guest)"));

    snprintf(buffer, sizeof(buffer), "M%d\nY%d\nT%d\nD%d\nA%d\nF%d\nZ%d\nG%02d\nV%d\nQ%d\nC%d\n",
             server.mode, server.volume, server.freq, server.deemphasis, server.agc, server.filter, server.ant, server.gain, server.daa, server.squelch, server.rotator);
    send(connfd, buffer, strlen(buffer), MSG_NOSIGNAL);

    u = user_add(&server, connfd, auth);

    snprintf(buffer, sizeof(buffer), "o%d\n", server.online);
    msg_send(buffer, strlen(buffer), -1);

    FD_ZERO(&input);
    FD_SET(u->fd, &input);
    while(select(u->fd+1, &input, NULL, NULL, NULL) > 0)
    {
        if(recv(u->fd, &c, 1, MSG_NOSIGNAL) <= 0)
        {
            break;
        }

        if(c != '\n')
        {
            if(pos == sizeof(buffer)-1)
            {
                // disconnect user when the buffer is full
                break;
            }
            buffer[pos++] = c;
            continue;
        }

        if(buffer[0] == 'X')
        {
            break;
        }

        if(u->auth)
        {
            buffer[pos] = '\n';
            serial_write(buffer, pos+1);
            buffer[pos] = 0;

            msg_parse_client(buffer, u->fd);
        }

        pos = 0;
    }

    user_remove(&server, u);
    if(server.online)
    {
        snprintf(buffer, sizeof(buffer), "o%d\n", server.online);
        msg_send(buffer, strlen(buffer), -1);
    }
    if(!server.online_auth && server.poweroff)
    {
        if(server.online)
        {
            // tell unauthenticated users that XDR is powered off
            sprintf(buffer, "X\n");
            msg_send(buffer, strlen(buffer), -1);
        }
        tuner_reset();
    }
    server_log(LOG_INFO, "user disconnected: %s:%u", ip, port);
    free(ip);
    return NULL;
}

void serial_init(char* path)
{
#ifdef __WIN32__
    server.serialfd = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if(server.serialfd == INVALID_HANDLE_VALUE)
    {
        server_log(LOG_ERR, "serial_init: CreateFile");
        exit(EXIT_FAILURE);
    }
    DCB dcbSerialParams = {0};
    if(!GetCommState(server.serialfd, &dcbSerialParams))
    {
        CloseHandle(server.serialfd);
        server_log(LOG_ERR, "serial_init: GetCommState");
        exit(EXIT_FAILURE);
    }
    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    if(!SetCommState(server.serialfd, &dcbSerialParams))
    {
        CloseHandle(server.serialfd);
        server_log(LOG_ERR, "serial_init: SetCommState");
        exit(EXIT_FAILURE);
    }
#else
    if((server.serialfd = open(path, O_RDWR | O_NOCTTY | O_NDELAY)) < 0)
    {
        server_log(LOG_ERR, "serial_init: open");
        exit(EXIT_FAILURE);
    }

    fcntl(server.serialfd, F_SETFL, 0);
    tcflush(server.serialfd, TCIOFLUSH);

    struct termios options;
    if(tcgetattr(server.serialfd, &options))
    {
        close(server.serialfd);
        server_log(LOG_ERR, "serial_init: tcgetattr");
        exit(EXIT_FAILURE);
    }
    if(cfsetispeed(&options, B115200) || cfsetospeed(&options, B115200))
    {
        close(server.serialfd);
        server_log(LOG_ERR, "serial_init: cfsetspeed");
        exit(EXIT_FAILURE);
    }
    options.c_iflag &= ~(BRKINT | ICRNL | IXON | IMAXBEL);
    options.c_iflag |= IGNBRK;
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG | IEXTEN | ECHOK | ECHOCTL | ECHOKE);
    options.c_oflag &= ~(OPOST | ONLCR);
    options.c_oflag |= NOFLSH;
    options.c_cflag |= CS8;
    options.c_cflag &= ~(CRTSCTS);
    if(tcsetattr(server.serialfd, TCSANOW, &options))
    {
        close(server.serialfd);
        server_log(LOG_ERR, "serial_init: tcsetattr");
        exit(EXIT_FAILURE);
    }
#endif
}

void serial_loop()
{
    char c, buff[SERIAL_BUFFER], buffered[100];
    int pos = 0;

#ifdef __WIN32__
    DWORD len_in = 0;
    BOOL fWaitingOnRead = FALSE;
    DWORD state;
    OVERLAPPED osReader = {0};
    osReader.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (osReader.hEvent == NULL)
    {
        server_log(LOG_ERR, "serial_loop: CreateEvent");
        exit(EXIT_FAILURE);
    }
#else
    fd_set input;
#endif

#ifdef __WIN32__
    while(1)
    {
        if (!fWaitingOnRead)
        {
            if (!ReadFile(server.serialfd, &c, 1, &len_in, &osReader))
            {
                if (GetLastError() != ERROR_IO_PENDING)
                {
                    CloseHandle(osReader.hEvent);
                    break;
                }
                else
                {
                    fWaitingOnRead = TRUE;
                }
            }
        }

        if (fWaitingOnRead)
        {
            state = WaitForSingleObject(osReader.hEvent, 200);
            if(state == WAIT_TIMEOUT)
            {
                continue;
            }
            if(state != WAIT_OBJECT_0)
            {
                CloseHandle(osReader.hEvent);
                break;
            }

            if (!GetOverlappedResult(server.serialfd, &osReader, &len_in, FALSE))
            {
                CloseHandle(osReader.hEvent);
                break;
            }

            fWaitingOnRead = FALSE;
        }
        if(len_in != 1)
        {
            continue;
        }
#else
    FD_ZERO(&input);
    FD_SET(server.serialfd, &input);
    while(select(server.serialfd+1, &input, NULL, NULL, NULL) > 0)
    {
        if(read(server.serialfd, &c, 1) <= 0)
        {
            break;
        }
#endif
        if(c != '\n' && pos != SERIAL_BUFFER-1)
        {
            buff[pos++] = c;
            continue;
        }

        buff[pos] = 0;
        if(msg_parse_serial(buff))
        {
            buff[pos] = '\n';
            msg_send(buff, pos+1, -1);
        }
        else if(buff[0] == 'S') // print RDS buffers
        {
            switch(server.rds.state)
            {
            case RDS_BUFF_STATE_PI:
                snprintf(buffered, sizeof(buffered), "P%s\n%s\n", server.rds.pi, buff);
                msg_send(buffered, strlen(buffered), -1);
                break;

            case RDS_BUFF_STATE_RDS:
                snprintf(buffered, sizeof(buffered), "R%s\n%s\n", server.rds.rds, buff);
                msg_send(buffered, strlen(buffered), -1);
                break;

            case RDS_BUFF_STATE_PIRDS:
                snprintf(buffered, sizeof(buffered), "P%s\nR%s\n%s\n", server.rds.pi, server.rds.rds, buff);
                msg_send(buffered, strlen(buffered), -1);
                break;

            case RDS_BUFF_STATE_RDSPI:
                snprintf(buffered, sizeof(buffered), "R%s\nP%s\n%s\n", server.rds.rds, server.rds.pi, buff);
                msg_send(buffered, strlen(buffered), -1);
                break;
            }
            server.rds.state = RDS_BUFF_STATE_EMPTY;
        }

        pos = 0;
    }
#ifdef __WIN32__
    CloseHandle(server.serialfd);
#else
    close(server.serialfd);
#endif
    server_log(LOG_ERR, "serial_loop");
    exit(EXIT_FAILURE);
}

void serial_write(char* msg, int len)
{
    pthread_mutex_lock(&server.mutex_s);
#ifdef __WIN32__
    OVERLAPPED osWrite = {0};
    DWORD dwWritten;

    osWrite.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if(osWrite.hEvent == NULL)
    {
        server_log(LOG_ERR, "server_conn: CreateEvent");
        exit(EXIT_FAILURE);
    }

    if (!WriteFile(server.serialfd, msg, len, &dwWritten, &osWrite))
    {
        if (GetLastError() == ERROR_IO_PENDING)
        {
            if(WaitForSingleObject(osWrite.hEvent, INFINITE) == WAIT_OBJECT_0)
            {
                GetOverlappedResult(server.serialfd, &osWrite, &dwWritten, FALSE);
            }
        }
    }
    CloseHandle(osWrite.hEvent);
#else
    write(server.serialfd, msg, len);
#endif
    pthread_mutex_unlock(&server.mutex_s);
}

user_t* user_add(server_t* LIST, int fd, int auth)
{
    user_t* new = malloc(sizeof(user_t));
    new->fd = fd;
    new->auth = auth;
    new->prev = NULL;

    pthread_mutex_lock(&LIST->mutex);
    new->next = LIST->head;
    if(LIST->head)
    {
        (LIST->head)->prev = new;
    }
    LIST->head = new;
    LIST->online++;
    LIST->online_auth += auth;
    pthread_mutex_unlock(&LIST->mutex);

    return new;
}

void user_remove(server_t* LIST, user_t* USER)
{
    pthread_mutex_lock(&LIST->mutex);
    if(USER->prev)
    {
        (USER->prev)->next = USER->next;
    }
    else
    {
        LIST->head = USER->next;
    }
    if(USER->next)
    {
        (USER->next)->prev = USER->prev;
    }
    LIST->online--;
    LIST->online_auth -= USER->auth;
    pthread_mutex_unlock(&LIST->mutex);

    closesocket(USER->fd);
    free(USER);
}

void msg_parse_client(char* msg, int fd)
{
    char buff[10];
    int n;

    switch(msg[0])
    {
    case 'M':
        n = atoi(msg+1);
        if(n == 0 || n == 1)
        {
            server.mode = n;
            snprintf(buff, sizeof(buff), "M%d\n", server.mode);
            msg_send(buff, strlen(buff), fd);
        }
        break;

    case 'Y':
        n = atoi(msg+1);
        if(n >= 0 && n <= 100)
        {
            server.volume = n;
            snprintf(buff, sizeof(buff), "Y%d\n", server.volume);
            msg_send(buff, strlen(buff), fd);
        }
        break;

    case 'D':
        n = atoi(msg+1);
        if(n >= 0 && n <= 2)
        {
            server.deemphasis = n;
            snprintf(buff, sizeof(buff), "D%d\n", server.deemphasis);
            msg_send(buff, strlen(buff), fd);
        }
        break;

    case 'A':
        n = atoi(msg+1);
        if(n >= 0 && n <= 3)
        {
            server.agc = n;
            snprintf(buff, sizeof(buff), "A%d\n", server.agc);
            msg_send(buff, strlen(buff), fd);
        }
        break;

    case 'F':
        n = atoi(msg+1);
        if(n >= -1 && n <= 31)
        {
            server.filter = n;
            snprintf(buff, sizeof(buff), "F%d\n", server.filter);
            msg_send(buff, strlen(buff), fd);
        }
        break;

    case 'Z':
        n = atoi(msg+1);
        if(n >= 0 && n <= 3)
        {
            server.ant = n;
            snprintf(buff, sizeof(buff), "Z%d\n", server.ant);
            msg_send(buff, strlen(buff), fd);
            server.rds.state = RDS_BUFF_STATE_EMPTY;
        }
        break;

    case 'G':
        n = atoi(msg+1);
        if(n == 0 || n == 1 || n == 10 || n == 11)
        {
            server.gain = n;
            snprintf(buff, sizeof(buff), "G%02d\n", server.gain);
            msg_send(buff, strlen(buff), fd);
        }
        break;

    case 'V':
        n = atoi(msg+1);
        if(n >= 0 && n < 128)
        {
            server.daa = n;
            snprintf(buff, sizeof(buff), "V%d\n", server.daa);
            msg_send(buff, strlen(buff), fd);
        }
        break;

    case 'Q':
        n = atoi(msg+1);
        if(n >= -1 && n <= 100)
        {
            server.squelch = n;
            snprintf(buff, sizeof(buff), "Q%d\n", server.squelch);
            msg_send(buff, strlen(buff), fd);
        }
        break;

    case 'C':
        n = atoi(msg+1);
        if(n >= 0 && n <= 2)
        {
            server.rotator = n;
            snprintf(buff, sizeof(buff), "C%d\n", server.rotator);
            msg_send(buff, strlen(buff), fd);
        }
        break;
    }
}

int msg_parse_serial(char* msg)
{
    switch(msg[0])
    {
    case 'X':
        tuner_defaults();
        return 1;

    case 'T':
        server.freq = atoi(msg+1);
        server.rds.state = RDS_BUFF_STATE_EMPTY;
        return 1;

    case 'V':
        server.daa = atoi(msg+1);
        return 1;

    case 'C':
        server.rotator = atoi(msg+1);
        return 1;

    case 'P':
        snprintf(server.rds.pi, RDS_BUFF_PI_LEN, "%s", msg+1);
        server.rds.state = ((server.rds.state==RDS_BUFF_STATE_RDS)?RDS_BUFF_STATE_RDSPI:RDS_BUFF_STATE_PI);
        return 0;

    case 'R':
        snprintf(server.rds.rds, RDS_BUFF_RDS_LEN, "%s", msg+1);
        server.rds.state = ((server.rds.state==RDS_BUFF_STATE_PI)?RDS_BUFF_STATE_PIRDS:RDS_BUFF_STATE_RDS);
        return 0;

    case 'S':
        return (server.rds.state == RDS_BUFF_STATE_EMPTY);
    }
    return -1;
}

void msg_send(char* msg, int len, int ignore_fd)
{
    int sent, n;
    user_t *u;

    pthread_mutex_lock(&server.mutex);
    for(u = server.head; u; u=u->next)
    {
        if(u->fd == ignore_fd)
        {
            continue;
        }
        if(server.guest || u->auth)
        {
            sent = 0;
            do
            {
                n = send(u->fd, msg+sent, len-sent, MSG_NOSIGNAL);
                if(n < 0)
                {
                    shutdown(u->fd, 2);
                    break;
                }
                sent += n;
            }
            while(sent<len);
        }
    }
    pthread_mutex_unlock(&server.mutex);
}

char* auth_salt()
{
    char chars[] = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789";
    char* salt = (char*)malloc(sizeof(char)*17);
    int i;
    for(i=0; i<16; i++)
    {
        salt[i] = chars[rand()%strlen(chars)];
    }
    salt[i] = 0;
    return salt;
}

int auth_hash(char* salt, char* password, char* hash)
{
    unsigned char sha[SHA1_DIGEST_SIZE];
    char sha_string[SHA1_DIGEST_SIZE*2+1];
    int i;

    SHA1_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char*)salt, strlen(salt));
    SHA1_Update(&ctx, (unsigned char*)password, strlen(password));
    SHA1_Final(&ctx, sha);

    for(i=0; i<SHA1_DIGEST_SIZE; i++)
    {
        sprintf(sha_string+(i*2), "%02x", sha[i]);
    }

    return (strcasecmp(hash, sha_string) == 0);
}

void tuner_defaults()
{
    server.mode = 0;
    server.volume = 100;
    server.freq = 87500;
    server.deemphasis = 0;
    server.agc = 2;
    server.filter = -1;
    server.ant = 0;
    server.gain = 0;
    server.daa = 0;
    server.squelch = 0;
    server.rotator = 0;
    server.rds.state = RDS_BUFF_STATE_EMPTY;
}

void tuner_reset()
{
    pthread_mutex_lock(&server.mutex_s);
#ifdef __WIN32__
    // restart Arduino using RTS & DTR lines
    EscapeCommFunction(server.serialfd, CLRDTR);
    EscapeCommFunction(server.serialfd, CLRRTS);
    Sleep(10);
    EscapeCommFunction(server.serialfd, SETDTR);
    EscapeCommFunction(server.serialfd, SETRTS);
#else
    int ctl;
    // restart Arduino using RTS & DTR lines
    if(ioctl(server.serialfd, TIOCMGET, &ctl) != -1)
    {
        ctl &= ~(TIOCM_DTR | TIOCM_RTS);
        ioctl(server.serialfd, TIOCMSET, &ctl);
        usleep(10000);
        ctl |=  (TIOCM_DTR | TIOCM_RTS);
        ioctl(server.serialfd, TIOCMSET, &ctl);
    }
#endif
    tuner_defaults();
    pthread_mutex_unlock(&server.mutex_s);
}
