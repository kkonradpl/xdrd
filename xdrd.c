/*
 *  xdrd 0.1
 *  Copyright (C) 2013-2014  Konrad Kosmatka
 *  http://redakcja.radiopolska.pl/konrad/

 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  Compile with:
 *  gcc -Wall -O2 xdrd.c sha1.c -o xdrd -lpthread
 */

#include <stdlib.h>
#include <stdio.h>
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
#else
#include <termios.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#endif

#ifdef __WIN32__
#define DEFAULT_SERIAL "COM3"
#else
#define DEFAULT_SERIAL "/dev/ttyUSB0"
#endif

#define DEFAULT_PORT   7373
#define DEFAULT_USERS  10
#define SERIAL_BUFFER  8192
#define VERSION        "0.1"

struct user
{
    int fd;
    int auth;
    struct user* next;
    struct user* prev;
};

struct list
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

    // tuner settings
    int mode;
    int volume;
    int freq;
    int deemphasis;
    int agc;
    int filter;
    int ant;
    int gain;

    struct user* head;
};

struct thread_data
{
    int fd;
    char* salt;
};

struct list server;

void show_usage(char*);
void error(char*);
void server_init(int);
void* server_thread(void*);
void* server_conn(void*);
void serial_init(char*);
void serial_loop();
void serial_write(char*, int);
struct user* list_add(struct list*, int, int);
void list_remove(struct list*, struct user*);
void msg_parse_client(char*, int);
void msg_parse_serial(char*);
void msg_send(char*, int, int);
char* auth_salt();
int auth_hash(char*, char*, char*);
void tuner_defaults();

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
    server.head = NULL;

#ifdef __WIN32__
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData))
    {
        error("main: WSAStartup");
    }
#else
    if(getuid() == 0)
    {
        fprintf(stderr, "running the server as the root user is a BAD idea, giving up!\n");
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
            error("fork");

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
            error("setsid");
        }

        if(chdir("/") < 0)
        {
            error("chdir");
        }
    }
    else
#endif
    {
        printf("xdrd %s is starting using %s and TCP port: %d...\n", VERSION, serial, port);
    }

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
    printf("usage: %s [ -s serial ] [ -t port ] [ -u users ] [ -p password ] [ -hgxb ]\n", arg);
    printf("options:\n");
#ifdef __WIN32__
    printf("  -s  serial port (default COM3)\n");
#else
    printf("  -s  serial port (default ttyUSB0)\n");
#endif
    printf("  -t  tcp/ip port (default 7373)\n");
    printf("  -u  max users   (default 10)\n");
    printf("  -p  specify password (required)\n");
    printf("  -h  show this help list\n");
    printf("  -g  allow guest login (read-only access)\n");
    printf("  -x  power the tuner off when nobody is connected\n");
#ifndef __WIN32__
    printf("  -b  run server in the background\n");
#endif
}

void error(char* msg)
{
#ifndef __WIN32__
    if(server.background)
    {
        syslog(LOG_ERR, "error: %s", msg);
    }
    else
#endif
    {
        fprintf(stderr, "error: %s\n", msg);
    }
    exit(EXIT_FAILURE);
}

void server_init(int port)
{
    int sockfd;

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        error("server_init: socket");
    }

#ifndef __WIN32__
    int value = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&value, sizeof(value)) < 0)
    {
        error("server_init: SO_REUSEADDR");
    }
#endif

    struct sockaddr_in addr;
    memset((char*)&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if(bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        error("server_init: bind");
    }

    listen(sockfd, 4);

    pthread_mutex_init(&server.mutex, NULL);
    pthread_mutex_init(&server.mutex_s, NULL);

    tuner_defaults();

    pthread_t thread;
    int* sock = (int*)malloc(sizeof(int));
    *sock = sockfd;
    if(pthread_create(&thread, NULL, server_thread, (void*)sock))
    {
        error("server_init: pthread_create");
    }
}

void* server_thread(void* sockfd)
{
    pthread_t thread;
    pthread_attr_t attr;
    int connfd;

    srand((unsigned)time(NULL));

    while((connfd = accept(*((int*)sockfd), (struct sockaddr*)NULL, NULL)) >= 0)
    {
        if(server.online >= server.maxusers)
        {
#ifdef __WIN32__
            closesocket(connfd);
#else
            close(connfd);
#endif
            continue;
        }

        if(pthread_attr_init(&attr))
        {
            error("server_thread: pthread_attr_init");
        }

        if(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        {
            error("server_thread: pthread_attr_setdetachstate");
        }

        struct thread_data *t_data = malloc(sizeof(struct thread_data));
        t_data->fd = connfd;
        t_data->salt = auth_salt();
        if(pthread_create(&thread, &attr, server_conn, (void*)t_data))
        {
            error("server_thread: pthread_create");
        }
    }

    free(sockfd);
    error("server_thread: accept");
    return NULL;
}

void* server_conn(void* t_data)
{
    int connfd = ((struct thread_data*)t_data)->fd;
    char* salt = ((struct thread_data*)t_data)->salt;

    struct user *u;
    fd_set input;
    char buffer[50], c;
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
        closesocket(connfd);
#else
        close(connfd);
#endif
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
        error("server_conn: ioctlsocket");
    }
#else
    fcntl(connfd, F_SETFL, O_NONBLOCK);
#endif

    snprintf(buffer, sizeof(buffer), "OK\nM%d\nY%d\nT%d\nD%d\nA%d\nF%d\nZ%d\nG%02d\n",
             server.mode, server.volume, server.freq, server.deemphasis, server.agc, server.filter, server.ant, server.gain);
    send(connfd, buffer, strlen(buffer), MSG_NOSIGNAL);

    u = list_add(&server, connfd, auth);

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

    list_remove(&server, u);
    if(server.online)
    {
        snprintf(buffer, sizeof(buffer), "o%d\n", server.online);
        msg_send(buffer, strlen(buffer), -1);
    }
    else if(server.poweroff)
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
        pthread_mutex_unlock(&server.mutex_s);
        tuner_defaults();
    }
    return NULL;
}

void serial_init(char* path)
{
#ifdef __WIN32__
    server.serialfd = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if(server.serialfd == INVALID_HANDLE_VALUE)
    {
        error("serial_init: CreateFile");
    }
    DCB dcbSerialParams = {0};
    if(!GetCommState(server.serialfd, &dcbSerialParams))
    {
        error("serial_init: GetCommState");
    }
    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    if(!SetCommState(server.serialfd, &dcbSerialParams))
    {
        error("serial_init: SetCommState");
    }
#else
    if((server.serialfd = open(path, O_RDWR | O_NOCTTY | O_NDELAY)) < 0)
    {
        error("serial_init: open");
    }

    fcntl(server.serialfd, F_SETFL, 0);
    tcflush(server.serialfd, TCIOFLUSH);

    struct termios options;
    if(tcgetattr(server.serialfd, &options))
    {
        error("serial_init: tcgetattr");
    }
    if(cfsetispeed(&options, B115200) || cfsetospeed(&options, B115200))
    {
        error("serial_init: cfsetspeed");
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
        error("serial_init: tcsetattr");
    }
#endif
}

void serial_loop()
{
    char c, buff[SERIAL_BUFFER];
    int pos = 0;

#ifdef __WIN32__
    DWORD len_in = 0;
    BOOL fWaitingOnRead = FALSE;
    DWORD state;
    OVERLAPPED osReader = {0};
    osReader.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (osReader.hEvent == NULL)
    {
        error("serial_loop: CreateEvent");
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
        msg_parse_serial(buff);

        buff[pos] = '\n';
        msg_send(buff, pos+1, -1);

        pos = 0;
    }
#ifdef __WIN32__
    CloseHandle(server.serialfd);
#else
    close(server.serialfd);
#endif
    error("serial_loop");
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
        error("server_conn: CreateEvent");
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

struct user* list_add(struct list* LIST, int fd, int auth)
{
    struct user* new = malloc(sizeof(struct user));
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
    pthread_mutex_unlock(&LIST->mutex);

    return new;
}

void list_remove(struct list* LIST, struct user* USER)
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
    pthread_mutex_unlock(&LIST->mutex);

#ifdef __WIN32__
    closesocket(USER->fd);
#else
    close(USER->fd);
#endif
    free(USER);
    LIST->online--;
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
        if(n >= 0 && n <= 2047)
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
    }
}

void msg_parse_serial(char* msg)
{
    switch(msg[0])
    {
    case 'X':
        tuner_defaults();
        break;

    case 'T':
        server.freq = atoi(msg+1);
        break;
    }
}

void msg_send(char* msg, int len, int ignore_fd)
{
    pthread_mutex_lock(&server.mutex);
    struct user *u = server.head;
    while(u)
    {
        if(u->fd != ignore_fd)
        {
            if(server.guest || u->auth)
            {
                if(send(u->fd, msg, len, MSG_NOSIGNAL) < 0)
                {
                    shutdown(u->fd, 2);
                }
            }
        }
        u=u->next;
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

    return (strcmp(hash, sha_string) == 0);
}

void tuner_defaults()
{
    server.mode = 0;
    server.volume = 2047;
    server.freq = 87500;
    server.deemphasis = 0;
    server.agc = 2;
    server.filter = -1;
    server.gain = 0;
}
