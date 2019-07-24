/*
 *  xdrd 1.0-git
 *  Copyright (C) 2013-2017  Konrad Kosmatka
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

#ifdef __WIN32__
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#define strcasecmp _stricmp
#define MSG_NOSIGNAL 0
#define LOG_ERR  0
#define LOG_INFO 1
#define DEFAULT_SERIAL "COM3"
#define BACKGROUND_EXEC "START /MIN cmd /c "
#endif

#define _GNU_SOURCE
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
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "xdr-protocol.h"

#ifndef __WIN32__
#include <termios.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#define DEFAULT_SERIAL "/dev/ttyUSB0"
#endif

#define VERSION       "1.0-git"
#define DEFAULT_USERS 10
#define SERIAL_BUFFER 8192

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

    char* f_exec; // command to run after first user has connected
    char* l_exec; // command to run after last user has disconnected

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
    int sampling;
    int detector;

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
char* prepare_cmd(const char*);
void server_init(int);
void* server_thread(void*);
void* server_conn(void*);
void serial_init(char*);
void serial_loop();
void serial_write(char*, int);
user_t* user_add(server_t*, int, int);
void user_remove(server_t*, user_t*);
void msg_parse_serial(char, char*);
void msg_send(char*, int);
char* auth_salt();
int auth_hash(char*, char*, char*);
void tuner_defaults();
void tuner_reset();
void socket_close(int);

int main(int argc, char* argv[])
{
    char serial[250] = DEFAULT_SERIAL;
    int port = XDR_TCP_DEFAULT_PORT;
    int c;

    server.background = 0;
    server.guest = 0;
    server.password = NULL;
    server.maxusers = DEFAULT_USERS;
    server.f_exec = NULL;
    server.l_exec = NULL;
    server.online = 0;
    server.online_auth = 0;
    server.head = NULL;
    tuner_defaults();
    pthread_mutex_init(&server.mutex, NULL);
    pthread_mutex_init(&server.mutex_s, NULL);

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
        fprintf(stderr, "error: running the server as root is a bad idea, giving up!\n");
        exit(EXIT_FAILURE);
    }
#endif

    while((c = getopt(argc, argv, "hbgxt:s:u:p:f:l:")) != -1)
    {
        switch(c)
        {
        case 'h':
            show_usage(argv[0]);

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
            snprintf(serial, sizeof(serial), "%s", optarg);
#endif
            break;

        case 'u':
            server.maxusers = atoi(optarg);
            break;

        case 'p':
            server.password = optarg;
            break;

        case 'f':
            server.f_exec = prepare_cmd(optarg);
            break;

        case 'l':
            server.l_exec = prepare_cmd(optarg);
            break;

        case ':':
        case '?':
            show_usage(argv[0]);
        }
    }

    if(port < 1024 || port > 65535)
    {
        fprintf(stderr, "error: the tcp port must be in 1024-65535 range\n");
        show_usage(argv[0]);
    }

    if(!server.password || !strlen(server.password))
    {
        fprintf(stderr, "error: no password specified\n");
        show_usage(argv[0]);
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

        if(open("/dev/null", O_RDONLY) == -1 ||
           open("/dev/null", O_WRONLY) == -1 ||
           open("/dev/null", O_RDWR) == -1)
        {
            server_log(LOG_ERR, "open /dev/null");
            exit(EXIT_FAILURE);
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
    server_log(LOG_INFO, "xdrd " VERSION " is starting using %s and TCP port: %d", serial, port);
    server_init(port);
    serial_init(serial);
    serial_loop();
#ifdef __WIN32__
    WSACleanup();
#endif
    server_log(LOG_ERR, "lost connection with tuner");
    return EXIT_FAILURE;
}

void show_usage(char* arg)
{
    printf("xdrd " VERSION "\n");
    printf("usage:\n");
    printf("%s [ -s serial ] [ -t port ] [ -u users ]\n", arg);
    printf("%*s [ -p password ] [ -f command ] [ -l command ]\n", (int)strlen(arg), "");
#ifndef __WIN32__
    printf("%*s [ -hgxb ]\n", (int)strlen(arg), "");
#else
    printf("%*s [ -hgx ]\n", (int)strlen(arg), "");
#endif
    printf("options:\n");
    printf("  -s  serial port (default %s)\n", DEFAULT_SERIAL);
    printf("  -t  tcp/ip port (default %d)\n", XDR_TCP_DEFAULT_PORT);
    printf("  -u  max users   (default %d)\n", DEFAULT_USERS);
    printf("  -p  specify password (required)\n");
    printf("  -h  show this help list\n");
    printf("  -g  allow guest login (read-only access)\n");
    printf("  -x  power the tuner off after last user has disconnected\n");
    printf("  -f  execute the specified command after first user has connected\n");
    printf("  -l  execute the specified command after last user has disconnected\n");
#ifndef __WIN32__
    printf("  -b  run server in the background\n");
#endif
    exit(EXIT_SUCCESS);
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

char* prepare_cmd(const char* cmd)
{
    char* buff;
    int len;
#ifdef __WIN32__
    len = strlen(BACKGROUND_EXEC) + strlen(cmd) + 1;
    buff = malloc(len);
    memcpy(buff, BACKGROUND_EXEC, strlen(BACKGROUND_EXEC));
    memcpy(buff+strlen(BACKGROUND_EXEC), cmd, strlen(cmd));
#else
    len = strlen(cmd) + 1 + 1;
    buff = malloc(len);
    memcpy(buff, cmd, strlen(cmd));
    buff[len-1] = '&';
#endif
    buff[len] = '\0';
    return buff;
}

void server_init(int port)
{
    int sockfd;
    struct sockaddr_in addr;
    pthread_t thread;

#ifdef __WIN32__
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
#else
    if((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
#endif
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

    if(pthread_create(&thread, NULL, server_thread, (void*)(intptr_t)sockfd))
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
    char *salt;

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

#ifdef __WIN32__
    while((connfd = accept((int)(intptr_t)sockfd, (struct sockaddr *)&dest, &dest_size)) >= 0)
#else
    while((connfd = accept4((int)(intptr_t)sockfd, (struct sockaddr *)&dest, &dest_size, SOCK_CLOEXEC)) >= 0)
#endif
    {
        if(server.online >= server.maxusers)
        {
            socket_close(connfd);
            continue;
        }

        if(!(salt = auth_salt()))
        {
            socket_close(connfd);
            continue;
        }

        t_data = malloc(sizeof(thread_t));
        t_data->fd = connfd;
        t_data->salt = salt;
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
    char buffer[100];
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
        socket_close(connfd);
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

    if(server.online_auth)
    {
        snprintf(buffer, sizeof(buffer),
                 "M%d\nY%d\nT%d\nD%d\nA%d\nF%d\nZ%d\nG%02d\nV%d\nQ%d\nC%d\nI%d,%d\n",
                 server.mode,
                 server.volume,
                 server.freq,
                 server.deemphasis,
                 server.agc,
                 server.filter,
                 server.ant,
                 server.gain,
                 server.daa,
                 server.squelch,
                 server.rotator,
                 server.sampling,
                 server.detector);
        send(connfd, buffer, strlen(buffer), MSG_NOSIGNAL);
    }

    u = user_add(&server, connfd, auth);

    snprintf(buffer, sizeof(buffer), "o%d,%d\n",
             server.online_auth,
             server.online - server.online_auth);
    msg_send(buffer, strlen(buffer));

    FD_ZERO(&input);
    FD_SET(u->fd, &input);
    while(select(u->fd+1, &input, NULL, NULL, NULL) > 0)
    {
        if(recv(u->fd, &buffer[pos], 1, MSG_NOSIGNAL) <= 0)
            break;

        /* If this command is too long to
         * fit into a buffer, clip it */
        if(buffer[pos] != '\n')
        {
            if(pos != sizeof(buffer)-1)
                pos++;
            continue;
        }

        if(buffer[0] == XDR_P_SHUTDOWN)
            break;

        if(u->auth)
            serial_write(buffer, pos+1);

        pos = 0;
    }

    user_remove(&server, u);
    server_log(LOG_INFO, "user disconnected: %s:%u", ip, port);
    free(ip);

    if(server.online)
    {
        snprintf(buffer, sizeof(buffer), "o%d,%d\n",
                 server.online_auth,
                 server.online - server.online_auth);
        msg_send(buffer, strlen(buffer));
    }

    if(!server.online_auth && server.poweroff)
    {
        if(server.online)
        {
            /* tell unauthenticated users that XDR has been powered off */
            sprintf(buffer, "X\n");
            msg_send(buffer, strlen(buffer));
        }
        server_log(LOG_INFO, "tuner shutdown");
        tuner_reset();
    }

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
    if((server.serialfd = open(path, O_RDWR | O_NOCTTY | O_NDELAY | O_CLOEXEC)) < 0)
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
    tuner_reset();
}

void serial_loop()
{
    char buff[SERIAL_BUFFER];
    int pos = 0;
#ifdef __WIN32__
    DWORD state, len_in = 0;
    BOOL fWaitingOnRead = FALSE;
    OVERLAPPED osReader = {0};
    osReader.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if(osReader.hEvent == NULL)
    {
        server_log(LOG_ERR, "serial_loop: CreateEvent");
        exit(EXIT_FAILURE);
    }
    while(1)
    {
        if(!fWaitingOnRead)
        {
            if(!ReadFile(server.serialfd, &buff[pos], 1, &len_in, &osReader))
            {
                if(GetLastError() != ERROR_IO_PENDING)
                {
                    CloseHandle(osReader.hEvent);
                    break;
                }
                else
                    fWaitingOnRead = TRUE;
            }
        }
        if(fWaitingOnRead)
        {
            state = WaitForSingleObject(osReader.hEvent, 200);
            if(state == WAIT_TIMEOUT)
                continue;
            if(state != WAIT_OBJECT_0 ||
               !GetOverlappedResult(server.serialfd, &osReader, &len_in, FALSE))
            {
                CloseHandle(osReader.hEvent);
                break;
            }
            fWaitingOnRead = FALSE;
        }
        if(len_in != 1)
            continue;
#else
    fd_set input;
    FD_ZERO(&input);
    FD_SET(server.serialfd, &input);
    while(select(server.serialfd+1, &input, NULL, NULL, NULL) > 0)
    {
        if(read(server.serialfd, &buff[pos], 1) <= 0)
            break;
#endif
        if(buff[pos] != '\n') /* If this command is too long to fit into a buffer, clip it */
        {
            if(pos != SERIAL_BUFFER-1)
                pos++;
            continue;
        }
        buff[pos] = 0;
        if(pos)
            msg_parse_serial(buff[0], buff+1);
        buff[pos] = '\n';
        msg_send(buff, pos+1);
        pos = 0;
    }
#ifdef __WIN32__
    CloseHandle(server.serialfd);
#else
    close(server.serialfd);
#endif
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

    if(!WriteFile(server.serialfd, msg, len, &dwWritten, &osWrite))
        if(GetLastError() == ERROR_IO_PENDING)
            if(WaitForSingleObject(osWrite.hEvent, INFINITE) == WAIT_OBJECT_0)
                GetOverlappedResult(server.serialfd, &osWrite, &dwWritten, FALSE);
    CloseHandle(osWrite.hEvent);
#else
    write(server.serialfd, msg, len);
#endif
    pthread_mutex_unlock(&server.mutex_s);
}

user_t* user_add(server_t* LIST, int fd, int auth)
{
    user_t* u = malloc(sizeof(user_t));
    u->fd = fd;
    u->auth = auth;
    u->prev = NULL;

    pthread_mutex_lock(&LIST->mutex);
    u->next = LIST->head;
    if(LIST->head)
    {
        (LIST->head)->prev = u;
    }
    LIST->head = u;
    LIST->online++;
    LIST->online_auth += auth;

    if(server.f_exec && LIST->online_auth == 1)
    {
        server_log(LOG_INFO, "executing: %s", server.f_exec);
        system(server.f_exec);
    }

    pthread_mutex_unlock(&LIST->mutex);
    return u;
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

    if(server.l_exec && LIST->online_auth == 0)
    {
        server_log(LOG_INFO, "executing: %s", server.l_exec);
        system(server.l_exec);
    }

    pthread_mutex_unlock(&LIST->mutex);
    socket_close(USER->fd);
    free(USER);
}

void msg_parse_serial(char cmd, char* msg)
{
    char *ptr;
    switch(cmd)
    {
    case XDR_P_SHUTDOWN:
        tuner_defaults();
        return;

    case XDR_P_MODE:
        server.mode = atoi(msg);
        server.filter = XDR_P_FILTER_DEFAULT;
        return;

    case XDR_P_TUNE:
        server.freq = atoi(msg);
        return;

    case XDR_P_FILTER:
        server.filter = atoi(msg);

    case XDR_P_DAA:
        server.daa = atoi(msg);
        return;

    case XDR_P_DEEMPHASIS:
        server.deemphasis = atoi(msg);
        return;

    case XDR_P_AGC:
        server.agc = atoi(msg);
        return;

    case XDR_P_GAIN:
        server.gain = atoi(msg);
        return;

    case XDR_P_SQUELCH:
        server.squelch = atoi(msg);
        return;

    case XDR_P_VOLUME:
        server.volume = atoi(msg);
        return;

    case XDR_P_ANTENNA:
        server.ant = atoi(msg);
        return;

    case XDR_P_ROTATOR:
        server.rotator = atoi(msg);
        return;

    case XDR_P_INTERVAL:
        server.sampling = atoi(msg);
        for(ptr = msg; *ptr != '\0'; ptr++)
        {
            if(*ptr == ',')
            {
                server.detector = (*(ptr+1) == '1');
                break;
            }
        }
        return;
    }
}

void msg_send(char* msg, int len)
{
    int sent, n;
    user_t *u;

    pthread_mutex_lock(&server.mutex);
    for(u = server.head; u; u=u->next)
    {
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
    static const char chars[] = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789_-";
    const int len = strlen(chars);
    unsigned char random_data[XDR_TCP_SALT_LENGTH];
    char* output;
    int i;

    if(!RAND_bytes(random_data, sizeof(random_data)))
    {
        server_log(LOG_ERR, "RAND_bytes failed!");
        return NULL;
    }

    output = (char*)malloc(sizeof(char)*(XDR_TCP_SALT_LENGTH+1));
    for(i=0; i<XDR_TCP_SALT_LENGTH; i++)
    {
        output[i] = chars[random_data[i]%len];
    }
    output[i] = 0;
    return output;
}

int auth_hash(char* salt, char* password, char* hash)
{
    SHA_CTX ctx;
    unsigned char sha[SHA_DIGEST_LENGTH];
    char sha_string[SHA_DIGEST_LENGTH*2+1];
    int i;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char*)salt, strlen(salt));
    SHA1_Update(&ctx, (unsigned char*)password, strlen(password));
    SHA1_Final(sha, &ctx);

    for(i=0; i<SHA_DIGEST_LENGTH; i++)
        sprintf(sha_string+(i*2), "%02x", sha[i]);

    return (strcasecmp(hash, sha_string) == 0);
}

void tuner_defaults()
{
    server.mode = XDR_P_MODE_DEFAULT;
    server.volume = XDR_P_VOLUME_DEFAULT;
    server.freq = XDR_P_TUNE_DEFAULT;
    server.deemphasis = XDR_P_DEEMPHASIS_DEFAULT;
    server.agc = XDR_P_AGC_DEFAULT;
    server.filter = XDR_P_FILTER_DEFAULT;
    server.ant = XDR_P_ANTENNA_DEFAULT;
    server.gain = XDR_P_GAIN_DEFAULT;
    server.daa = XDR_P_DAA_DEFAULT;
    server.squelch = XDR_P_SQUELCH_DEFAULT;
    server.rotator = XDR_P_ROTATOR_DEFAULT;
    server.sampling = XDR_P_SAMPLING_DEFAULT;
    server.detector = XDR_P_DETECTOR_DEFAULT;
}

void tuner_reset()
{
    /* restart Arduino using RTS & DTR lines */
    pthread_mutex_lock(&server.mutex_s);
#ifdef __WIN32__
    EscapeCommFunction(server.serialfd, CLRDTR);
    EscapeCommFunction(server.serialfd, CLRRTS);
    Sleep(10);
    EscapeCommFunction(server.serialfd, SETDTR);
    EscapeCommFunction(server.serialfd, SETRTS);
#else
    int ctl;
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

    /* Wait for controller re-initialization,
       before unlocking the mutex. */
#ifdef __WIN32__
    Sleep(XDR_P_ARDUINO_INIT_TIME);
#else
    usleep(XDR_P_ARDUINO_INIT_TIME * 1000);
#endif

    pthread_mutex_unlock(&server.mutex_s);
}

void socket_close(int fd)
{
    shutdown(fd, 2);
#ifdef __WIN32__
    closesocket(fd);
#else
    close(fd);
#endif
}
