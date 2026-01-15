#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>

#define MAX_CLIENTS 64
#define INITIAL_RECV_SIZE 0x300
#define INITIAL_SEND_SIZE 0x300
#define MAX_POSTS 1024

// 协议命令
#define CMD_POST_CREATE 0x01
#define CMD_POST_DELETE 0x02
#define CMD_POST_LIST 0x03
#define CMD_POST_VIEW 0x04
#define CMD_POST_MODIFY 0x05

// 状态定义
#define STATE_RECV_CMD 0
#define STATE_PROCESSING 1
#define STATE_SENDING 2

// 帖子结构
typedef struct {
    int id;
    char *title;
    char *tag;
    char *content;
    char *username;
    char *date;
    int deleted;
} Post;

// 接收缓冲区结构 (可变大小)
typedef struct {
    size_t size;
    char *ptr;      // 当前写入位置
    char *end;      // 缓冲区结束位置
    char data[];    // 柔性数组成员
} RecvBuf;

// 发送缓冲区结构 (可变大小)
typedef struct {
    size_t size;
    char *ptr;      // 当前发送位置
    char *end;      // 数据结束位置
    char data[];    // 柔性数组成员
} SendBuf;

// Socket描述符
typedef struct {
    int state;
    int fd;
    int active;
    RecvBuf *recvbuf;
    SendBuf *sendbuf;
} SlpdSocket;

// 全局变量
Post *posts[MAX_POSTS];
int post_count = 0;
int next_post_id = 1;
SlpdSocket *clients[MAX_CLIENTS];  // 修改为指针数组

// 函数声明
void init_slpd_socket(SlpdSocket *sock, int fd);
void free_slpd_socket(SlpdSocket *sock, int index);
int resize_recvbuf(SlpdSocket *sock, size_t new_size);
int resize_sendbuf(SlpdSocket *sock, size_t new_size);
void handle_client_data(SlpdSocket *sock, int index);
void process_command(SlpdSocket *sock);
void cmd_create_post(SlpdSocket *sock);
void cmd_delete_post(SlpdSocket *sock);
void cmd_list_posts(SlpdSocket *sock);
void cmd_view_post(SlpdSocket *sock);
void cmd_modify_post(SlpdSocket *sock);
char* read_param(char *ptr, size_t *remain, unsigned short *param_len);
void send_response(SlpdSocket *sock, const char *msg);
void free_post(Post *post);
void cleanup_all_posts(void);

// 初始化SlpdSocket
void init_slpd_socket(SlpdSocket *sock, int fd) {
    sock->fd = fd;
    
    // 创建接收缓冲区
    sock->recvbuf = (RecvBuf*)calloc(1, sizeof(RecvBuf) + INITIAL_RECV_SIZE);
    sock->recvbuf->size = INITIAL_RECV_SIZE;
    sock->recvbuf->ptr = sock->recvbuf->data;
    sock->recvbuf->end = sock->recvbuf->data + INITIAL_RECV_SIZE;
    
    // 创建发送缓冲区
    sock->sendbuf = (SendBuf*)calloc(1, sizeof(SendBuf) + INITIAL_SEND_SIZE);
    sock->sendbuf->size = INITIAL_SEND_SIZE;
    sock->sendbuf->ptr = sock->sendbuf->data;
    sock->sendbuf->end = sock->sendbuf->data;
    
    sock->state = STATE_RECV_CMD;
    sock->active = 1;
}

// 释放SlpdSocket
void free_slpd_socket(SlpdSocket *sock, int index) {
    if (!sock) return;
    
    if (sock->recvbuf) {
        free(sock->recvbuf);
        sock->recvbuf = NULL;
    }
    if (sock->sendbuf) {
        free(sock->sendbuf);
        sock->sendbuf = NULL;
    }
    if (sock->fd > 0) {
        close(sock->fd);
        sock->fd = -1;
    }
    sock->active = 0;
    
    free(sock);
    clients[index] = NULL;
}

// 调整接收缓冲区大小
int resize_recvbuf(SlpdSocket *sock, size_t new_size) {
    RecvBuf *new_buf = (RecvBuf*)calloc(1, sizeof(RecvBuf) + new_size);
    if (!new_buf) return -1;
    
    new_buf->size = new_size;
    
    // 计算已接收数据量
    size_t recv_len = sock->recvbuf->ptr - sock->recvbuf->data;
    
    // 复制旧数据
    if (recv_len > 0) {
        memcpy(new_buf->data, sock->recvbuf->data, recv_len);
    }
    
    // 设置新指针
    new_buf->ptr = new_buf->data + recv_len;
    new_buf->end = new_buf->data + new_size;
    
    free(sock->recvbuf);
    sock->recvbuf = new_buf;
    return 0;
}

// 调整发送缓冲区大小
int resize_sendbuf(SlpdSocket *sock, size_t new_size) {
    SendBuf *new_buf = (SendBuf*)calloc(1, sizeof(SendBuf) + new_size);
    if (!new_buf) return -1;
    
    new_buf->size = new_size;
    
    // 计算已发送和总数据量
    size_t sent_len = sock->sendbuf->ptr - sock->sendbuf->data;
    size_t total_len = sock->sendbuf->end - sock->sendbuf->data;
    
    // 复制旧数据
    if (total_len > 0) {
        memcpy(new_buf->data, sock->sendbuf->data, total_len);
    }
    
    // 设置新指针
    new_buf->ptr = new_buf->data + sent_len;
    new_buf->end = new_buf->data + total_len;
    
    free(sock->sendbuf);
    sock->sendbuf = new_buf;
    return 0;
}

// 读取参数 (直接在recvbuf上分析，返回参数起始位置)
char* read_param(char *ptr, size_t *remain, unsigned short *param_len) {
    if (*remain < 2) return NULL;
    
    // 读取长度
    *param_len = *(unsigned short *)ptr;
    ptr += 2;
    *remain -= 2;
    
    // 检查剩余空间是否足够
    if (*remain < *param_len) return NULL;
    
    // 返回参数内容起始位置
    char *param_start = ptr;
    *remain -= *param_len;
    
    return param_start;
}

// 发送响应
void send_response(SlpdSocket *sock, const char *msg) {
    size_t len = strlen(msg);
    
    if (len > sock->sendbuf->size) {
        size_t new_size = sock->sendbuf->size;
        while (new_size < len) new_size *= 2;
        resize_sendbuf(sock, new_size);
    }
    
    strcpy(sock->sendbuf->data, msg);
    sock->sendbuf->ptr = sock->sendbuf->data;
    sock->sendbuf->end = sock->sendbuf->data + len;
    sock->state = STATE_SENDING;
}

// 释放帖子
void free_post(Post *post) {
    if (!post) return;
    
    if (post->title) free(post->title);
    if (post->tag) free(post->tag);
    if (post->content) free(post->content);
    if (post->username) free(post->username);
    if (post->date) free(post->date);
    free(post);
}

// 清理所有帖子（程序退出时调用）
void cleanup_all_posts(void) {
    for (int i = 0; i < post_count; i++) {
        if (posts[i]) {
            free_post(posts[i]);
            posts[i] = NULL;
        }
    }
}

// 创建帖子
void cmd_create_post(SlpdSocket *sock) {
    char *ptr = sock->recvbuf->data + 1; // 跳过命令字节
    size_t remain = (sock->recvbuf->ptr - sock->recvbuf->data) - 1;
    unsigned short len1, len2, len3;
    
    // 读取参数1: title/../tag/../content
    char *param1 = read_param(ptr, &remain, &len1);
    if (!param1) {
        send_response(sock, "ERROR: Invalid parameters\n");
        return;
    }
    ptr = param1 + len1;
    
    // 读取参数2: username
    char *username_start = read_param(ptr, &remain, &len2);
    if (!username_start) {
        send_response(sock, "ERROR: Invalid parameters\n");
        return;
    }
    ptr = username_start + len2;
    
    // 读取参数3: date
    char *date_start = read_param(ptr, &remain, &len3);
    if (!date_start) {
        send_response(sock, "ERROR: Invalid parameters\n");
        return;
    }
    
    // 解析 title/../tag/../content
    char *title_start = param1;
    char *sep1 = strstr(param1, "/../");
    if (!sep1 || (sep1 - param1) > len1) {
        send_response(sock, "ERROR: Invalid format\n");
        return;
    }
    
    // 将第一个分隔符置为\x00
    *sep1 = '\0';
    *(sep1 + 1) = '\0';
    *(sep1 + 2) = '\0';
    *(sep1 + 3) = '\0';
    
    char *tag_start = sep1 + 4;
    char *sep2 = strstr(tag_start, "/../");
    if (!sep2 || (sep2 - param1) > len1) {
        send_response(sock, "ERROR: Invalid format\n");
        return;
    }
    
    // 将第二个分隔符置为\x00
    *sep2 = '\0';
    *(sep2 + 1) = '\0';
    *(sep2 + 2) = '\0';
    *(sep2 + 3) = '\0';
    
    char *content_start = sep2 + 4;
    
    // 检查边界
    if ((content_start - param1) > len1) {
        send_response(sock, "ERROR: Invalid format\n");
        return;
    }
    
    if (post_count >= MAX_POSTS) {
        send_response(sock, "ERROR: Post limit reached\n");
        return;
    }
    
    // 计算各部分长度
    size_t title_len = sep1 - param1;
    size_t tag_len = sep2 - tag_start;
    size_t content_len = len1 - (content_start - param1);
    
    // 创建帖子
    Post *post = calloc(1, sizeof(Post));
    post->title = calloc(1, title_len + 1);
    post->tag = calloc(1, tag_len + 1);
    post->content = calloc(1, content_len + 1);
    post->username = calloc(1, len2 + 1);
    post->date = calloc(1, len3 + 1);

    post->id = next_post_id++;
    post->deleted = 0;
    strcpy(post->title, title_start);
    
    strcpy(post->tag, tag_start);
    
    strcpy(post->content, content_start);
    
    strncpy(post->username, username_start, len2);
    post->username[len2] = '\0';
    
    strncpy(post->date, date_start, len3);
    post->date[len3] = '\0';
    
    posts[post_count++] = post;
    
    char *response = calloc(1, 128);
    snprintf(response, 128, "OK: Post created with ID %d\n", post->id);
    send_response(sock, response);
    free(response);
}

// 删除帖子 (真正释放内存)
void cmd_delete_post(SlpdSocket *sock) {
    char *ptr = sock->recvbuf->data + 1;
    size_t remain = (sock->recvbuf->ptr - sock->recvbuf->data) - 1;
    unsigned short len;
    
    char *id_str = read_param(ptr, &remain, &len);
    if (!id_str) {
        send_response(sock, "ERROR: Invalid parameters\n");
        return;
    }
    
    // 临时复制ID字符串用于转换
    char *temp_id = malloc(len + 1);
    temp_id[len+1] = '\x00';
    strcpy(temp_id, id_str);
    
    int id = atoi(temp_id);
    free(temp_id);
    
    for (int i = 0; i < post_count; i++) {
        if (posts[i] && posts[i]->id == id && !posts[i]->deleted) {
            // 真正释放帖子内存
            free_post(posts[i]);
            posts[i] = NULL;
            
            send_response(sock, "OK: Post deleted\n");
            return;
        }
    }
    
    send_response(sock, "ERROR: Post not found\n");
}

// 列出所有帖子 (功能未开放)
void cmd_list_posts(SlpdSocket *sock) {
    send_response(sock, "ERROR: Feature not available\n");
}

// 查看具体帖子 (功能未开放)
void cmd_view_post(SlpdSocket *sock) {
    send_response(sock, "ERROR: Feature not available\n");
}

// 修改帖子
void cmd_modify_post(SlpdSocket *sock) {
    char *ptr = sock->recvbuf->data + 1;
    size_t remain = (sock->recvbuf->ptr - sock->recvbuf->data) - 1;
    unsigned short len1, len2;
    
    char *id_str = read_param(ptr, &remain, &len1);
    if (!id_str) {
        send_response(sock, "ERROR: Invalid parameters\n");
        return;
    }
    ptr = id_str + len1;
    
    char *new_content_start = read_param(ptr, &remain, &len2);
    if (!new_content_start) {
        send_response(sock, "ERROR: Invalid parameters\n");
        return;
    }
    
    char *temp_id = malloc(len1 + 1);
    temp_id[len1+1] = '\x00';
    strcpy(temp_id, id_str);
    
    int id = atoi(temp_id);
    free(temp_id);
    
    for (int i = 0; i < post_count; i++) {
        if (posts[i] && posts[i]->id == id && !posts[i]->deleted) {
            free(posts[i]->content);
            
            // 复制新内容
            posts[i]->content = calloc(1, len2 + 1);
            strncpy(posts[i]->content, new_content_start, len2);
            posts[i]->content[len2] = '\0';
            
            send_response(sock, "OK: Post modified\n");
            return;
        }
    }
    
    send_response(sock, "ERROR: Post not found\n");
}

// 处理命令
void process_command(SlpdSocket *sock) {
    size_t recv_len = sock->recvbuf->ptr - sock->recvbuf->data;
    if (recv_len < 1) return;
    
    unsigned char cmd = sock->recvbuf->data[0];
    
    switch (cmd) {
        case CMD_POST_CREATE:
            cmd_create_post(sock);
            break;
        case CMD_POST_DELETE:
            cmd_delete_post(sock);
            break;
        case CMD_POST_LIST:
            cmd_list_posts(sock);
            break;
        case CMD_POST_VIEW:
            cmd_view_post(sock);
            break;
        case CMD_POST_MODIFY:
            cmd_modify_post(sock);
            break;
        default:
            send_response(sock, "ERROR: Unknown command\n");
    }
    
    // 重置接收缓冲区
    sock->recvbuf->ptr = sock->recvbuf->data;
    memset(sock->recvbuf->ptr, 0, sock->recvbuf->size);
}

// 处理客户端数据
void handle_client_data(SlpdSocket *sock, int index) {
    if (sock->state == STATE_RECV_CMD || sock->state == STATE_PROCESSING) {
        // 计算剩余空间
        size_t space = sock->recvbuf->end - sock->recvbuf->ptr;
        
        // 接收数据
        ssize_t n = recv(sock->fd, sock->recvbuf->ptr, space, 0);
        
        if (n <= 0) {
            free_slpd_socket(sock, index);
            return;
        }
        
        sock->recvbuf->ptr += n;
        
        // 如果缓冲区满了，扩展
        if (sock->recvbuf->ptr >= sock->recvbuf->end) {
            resize_recvbuf(sock, sock->recvbuf->size * 2);
        }
        
        sock->state = STATE_PROCESSING;
        process_command(sock);
    }
    
    if (sock->state == STATE_SENDING) {
        // 计算剩余发送量
        size_t to_send = sock->sendbuf->end - sock->sendbuf->ptr;
        
        // 发送数据
        ssize_t n = send(sock->fd, sock->sendbuf->ptr, to_send, 0);
        
        if (n <= 0) {
            free_slpd_socket(sock, index);
            return;
        }
        
        sock->sendbuf->ptr += n;
        
        if (sock->sendbuf->ptr >= sock->sendbuf->end) {
            // 发送完成，回到接收状态
            sock->state = STATE_RECV_CMD;
            sock->sendbuf->ptr = sock->sendbuf->data;
            sock->sendbuf->end = sock->sendbuf->data;
            memset(sock->sendbuf->ptr, 0, sock->sendbuf->size);
        }
    }
}

// 主函数
int main(int argc, char *argv[]) {
    int server_fd, port = 8888;
    struct sockaddr_in addr;
    
    if (argc > 1) port = atoi(argv[1]);
    
    // 初始化客户端数组
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = NULL;
    }
    
    // 初始化帖子数组
    for (int i = 0; i < MAX_POSTS; i++) {
        posts[i] = NULL;
    }
    
    // 创建服务器socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    for (size_t i = 0; i < sizeof(addr); i++) {
        ((char*)&addr)[i] = 0;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 10);
    
    printf("Forum server listening on port %d\n", port);
    
    while (1) {
        fd_set readfds, writefds;
        int max_fd = server_fd;
        
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(server_fd, &readfds);
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] && clients[i]->active) {
                if (clients[i]->state == STATE_SENDING) {
                    FD_SET(clients[i]->fd, &writefds);
                } else {
                    FD_SET(clients[i]->fd, &readfds);
                }
                if (clients[i]->fd > max_fd) max_fd = clients[i]->fd;
            }
        }
        
        select(max_fd + 1, &readfds, &writefds, NULL, NULL);
        
        // 接受新连接
        if (FD_ISSET(server_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
            
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == NULL) {
                    clients[i] = calloc(1, sizeof(SlpdSocket));
                    init_slpd_socket(clients[i], client_fd);
                    printf("Client connected: %d\n", client_fd);
                    break;
                }
            }
        }
        
        // 处理客户端
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i] || !clients[i]->active) continue;
            
            if (FD_ISSET(clients[i]->fd, &readfds) || 
                FD_ISSET(clients[i]->fd, &writefds)) {
                handle_client_data(clients[i], i);
            }
        }
    }
    
    // 程序退出前清理所有客户端
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i]) {
            free_slpd_socket(clients[i], i);
        }
    }
    
    // 程序退出前清理所有帖子
    cleanup_all_posts();
    close(server_fd);
    return 0;
}