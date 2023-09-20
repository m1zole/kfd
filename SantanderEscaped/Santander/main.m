//
//  main.m
//  FileTroller
//
//  Created by Nathan Senter on 3/7/23.
//

#import <UIKit/UIKit.h>
#import <stdio.h>
#import <objc/runtime.h>
#import <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#import "grant_full_disk_access.h"
#import "Santander-Swift.h"

void handle_client(int client_socket);

int main(int argc, char *argv[]) {
    NSString * appDelegateClassName;
    
    if (argc == 2 && strcmp(argv[1], "--server") == 0) {
        int server_socket, client_socket, port;
        struct sockaddr_in server_addr, client_addr;
        socklen_t client_len = sizeof(client_addr);

        port = atoi("1337");

        if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Error creating socket");
            exit(1);
        }

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        server_addr.sin_port = htons(port);

        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Error binding socket");
            exit(1);
        }

        if (listen(server_socket, 5) < 0) {
            perror("Error listening for connections");
            exit(1);
        }

        printf("Server listening on port %d...\n", port);

        while (1) {
            if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len)) < 0) {
                perror("Error accepting connection");
                exit(1);
            }

            handle_client(client_socket);
        }

        return 0;
    } else {
        @autoreleasepool {
            // Setup code that might create autoreleased objects goes here.
            appDelegateClassName = NSStringFromClass([AppDelegate class]);
        }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
    }
        
}

void handle_client(int client_socket) {
    char buffer[1024];
    ssize_t num_bytes;

    while ((num_bytes = read(client_socket, buffer, sizeof(buffer))) > 0) {
        buffer[num_bytes - 1] = '\0';

        char command_output[1024];

        if (strncmp(buffer, "ls", 2) == 0) {
                    DIR *dir = opendir(strtok(buffer + 3, " "));
                    DIR *dir2 = opendir(".");
                    if (dir == NULL) {
                        struct dirent *entry;
                        while ((entry = readdir(dir2)) != NULL) {
                            snprintf(command_output, sizeof(command_output), "%s\n", entry->d_name);
                            write(client_socket, command_output, strlen(command_output));
                        }
                        closedir(dir2);
                        memset(buffer, 0, sizeof(buffer));
                    }
                    else {
                        struct dirent *entry;
                        while ((entry = readdir(dir)) != NULL) {
                            snprintf(command_output, sizeof(command_output), "%s\n", entry->d_name);
                            write(client_socket, command_output, strlen(command_output));
                        }
                        closedir(dir);
                        memset(buffer, 0, sizeof(buffer));
                    }
        } else if (strncmp(buffer, "mv", 2) == 0) {
            char *src = strtok(buffer + 3, " ");
            char *dest = strtok(NULL, " ");
            if (src == NULL || dest == NULL) {
                char *error_message = "Invalid command\n";
                memset(buffer, 0, sizeof(buffer));
                write(client_socket, error_message, strlen(error_message));
                continue;
            }
            if (rename(src, dest) == -1) {
                char *error_message = "Error renaming file";
                memset(buffer, 0, sizeof(buffer));
                write(client_socket, error_message, strlen(error_message));
            }
        } else if (strncmp(buffer, "cp", 2) == 0) {
            char *src = strtok(buffer + 3, " ");
            char *dest = strtok(NULL, " ");
            if (src == NULL || dest == NULL) {
                char *error_message = "Invalid command\n";
                memset(buffer, 0, sizeof(buffer));
                write(client_socket, error_message, strlen(error_message));
                continue;
            }
            FILE *source_file = fopen(src, "r");
            if (source_file == NULL) {
                char *error_message = "Error opening source file\n";
                memset(buffer, 0, sizeof(buffer));
                write(client_socket, error_message, strlen(error_message));
                continue;
            }
            FILE *dest_file = fopen(dest, "w");
            if (dest_file == NULL) {
                char *error_message = "Error creating destination file\n";
                fclose(source_file);
                memset(buffer, 0, sizeof(buffer));
                write(client_socket, error_message, strlen(error_message));
                continue;
            }
            char buffer[1024];
            size_t bytes_read;
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), source_file)) > 0) {
                fwrite(buffer, 1, bytes_read, dest_file);
            }
            fclose(source_file);
            fclose(dest_file);
            char *success_message = "File copied successfully\n";
            memset(buffer, 0, sizeof(buffer));
            write(client_socket, success_message, strlen(success_message));
        } else if (strncmp(buffer, "cd", 2) == 0) {
            char *dir = strtok(buffer + 3, " ");
            if (dir == NULL) {
                char *error_message = "Invalid command\n";
                memset(buffer, 0, sizeof(buffer));
                write(client_socket, error_message, strlen(error_message));
                continue;
            }
            if (chdir(dir) == -1) {
                char *error_message = "Error changing dir\n";
                memset(buffer, 0, sizeof(buffer));
                write(client_socket, error_message, strlen(error_message));
            }
        } else if (strncmp(buffer, "id", 2) == 0) {
            uid_t uid = getuid();
            snprintf(command_output, sizeof(command_output), "uid=%d\n", uid);
            write(client_socket, command_output, strlen(command_output));
        } else if (strncmp(buffer, "exit", 2) == 0) {
            close(client_socket);
        } else if (strncmp(buffer, "touch", 5) == 0) {
            char *file_path = strtok(buffer + 6, " ");
            if (file_path == NULL) {
                char *error_message = "Invalid command\n";
                memset(buffer, 0, sizeof(buffer));
                write(client_socket, error_message, strlen(error_message));
                continue;
            }
            int fd = open(file_path, O_CREAT, 0644);
            if (fd == -1) {
                char *error_message = "Error creating file";
                write(client_socket, error_message, strlen(error_message));
            } else {
                close(fd);
                memset(buffer, 0, sizeof(buffer));
            }
        } else if (strncmp(buffer, "rm", 2) == 0) {
            char *filename = strtok(buffer + 3, " ");
            if (remove(filename) == 0) {
                char success_message[1024];
                snprintf(success_message, sizeof(success_message), "%s removed successfully.\n", filename);
                write(client_socket, success_message, strlen(success_message));
            } else {
                char error_message[1024];
                snprintf(error_message, sizeof(error_message), "Error removing %s\n", filename);
                write(client_socket, error_message, strlen(error_message));
            }
        } else if (strncmp(buffer, "cat", 3) == 0) {
                    char *file = strtok(buffer + 4, " ");
                    FILE *fp;
                    char line[1024];
                    fp = fopen(file, "r");
            if (fp != NULL) {
                while (fgets(line, sizeof(line), fp)) {
                    write(client_socket, line, strlen(line));
                }
                fclose(fp);
            }
        } else if (strncmp(buffer, "tccd", 2) == 0) {
            grant_full_disk_access(^(NSError* error) {
                char command_output_tccd[1024];
                snprintf(command_output_tccd, sizeof(command_output_tccd), "grant_full_disk_access returned error: %s\n", [error.localizedDescription UTF8String]);
                write(client_socket, command_output_tccd, strlen(command_output_tccd));
            });
        } else {
            char *error_message = "Invalid command\n";
            write(client_socket, error_message, strlen(error_message));
        }
    }

    close(client_socket);
}
