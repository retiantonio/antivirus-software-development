#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/inotify.h>
#include <sys/wait.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUFFER_SIZE (1024 * (EVENT_SIZE + 16))

#define DETECTION_ENGINE_PATH "/home/retiantonio/CyberSecurity/antivirus-software-development/antivirusengine"

void callAntivirusEngine(char* fullPath) {
    pid_t enginePid;
    enginePid = fork();
    if(enginePid == 0) {
        //child process
        execl(DETECTION_ENGINE_PATH, DETECTION_ENGINE_PATH, fullPath, NULL);
        printf("[ERROR] Could not start detection engine\n");
        return;
    } else if(enginePid > 0) {
        //parent process
        int status;
        waitpid(enginePid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            printf("[ERROR] Antivirus Engine returned %d\n", WEXITSTATUS(status));
        }
    } else {
        printf("[ERROR] Could not create a new process\n");
    }
}


void* monitorFunction(void* args) {
    char* path = (char*) args;
    
    int monitoringDescriptor = -1;
    if((monitoringDescriptor = inotify_init()) < 0) {
        printf("[ERROR] Could not initialize inotify\n");
        return NULL;
    }    

    int watchDescriptor = -1;
    if((watchDescriptor = inotify_add_watch(monitoringDescriptor, path, IN_CREATE | IN_MODIFY)) < 0) {
        printf("[ERROR] Could not start inotify watch\n");
        return NULL;
    }


    char buffer[BUFFER_SIZE];
    while(1) {
        int readBytes = read(monitoringDescriptor, buffer, BUFFER_SIZE);
        if(readBytes < 0) {
            printf("[ERROR] Read not functioning properly\n");
            return NULL;
        }

        for(int i = 0; i < readBytes;) {
            struct inotify_event* event = (struct inotify_event*) &buffer[i];

            if(event->len) {
                printf("Detected file name: %s\n", event->name);
                char fullPath[512];
                snprintf(fullPath, 512, "%s/%s", path, event->name);
                callAntivirusEngine(fullPath);
            }

            i += EVENT_SIZE + event->len;
        }
    }

    close(watchDescriptor);
    close(monitoringDescriptor);

    return NULL;
}

int main(int argc, char* argv[]) {
    
    if(argc != 2) {
        printf("[ERROR] Wrong parameters input\n");
        return 1;
    }

    char* argument = argv[1];
    printf("argument: %s\n", argument);

    char* argumentCopy = (char*) malloc(strlen(argument) + 1);
    memcpy(argumentCopy, argument, strlen(argument) + 1);
    printf("argument copy: %s\n", argumentCopy);

    int tokenCounter = 0;
    char* token = strtok(argument, ";");    
    while(token != NULL) {
        tokenCounter++;
        token = strtok(NULL, ";");
    }
    
    pthread_t tid[tokenCounter];
    int threadCounter = 0;
    token = strtok(argumentCopy, ";");
    while(token != NULL) {
        //thread creation
        printf("function token: %s\n", token);
        if(pthread_create(&tid[threadCounter], NULL, monitorFunction, token) != 0) {
            printf("[ERROR] Cannot create thread\n");
            return 1;
        }

        token = strtok(NULL, ";");
        threadCounter++;
    }

    for(int i = 0; i < tokenCounter; i++) {
        pthread_join(tid[i], NULL);
    }

    free(argumentCopy);
    return 0;
}