#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fcntl.h>

#include <yara.h>

#define BUFFER_SIZE 512
#define QUARANTINE_PATH "/home/retiantonio/CyberSecurity/QUARANTINE_TEST"

int matchedCount = 0;
int notMatchedCount = 0;

int scanCallBack(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData) {
    switch(message) {
        case CALLBACK_MSG_RULE_MATCHING:
            printf("[SCANNING] Matched rule: %s\n", ((YR_RULE*)messageData)->identifier);
            matchedCount++;
            break;
        case CALLBACK_MSG_RULE_NOT_MATCHING:
            printf("[SCANNING] Did not match rule: %s\n", ((YR_RULE*)messageData)->identifier);
            notMatchedCount++;
            break;
        case CALLBACK_MSG_SCAN_FINISHED:
            printf("\n[RESULT] Scan finished\n");
            break;
        case CALLBACK_MSG_TOO_MANY_MATCHES:
            printf("Too many matches\n");
            break;
        case CALLBACK_MSG_CONSOLE_LOG:
            printf("Console log: %s\n", (char*)messageData);
            break;
        default:
            break;
    }

    return CALLBACK_CONTINUE;
}

void scanFile(const char* filePath, YR_RULES* rules) { 
    yr_rules_scan_file(rules, filePath, SCAN_FLAGS_REPORT_RULES_NOT_MATCHING | SCAN_FLAGS_REPORT_RULES_MATCHING, scanCallBack, NULL, 0);
}

void scanDirectory(const char* directoryPath, YR_RULES* rules) {
    DIR* directory = NULL;
    struct dirent* entry;

    if(!(directory = opendir(directoryPath))) {
        printf("[ERROR] Could not open file directory\n");
        return;
    }

    char path[BUFFER_SIZE];

    while((entry = readdir(directory)) != NULL) {
        if(entry->d_type == DT_DIR) {
            if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            snprintf(path, BUFFER_SIZE, "%s/%s", directoryPath, entry->d_name);
            scanDirectory(path, rules);
        } else {
            snprintf(path, BUFFER_SIZE, "%s/%s", directoryPath, entry->d_name);
            scanFile(path, rules);
        }
    }
}

void checkType(const char* path, YR_RULES* rules) {
    struct stat pathStat;

    if(stat(path, &pathStat) == 0) {
        if(S_ISREG(pathStat.st_mode)) {
            scanFile(path, rules);
        } else if(S_ISDIR(pathStat.st_mode)) {
            scanDirectory(path, rules);
        } else {
            printf("[ERROR] Unknown file type\n");
        }
    } else {
        printf("[ERROR] Could not get file status\n");
    }
}

void moveToQuarantine(char* filePath) {
    //copy the file and move it to quarantine folder
    int sourceFileDescriptor = open(filePath, O_RDONLY);
    if(sourceFileDescriptor < 0) {
        printf("[ERROR] Could not open given file\n");
        return;
    }

    //get the name of the file
    char* fileName = strrchr(filePath, '/');
    if(fileName) {
        fileName++;
    } else {
        printf("[ERROR] Invalid file path\n");
        return;
    }

    //form the path for the destination
    char destinationPath[BUFFER_SIZE] = {0};
    snprintf(destinationPath, BUFFER_SIZE, "%s/%s", QUARANTINE_PATH, fileName);

    int destinationFileDescriptor = open(destinationPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(destinationFileDescriptor < 0) {
        printf("[Error] Could not create quarantine file\n");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes;
    while((bytes = read(sourceFileDescriptor, buffer, BUFFER_SIZE)) > 0) {
        if(write(destinationFileDescriptor, buffer, bytes) != bytes) {
            printf("[ERROR] file write\n");
            close(sourceFileDescriptor);
            close(destinationFileDescriptor);
            return;
        }
    }

    close(sourceFileDescriptor);
    close(destinationFileDescriptor);

    if(bytes < 0) {
        printf("[ERROR] file read\n");
        return;
    }
   
    if(unlink(filePath) != 0) {
        printf("[ERROR] file unlink\n");
    }
}

void printResult(char* filePath) {
    printf("[RESULT] Rules Not Matched: %d\n", notMatchedCount);
    printf("[RESULT] Rules Matched: %d\n", matchedCount);

    if(matchedCount == 0) {
        printf("[RESULT] Engine didn't detect any possible malware\n");
    } else {
        printf("[RESULT] Detections: %d | File may be dangerous to your computer\n", matchedCount);
    }
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        printf("[ERROR] Incorrect parameter number\n");
        return 1;
    }

    const char directoryPath[] = "/home/retiantonio/CyberSecurity/antivirus-software-development/yara-rules";

    char* filePath = argv[1];

    int initResult = yr_initialize();
    if(initResult != 0) {
        printf("[ERROR] failed to initalize YARA\n");
        return 1;
    } 

    printf("[SUCCES] YARA succesfully initialized\n");
    
    YR_COMPILER* yaraCompiler = NULL;
    int compileResult = yr_compiler_create(&yaraCompiler);
    if(compileResult != ERROR_SUCCESS) {
        printf("[ERROR] Failed to initialize YARA compiler\n");
    }

    DIR* directory = opendir(directoryPath);
    if(directory == NULL) {
        printf("[ERROR] Failed to open directory %s\n", directoryPath);
        yr_finalize();
        return 1;
    }

    printf("[SUCCESS] Succesfully opened rule directory\n");
    
    struct dirent* entry;
    while((entry = readdir(directory)) != NULL) {
        if(entry->d_type == DT_REG && strstr(entry->d_name, ".yar") != NULL) {
            char ruleFilePath[BUFFER_SIZE];
            snprintf(ruleFilePath, BUFFER_SIZE, "%s/%s", directoryPath, entry->d_name);
            FILE* ruleFile = fopen(ruleFilePath, "rb");

            int addResult = yr_compiler_add_file(yaraCompiler, ruleFile, NULL, NULL);
            if(addResult > 0) {
                printf("[ERROR] Failed to compile YARA rule %s, number of errors found: %d\n", ruleFilePath, addResult);
            } else {
                printf("[SUCCESS] Compiled rule: %s\n", ruleFilePath);
            }
            
            fclose(ruleFile);
        }
    }

    closedir(directory);

    YR_RULES* rules = NULL;
    yr_compiler_get_rules(yaraCompiler, &rules);

    checkType(filePath, rules);
    printResult(filePath);

    if(matchedCount > 0) {
        //move file to quarantine
        printf("[IN PROGRESS] Moving File\n");
        moveToQuarantine(filePath);
        printf("[SUCCESS] Moved File to Quarantine\n");
    }

    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}