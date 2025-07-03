#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <sys/stat.h>

#include <yara.h>
#include <windows.h>

#define BUFFER_SIZE 512


int scanCallBack(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData) {
    switch(message) {
        case CALLBACK_MSG_RULE_MATCHING:
            printf("Matched rule: %s\n", ((YR_RULE*)messageData)->identifier);
            break;
        case CALLBACK_MSG_RULE_NOT_MATCHING:
            printf("Did not match rule: %s\n", ((YR_RULE*)messageData)->identifier);
            break;
        case CALLBACK_MSG_SCAN_FINISHED:
            printf("Scan finished\n");
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
    yr_rules_scan_file(rules, filePath, SCAN_FLAGS_REPORT_RULES_NOT_MATCHING, scanCallBack, NULL, NULL);
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
            scanfFile(path, rules);
        }
    }
}

void checkType(const char* path, const char* rules) {
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

int main(int argc, char* argv[]) {
    if(argc != 2) {
        printf("[ERROR] Incorrect parameter number\n");
        return 1;
    }

    const char directoryPath[] = "path to rules";

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
                printf("[SUCCESS] Compiled rule: %s", ruleFilePath);
            }
            fclose(ruleFile);
        }
    }

    closedir(directory);

    YR_RULES* rules = NULL;
    yr_compiler_get_rules(yaraCompiler, &rules);

    checkType(filePath, rules);

    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}