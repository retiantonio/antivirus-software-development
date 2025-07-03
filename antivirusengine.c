#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>

#include <yara.h>
#include <windows.h>

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
            char ruleFilePath[512];
            snprintf(ruleFilePath, 512, "%s/%s", directoryPath, entry->d_name);
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

    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}