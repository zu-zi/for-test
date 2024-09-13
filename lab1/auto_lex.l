%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *keywords[] = {
    "int", "float", "char", "if", "else", "while", "for", "return", "void"
};
const int num_keywords = sizeof(keywords) / sizeof(keywords[0]);

int is_keyword(const char *token) {
    for (int i = 0; i < num_keywords; i++) {
        if (strcmp(token, keywords[i]) == 0) {
            return 1;
        }
    }
    return 0;
}
%}

%option noyywrap

%%

[ \t\n]+                     ; // Ignore whitespace
[0-9]+                       { printf("Constant: %s\n", yytext); }
[A-Za-z_][A-Za-z0-9_]*       {
                              if (is_keyword(yytext)) {
                                  printf("Keyword: %s\n", yytext);
                              } else {
                                  printf("Identifier: %s\n", yytext);
                              }
                            }
[\+\-\*/%=&|<>!]+            { printf("Operator: %s\n", yytext); }
[;,\(\)\{\}]                 { printf("Delimiter: %s\n", yytext); }

.                            { /* Ignore unknown characters */ }

%%

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *file = fopen(argv[1], "r");
    if (!file) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    yyin = file;
    yylex();
    fclose(file);

    return EXIT_SUCCESS;
}
