#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define MAX_TOKEN_LENGTH 100

const char *keywords[] = {
    "int", "float", "char", "if", "else", "while", "for", "return", "void"};
const int num_keywords = sizeof(keywords) / sizeof(keywords[0]);

int is_keyword(const char *token)
{
  for (int i = 0; i < num_keywords; i++)
  {
    if (strcmp(token, keywords[i]) == 0)
    {
      return 1;
    }
  }
  return 0;
}

void classify_token(const char *token)
{
  if (isdigit(token[0]))
  {
    printf("Constant: %s\n", token);
  }
  else if (isalpha(token[0]))
  {
    if (is_keyword(token))
    {
      printf("Keyword: %s\n", token);
    }
    else
    {
      printf("Identifier: %s\n", token);
    }
  }
  else if (strchr("+-*/%=&|<>!;", token[0]))
  {
    printf("Operator/Delimiter: %s\n", token);
  }
  else
  {
    printf("Unknown: %s\n", token);
  }
}

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return EXIT_FAILURE;
  }

  FILE *file = fopen(argv[1], "r");
  if (!file)
  {
    perror("Error opening file");
    return EXIT_FAILURE;
  }

  char c;
  char token[MAX_TOKEN_LENGTH];
  int token_length = 0;

  while ((c = fgetc(file)) != EOF)
  {
    if (isspace(c) || strchr("+-*/%=&|<>!;,", c))
    {
      if (token_length > 0)
      {
        token[token_length] = '\0';
        classify_token(token);
        token_length = 0;
      }
      if (strchr("+-*/%=&|<>!;,", c))
      {
        token[0] = c;
        token[1] = '\0';
        classify_token(token);
      }
    }
    else if (isalnum(c))
    {
      if (token_length < MAX_TOKEN_LENGTH - 1)
      {
        token[token_length++] = c;
      }
    }
  }

  if (token_length > 0)
  {
    token[token_length] = '\0';
    classify_token(token);
  }

  fclose(file);
  return EXIT_SUCCESS;
}
