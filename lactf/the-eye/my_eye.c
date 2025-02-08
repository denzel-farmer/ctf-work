#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void *read_msg()
{
    void *ptr;    // [rsp+8h] [rbp-18h]
    FILE *stream; // [rsp+10h] [rbp-10h]
    int64_t n;    // [rsp+18h] [rbp-8h]

    stream = fopen("msg.txt", "rb");
    if (!stream)
    {
        puts("msg.txt is missing");
        exit(1);
    }
    fseek(stream, 0LL, 2);
    n = ftell(stream);
    ptr = malloc(n + 1);

    fseek(stream, 0LL, 0);
    fread(ptr, 1uLL, n, stream);
    fclose(stream);

    if (*((uint8_t *)ptr + n - 1) == 10)
    {
        --n;
    }

    *((uint8_t *)ptr + n) = 0;
    return ptr;
}

// For each character in the string starting from the end, swap it
// with a random, previous character
int64_t shuffle(char *target)
{
    int64_t len, result; // rax
    int i;               // [rsp+1Ch] [rbp-4h]

    len = (unsigned int)strlen(target) - 1;

    // printf("Length of string: %ld\n", len+1);

    int count_swaps = 0;

    // Decrement from result length-1 to 0
    for (i = len; i >= 0; --i)
    {
        // Get an index between 0 and i+1
        int rand_char_index = rand() % (i + 1);

        // Swap the characters at i and rand_char_index
        uint8_t curr_char = target[i];
        target[i] = target[rand_char_index];
        target[rand_char_index] = curr_char;

        result = curr_char;

        count_swaps++;
    }

    // printf("Number of swaps: %d\n", count_swaps);

    return result;
}

void encode(char *target, unsigned int seed, int num_shuffles)
{
    srand(seed);
    int count_shuffles = 0;
    for (int i = 0; i < num_shuffles; i++)
    {
        count_shuffles++;
        shuffle(target);
    }

    printf("Number of shuffles: %d\n", count_shuffles);
}

int main(int argc, const char **argv, const char **envp)
{
    unsigned int curr_time; // eax
    int64_t v4;             // rdi
    char *s, *target;       // [rsp+0h] [rbp-10h]
    int i;                  // [rsp+Ch] [rbp-4h]

    curr_time = time(0LL);
    // fprintf(stderr, "Current time: %u\n", curr_time);
    v4 = curr_time;
    srand(curr_time);

    s = (char *)read_msg(v4, argv);
    // target = strdup(s);

    for (i = 0; i <= 21; ++i)
        shuffle(s);

    puts(s);


    free(s);

    FILE *time_file = fopen("time.txt", "w");
    if (time_file)
    {
        fprintf(time_file, "%u\n", curr_time);
        fclose(time_file);
    }
    else
    {
        puts("Failed to open time.txt for writing");
    }

    return 0;
}