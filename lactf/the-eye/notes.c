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

// Undoes a single shuffle assuming assuming rand() returns in the same order as the corresponding shuffle()
// Will call rand() the same number of times
void unshuffle(char *target)
{
  // Decoder calls rand()
  int64_t len;

  len = (unsigned int)strlen(target) - 1;
  for (int i = len; i >= 0; --i)
  {
    int rand_char_index = rand() % (i + 1);
    uint8_t curr_char = target[i];
    target[i] = target[rand_char_index];
    target[rand_char_index] = curr_char;
  }
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

struct swap_idx_op
{
  int idx1;
  int idx2;
};

void decode(char *target, unsigned int seed, int num_shuffles)
{
  srand(seed);
  int len = strlen(target);
  int num_swap_ops = num_shuffles * len;
  struct swap_idx_op *swap_ops = malloc(num_swap_ops * sizeof(struct swap_idx_op));

  // For each round of shuffling, store the swap operations
  int swap_op_index = 0;
  for (int i = 0; i < num_shuffles; i++)
  {
    // For a single round of shuffling, iterate through the string from the end
    for (int j = len - 1; j >= 0; j--)
    {

      // Rand char produced by shuffle()
      int rand_char_index = rand() % (j + 1);

      struct swap_idx_op swap_op;
      swap_op.idx1 = j;
      swap_op.idx2 = rand_char_index;

      swap_ops[swap_op_index] = swap_op;
      swap_op_index++;
    }
  }

  // Undo the swap operations in reverse order
  for (int i = num_swap_ops - 1; i >= 0; i--)
  {
    struct swap_idx_op swap_op = swap_ops[i];
    int idx1 = swap_op.idx1;
    int idx2 = swap_op.idx2;

    uint8_t curr_char = target[idx1];
    target[idx1] = target[idx2];
    target[idx2] = curr_char;
  }
}

int main(int argc, const char **argv, const char **envp)
{
  unsigned int curr_time; // eax
  int64_t v4;             // rdi
  char *s, *target;       // [rsp+0h] [rbp-10h]
  int i;                  // [rsp+Ch] [rbp-4h]

  curr_time = time(0LL);
  printf("Current time: %u\n", curr_time);
  v4 = curr_time;
  srand(curr_time);

  s = (char *)read_msg(v4, argv);
  target = strdup(s);

  for (i = 0; i <= 21; ++i)
    shuffle(s);

  puts(s);

  // Use encode() to encode the string and make sure it matches
  unsigned int seed = curr_time;
  int num_shuffles = 22;

  printf("\nOriginal: %s\n", target);
  encode(target, seed, num_shuffles);
  printf("\nEncoded: %s\n", target);
  decode(target, seed, num_shuffles);
  printf("\nDecoded: %s\n", target);

  // Use decode() to decode the string

  free(target);

  free(s);
  return 0;
}