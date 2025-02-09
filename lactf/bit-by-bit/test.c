#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <unistd.h>

typedef uint64_t _QWORD;
typedef uint32_t _DWORD;
typedef uint16_t _WORD;
typedef uint8_t _BYTE;

int64_t decode_first_hostname_ns_rev(int64_t a1)
{
    int64_t result; // rax
    int i;          // [rsp+14h] [rbp-4h]

    for (i = 0;; ++i)
    {
        result = *(uint8_t *)(i + a1);
        if (!(_BYTE)result)
            break;
        *(_BYTE *)(i + a1) ^= 0x20u;
    }
    return result;
}

int64_t decode_hostname2_and_scramble_flag(int64_t a1)
{
    int64_t result; // rax
    int i;          // [rsp+14h] [rbp-4h]

    for (i = 0;; ++i)
    {
        result = *(uint8_t *)(i + a1);
        if (!(_BYTE)result)
            break;
        *(_BYTE *)(i + a1) ^= 3 * (_BYTE)i;
    }
    return result;
}

int64_t decode_formatstring(int64_t a1)
{
    int64_t result; // rax
    int i;          // [rsp+14h] [rbp-4h]

    for (i = 0;; ++i)
    {
        result = *(uint8_t *)(i + a1);
        if (!(_BYTE)result)
            break;
        *(_BYTE *)(i + a1) ^= 0x11u;
    }
    return result;
}

int bittest(const int *ptr, int bit)
{
    return (*ptr >> bit) & 1;
}

int64_t main(int a1, char **a2, char **a3)
{
    int64_t v3;                            // rsi
    char *v4;                              // rdi
    char *fgets_err;                       // rdx
    int64_t result;                        // rax
    struct hostent *ns1rev_hostent;        // rbx
    struct __res_state *resolv_state;      // rax
    size_t h_length;                       // rdx
    int len_ns_msg_len;                    // eax
    uint64_t len_rr_txt_len;                        // rax
    size_t input_flag_length;                     // rbx
    int msg_len;                               // eax
    char *maybe_output_rdata;              // rdi
    uint64_t rr_data_len;                  // rax
    const unsigned char *ns_rr_data_start; // rsi
    int64_t result_num_QQQ;                // rcx
    char *bit_info_str;                  // rax
    char *dup_bit_info_str;                    // r8
    const char *dup_next_dns_num_str;         // rdi
    unsigned int next_dns_num;    // eax
    void (*v22)(void);                     // rdx
    int input_flag_byte;                // eax
    unsigned int curr_dns_num;           // [rsp+4h] [rbp-1414h]
    char *next_dns_num_str;                   // [rsp+10h] [rbp-1408h]
    char *dup_bit_info_str;              // [rsp+10h] [rbp-1408h]
    int dup_bit_index;                            // [rsp+10h] [rbp-1408h]
    int bit_index;                     // [rsp+28h] [rbp-13F0h] BYREF
    int true_bit_value;                     // [rsp+2Ch] [rbp-13ECh] BYREF
    ns_msg len_ns_parse_handle;            // [rsp+30h] [rbp-13E8h] BYREF
    ns_msg ns_parse_handle;                            // [rsp+80h] [rbp-1398h] BYREF
    ns_rr len_ns_rr;                       // [rsp+D0h] [rbp-1348h] BYREF
    ns_rr ans_ns_rr;        // [rsp+4F0h] [rbp-F28h] BYREF
    unsigned char ns1rev_name_str[14];     // [rsp+915h] [rbp-B03h] BYREF
    unsigned char d_rev_fmt_str[14];  // [rsp+923h] [rbp-AF5h] BYREF
    unsigned char len_rev_name_str[15];    // [rsp+931h] [rbp-AE7h] BYREF
    char input_flag[144];                  // [rsp+940h] [rbp-AD8h] BYREF
    char curr_domain[256];            // [rsp+9D0h] [rbp-A48h] BYREF
    char len_rr_txt[256];                // [rsp+AD0h] [rbp-948h] BYREF
    unsigned char ans_array2[512];         // [rsp+BD0h] [rbp-848h] BYREF
    unsigned char ans_array[512];          // [rsp+DD0h] [rbp-648h] BYREF
    char query_data[1032];           // [rsp+FD0h] [rbp-448h] BYREF
    uint64_t v43;                          // [rsp+13D8h] [rbp-40h]

    // v43 = __readfsqword(0x28u);
    setvbuf(stdout, 0LL, 2, 0LL);

    __printf_chk(2LL, "Enter the flag: ");
    v3 = 129LL;

    // Read user test flag
    v4 = input_flag;
    fgets_err = fgets(input_flag, 129, stdin);
    result = 1LL;

    if (!fgets_err)
        goto exit_label;

    input_flag[strcspn(input_flag, "\n")] = 0; // Null/newline terminate?
                                               //
    __printf_chk(2LL, "Checking (this may take a while)");

    if (__res_init() < 0)
        goto an_err_occured;

    // Decode hostname ns1rev.lac.tf
    *(_QWORD *)ns1rev_name_str = 0x4C0E56455211534ELL;
    *(_QWORD *)&ns1rev_name_str[6] = 0x2046540E43414C0ELL;
    decode_first_hostname_ns_rev((int64_t)ns1rev_name_str);
    ns1rev_hostent = gethostbyname(ns1rev_name_str);

    if (!ns1rev_hostent)
    {
        v3 = 1LL;
        v4 = "\nAn unexpected error occurred. Is the program running in a restricted sandbox?\n";
        fwrite(
            "\nAn unexpected error occurred. Is the program running in a restricted sandbox?\n",
            1uLL,
            0x4FuLL,
            stderr);
        goto LABEL_38;
    }

    // Set DNS nameserver address
    resolv_state = __res_state();
    h_length = ns1rev_hostent->h_length;
    resolv_state->nscount = 1;
    memcpy(&resolv_state->nsaddr_list[0].sin_addr, *(const void **)ns1rev_hostent->h_addr_list, h_length);

    // Decode hostname len.rev.lac.tf
    *(_QWORD *)len_rev_name_str = 0x3B646A7E2768666CLL;
    *(_QWORD *)&len_rev_name_str[7] = 0x2A41500F7D7A743BLL;
    // NOTE: appears to also scramble the input flag--maybe a bug? Maybe final decode step?
    decode_hostname2_and_scramble_flag((int64_t)len_rev_name_str);

    // Query len.rev.lac.tf to get expected flag length (37d)
    len_ns_msg_len = res_query(len_rev_name_str, ns_c_in, ns_t_txt, ans_array, sizeof(ans_array));
    
    // Parse response to get expected_flag_length
    if (len_ns_msg_len < 0 ||
        (ns_initparse(ans_array, len_ns_msg_len, &len_ns_parse_handle),
         ns_parserr(&len_ns_parse_handle, ns_s_an, 0, &len_ns_rr) < 0) ||
        len_ns_rr.type != 16)
    {
    an_err_occured:
        v3 = 1LL;
        v4 = "\nAn unexpected error occurred.\n";
        fwrite("\nAn unexpected error occurred.\n", 1uLL, 0x1FuLL, stderr);
    LABEL_38:
        result = 4294967294LL;
        goto exit_label;
    }
    len_rr_txt_len = *len_ns_rr.rdata;
    memcpy(len_rr_txt, len_ns_rr.rdata + 1, len_rr_txt_len);
    len_rr_txt[len_rr_txt_len] = 0;
    v3 = 0LL;
    
    // Check input flag length
    input_flag_length = strlen(input_flag);
    if (input_flag_length != (int)strtol(len_rr_txt, 0LL, 10))
    {
        v4 = "\nIncorrect.";
        puts("\nIncorrect.");
        goto LABEL_38;
    }

    // Begin DNS query loop
    curr_dns_num = 0;
    while (1)
    {
        // Decode format string %d.rev.lac.tf
        *(_QWORD *)d_rev_fmt_str = 0x7D3F6774633F7534LL;
        *(_QWORD *)&d_rev_fmt_str[6] = 0x1177653F72707D3FLL;
        decode_formatstring((int64_t)d_rev_fmt_str);

        // Construct actual domain name and make request
        __snprintf_chk(curr_domain, 256LL, 2LL, 256LL, d_rev_fmt_str, curr_dns_num);
        msg_len = res_query(curr_domain, ns_c_in, ns_t_txt, ans_array2, sizeof(ans_array2));
        if (msg_len < 0)
            break;

        // Parse TXT response from ANSWER section
        ns_initparse(ans_array2, msg_len, &ns_parse_handle);
        if (ns_parserr(&ns_parse_handle, ns_s_an, 0, &ans_ns_rr) < 0)
            break;
        if (ans_ns_rr.type == 16) // TXT 
        {
            // Complicated parsing code, extracts from rdata in chunks to populate query_data
            maybe_output_rdata = query_data;
            rr_data_len = *ans_ns_rr.rdata;
            ns_rr_data_start = ans_ns_rr.rdata + 1;
            if ((unsigned int)rr_data_len >= 8)
            {
                memcpy(query_data, ns_rr_data_start, 8 * (rr_data_len >> 3));
                ns_rr_data_start += 8 * (rr_data_len >> 3);
                maybe_output_rdata = &query_data[8 * (rr_data_len >> 3)];
            }
            result_num_QQQ = 0LL;
            if ((rr_data_len & 4) != 0)
            {
                *(_DWORD *)maybe_output_rdata = *(_DWORD *)ns_rr_data_start;
                result_num_QQQ = 4LL;
            }
            if ((rr_data_len & 2) != 0)
            {
                *(_WORD *)&maybe_output_rdata[result_num_QQQ] = *(_WORD *)&ns_rr_data_start[result_num_QQQ];
                result_num_QQQ += 2LL;
            }
            if ((rr_data_len & 1) != 0)
                maybe_output_rdata[result_num_QQQ] = ns_rr_data_start[result_num_QQQ];
            query_data[rr_data_len] = 0;

            // Query data is ASCII string in format "<next dns num>;<bit index>,<bit value>", where bit index and value optional
            
            // Split next dns num and bit info
            next_dns_num_str = strtok(query_data, ";");
            bit_info_str = strtok(0LL, ";");
            dup_bit_info_str = bit_info_str;
            if (next_dns_num_str)
            {
                // Code I added, dumps sequence to disk
                FILE *seq_file = fopen("sequence.txt", "a");
                if (seq_file != NULL)
                {
                    fprintf(seq_file, "%s\n", next_dns_num_str);
                    fclose(seq_file);
                }
                else
                {
                    perror("Error opening sequence file");
                }
            
                v3 = 0LL;

                // Convert next dns num to long
                dup_next_dns_num_str = next_dns_num_str;
                dup_bit_info_str = bit_info_str;
                next_dns_num = strtol(dup_next_dns_num_str, 0LL, 10);
                dup_bit_info_str = dup_bit_info_str;

                // Update current dns num
                curr_dns_num = next_dns_num;

                // If second string is null but first string is not, check if correct and if not continue
                if (!dup_bit_info_str)
                    goto check_end_continue;
                goto parse_bitinfo;
            }
            if (bit_info_str)
            {
            parse_bitinfo:
                // My added printing/dumping code
                printf("Second string exists: (%s)\n", dup_bit_info_str);
                FILE *seq_file = fopen("sequence.txt", "a");
                if (seq_file != NULL)
                {
                    fprintf(seq_file, "SECOND STRING: %s (first string was %s)\n", dup_bit_info_str, next_dns_num_str);
                    fclose(seq_file);
                }
                else
                {
                    perror("Error opening sequence file");
                }

                v3 = (int64_t)"%d,%d";

                // Parse bit info -> bit index and bit value
                if ((unsigned int)sscanf(dup_bit_info_str, "%d,%d", &bit_index, &true_bit_value) == 2)
                {
                    dup_bit_index = bit_index;
                    if (dup_bit_index < 8 * strlen(input_flag))
                    {
                        // Convert bit_index to byte index by dividing by 8 (>> 3), extract indexed byte
                        input_flag_byte = input_flag[dup_bit_index >> 3];

                        // Check the bit at index into the byte (endianess: ??)
                        if (bittest(&input_flag_byte, ~(_BYTE)dup_bit_index & 7))
                        {
                            if (!true_bit_value)
                            {
                            incorrect_exit:
                                v4 = "\nIncorrect.";
                                puts("\nIncorrect.");
                                // NOTE: Commented out this goto so binary will continue even if input flag incorrect
                                // goto exit_ret_negone;
                            }
                        }
                        else if (true_bit_value == 1)
                        {
                            // NOTE: Commented out this goto so binary will continue even if input flag incorrect
                            // goto incorrect_exit;
                        }
                    }
                }
            check_end_continue:
                sleep(1u);
                // putchar(46);
                if (curr_dns_num == -1)
                {
                    v4 = "Correct!";
                    puts("Correct!");
                    result = 0LL;
                    goto exit_label;
                }
            }
            else
            {
                sleep(1u);
                // putchar(46);
            }
        }
    }
    v3 = 1LL;
    v4 = "\nAn unexpected error occurred.\n";
    fwrite("\nAn unexpected error occurred.\n", 1uLL, 0x1FuLL, stderr);
exit_ret_negone:
    result = 0xFFFFFFFFLL;
exit_label:
    printf("EXIT CODE: %lld\n", v3);
    return result;
}
