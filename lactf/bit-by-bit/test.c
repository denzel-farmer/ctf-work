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
    struct hostent *hostname_struct_ptr;   // rbx
    struct __res_state *dns_res_state_QQ;  // rax
    size_t h_length;                       // rdx
    int v10;                               // eax
    uint64_t cplen;                        // rax
    size_t myflag_len;                     // rbx
    int v13;                               // eax
    char *maybe_output_rdata;              // rdi
    uint64_t rr_data_len;                  // rax
    const unsigned char *ns_rr_data_start; // rsi
    int64_t result_num_QQQ;                // rcx
    char *second_str_ldo;                  // rax
    char *sscanf_input;                    // r8
    const char *dup_first_str_ldo;         // rdi
    unsigned int first_str_ldo_to_long;    // eax
    void (*v22)(void);                     // rdx
    int flag_char_to_check;                // eax
    unsigned int corr_check_ptr;           // [rsp+4h] [rbp-1414h]
    char *first_str_ldo;                   // [rsp+10h] [rbp-1408h]
    char *dup_second_str_ldo;              // [rsp+10h] [rbp-1408h]
    int d1_out;                            // [rsp+10h] [rbp-1408h]
    int sscanf_out_d1;                     // [rsp+28h] [rbp-13F0h] BYREF
    int sscanf_out_d2;                     // [rsp+2Ch] [rbp-13ECh] BYREF
    ns_msg v30;                            // [rsp+30h] [rbp-13E8h] BYREF
    ns_msg v31;                            // [rsp+80h] [rbp-1398h] BYREF
    ns_rr ns_rr_struct_parser_out;         // [rsp+D0h] [rbp-1348h] BYREF
    ns_rr ns_rr_struct_parser_out2;        // [rsp+4F0h] [rbp-F28h] BYREF
    unsigned char ns_rev_lac_name[14];     // [rsp+915h] [rbp-B03h] BYREF
    unsigned char decoded_fmt_string[14];  // [rsp+923h] [rbp-AF5h] BYREF
    unsigned char hostname_str_2[15];      // [rsp+931h] [rbp-AE7h] BYREF
    char some_flag_shuffled_QQ[144];       // [rsp+940h] [rbp-AD8h] BYREF
    char decoded_snprintf[256];            // [rsp+9D0h] [rbp-A48h] BYREF
    char ns_rdata_out[256];                // [rsp+AD0h] [rbp-948h] BYREF
    unsigned char const_1_qq[512];         // [rsp+BD0h] [rbp-848h] BYREF
    unsigned char v41[512];                // [rsp+DD0h] [rbp-648h] BYREF
    char long_data_out_QQ[1032];           // [rsp+FD0h] [rbp-448h] BYREF
    uint64_t v43;                          // [rsp+13D8h] [rbp-40h]

    // v43 = __readfsqword(0x28u);
    setvbuf(stdout, 0LL, 2, 0LL);

    __printf_chk(2LL, "Enter the flag: ");
    v3 = 129LL;

    v4 = some_flag_shuffled_QQ;
    fgets_err = fgets(some_flag_shuffled_QQ, 129, stdin);
    result = 1LL;

    if (!fgets_err)
        goto exit_label;

    some_flag_shuffled_QQ[strcspn(some_flag_shuffled_QQ, "\n")] = 0; // Null/newline terminate?
                                                                     //
    __printf_chk(2LL, "Checking (this may take a while)");

    if (__res_init() < 0)
        goto an_err_occured;

    *(_QWORD *)ns_rev_lac_name = 0x4C0E56455211534ELL;
    *(_QWORD *)&ns_rev_lac_name[6] = 0x2046540E43414C0ELL;
    decode_first_hostname_ns_rev((int64_t)ns_rev_lac_name); // NS REV LACTF
                                                            //
    hostname_struct_ptr = gethostbyname(ns_rev_lac_name);

    if (!hostname_struct_ptr)
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

    dns_res_state_QQ = __res_state();
    h_length = hostname_struct_ptr->h_length;
    dns_res_state_QQ->nscount = 1;
    memcpy(&dns_res_state_QQ->nsaddr_list[0].sin_addr, *(const void **)hostname_struct_ptr->h_addr_list, h_length);

    *(_QWORD *)hostname_str_2 = 0x3B646A7E2768666CLL;
    *(_QWORD *)&hostname_str_2[7] = 0x2A41500F7D7A743BLL; // len.rev.lac
    decode_hostname2_and_scramble_flag((int64_t)hostname_str_2);
    v10 = res_query(hostname_str_2, ns_c_in, ns_t_txt, v41, sizeof(v41));
    if (v10 < 0 || (ns_initparse(v41, v10, &v30), ns_parserr(&v30, ns_s_an, 0, &ns_rr_struct_parser_out) < 0) || ns_rr_struct_parser_out.type != 16)
    {
    an_err_occured:
        v3 = 1LL;
        v4 = "\nAn unexpected error occurred.\n";
        fwrite("\nAn unexpected error occurred.\n", 1uLL, 0x1FuLL, stderr);
    LABEL_38:
        result = 4294967294LL;
        goto exit_label;
    }
    cplen = *ns_rr_struct_parser_out.rdata;
    memcpy(ns_rdata_out, ns_rr_struct_parser_out.rdata + 1, cplen);
    ns_rdata_out[cplen] = 0;
    v3 = 0LL;
    myflag_len = strlen(some_flag_shuffled_QQ); // obfuscated?
    if (myflag_len != (int)strtol(ns_rdata_out, 0LL, 10))
    {
        v4 = "\nIncorrect.";
        puts("\nIncorrect.");
        goto LABEL_38;
    }
    corr_check_ptr = 6835232;
    while (1)
    {
        *(_QWORD *)decoded_fmt_string = 0x7D3F6774633F7534LL;
        *(_QWORD *)&decoded_fmt_string[6] = 0x1177653F72707D3FLL;
        decode_formatstring((int64_t)decoded_fmt_string);
        __snprintf_chk(decoded_snprintf, 256LL, 2LL, 256LL, decoded_fmt_string, corr_check_ptr);
        v13 = res_query(decoded_snprintf, ns_c_in, ns_t_txt, const_1_qq, sizeof(const_1_qq));
        if (v13 < 0)
            break;
        ns_initparse(const_1_qq, v13, &v31);
        if (ns_parserr(&v31, ns_s_an, 0, &ns_rr_struct_parser_out2) < 0)
            break;
        if (ns_rr_struct_parser_out2.type == 16)
        {
            maybe_output_rdata = long_data_out_QQ;
            rr_data_len = *ns_rr_struct_parser_out2.rdata;
            ns_rr_data_start = ns_rr_struct_parser_out2.rdata + 1;
            if ((unsigned int)rr_data_len >= 8)
            {
                memcpy(long_data_out_QQ, ns_rr_data_start, 8 * (rr_data_len >> 3));
                ns_rr_data_start += 8 * (rr_data_len >> 3);
                maybe_output_rdata = &long_data_out_QQ[8 * (rr_data_len >> 3)];
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
            long_data_out_QQ[rr_data_len] = 0;

            first_str_ldo = strtok(long_data_out_QQ, ";");
            second_str_ldo = strtok(0LL, ";");
            sscanf_input = second_str_ldo;
            if (first_str_ldo)
            {
                FILE *seq_file = fopen("sequence.txt", "a");
                if (seq_file != NULL) {
                    fprintf(seq_file, "%s\n", first_str_ldo);
                    fclose(seq_file);
                } else {
                    perror("Error opening sequence file");
                }
                v3 = 0LL;
                dup_first_str_ldo = first_str_ldo;
                dup_second_str_ldo = second_str_ldo;
                first_str_ldo_to_long = strtol(dup_first_str_ldo, 0LL, 10);
                sscanf_input = dup_second_str_ldo;
                corr_check_ptr = first_str_ldo_to_long;
                // If second string is null but first string is not, check if finished
                if (!dup_second_str_ldo)
                    goto sleep_putchar_corrcheck;
                goto sscanf_stuff;
            }
            if (second_str_ldo)
            {
            sscanf_stuff:
                printf("Second string exists: (%s)\n", sscanf_input);

                FILE *seq_file = fopen("sequence.txt", "a");
                if (seq_file != NULL) {
                    fprintf(seq_file, "SECOND STRING: %s (first string was %s)\n", sscanf_input, first_str_ldo);
                    fclose(seq_file);
                } else {
                    perror("Error opening sequence file");
                }

                v3 = (int64_t)"%d,%d";
                if ((unsigned int)sscanf(sscanf_input, "%d,%d", &sscanf_out_d1, &sscanf_out_d2) == 2)
                {
                    d1_out = sscanf_out_d1;
                    if (d1_out < 8 * strlen(some_flag_shuffled_QQ))
                    {
                        // d1_out is bit index into entire flag, bucket into byte intex
                        flag_char_to_check = some_flag_shuffled_QQ[d1_out >> 3];

                        // Check the bit at index into the byte (endianess: ??)
                        if (bittest(&flag_char_to_check, ~(_BYTE)d1_out & 7))
                        {
                            if (!sscanf_out_d2)
                            {
                            incorrect_exit:
                                v4 = "\nIncorrect.";
                                puts("\nIncorrect.");
                               // goto exit_ret_negone;
                            }
                        }
                        else if (sscanf_out_d2 == 1)
                        {
                            goto incorrect_exit;
                        }
                    }
                }
            sleep_putchar_corrcheck:
                sleep(1u);
                // putchar(46);
                if (corr_check_ptr == -1)
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
/* Orphan comments:


*/