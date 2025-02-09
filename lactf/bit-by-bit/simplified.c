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
    int result = (*ptr >> bit) & 1;
    printf("bittest: checking bit %d of value %d (binary: ", bit, *ptr);
    for (int j = sizeof(int) * 8 - 1; j >= 0; j--)
    {
        printf("%d", (*ptr >> j) & 1);
    }
    printf("), result: %d\n", result);
    return result;
}

int is_incorrect_bit(int num_one, int num_two, char *input_flag_shuffled)
{
    int check_idx = num_one >> 3;
    int elem_check = input_flag_shuffled[check_idx];

    // Invert the bits and mask all but last 3 to get bit index
    int bit_idx = (~(uint8_t)num_one) & 7;

    if (bittest(&elem_check, bit_idx))
    {
        if (!num_two)
        {
            return 1;
        }
    }
    else if (num_two == 1)
    {
        return 1;
    }

    printf("Bit check passed\n");
    return 0;
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
    char *part_two;                        // rax
    char *sscanf_input;                    // r8
    const char *dup_part_one;              // rdi
    unsigned int part_one_to_long;         // eax
    void (*v22)(void);                     // rdx
    int flag_char_to_check;                // eax
    unsigned int dns_base_num;             // [rsp+4h] [rbp-1414h]
    char *part_one;                        // [rsp+10h] [rbp-1408h]
    // char *dup_part_two;              // [rsp+10h] [rbp-1408h]
    int d1_out;                           // [rsp+10h] [rbp-1408h]
    int sscanf_out_d1;                    // [rsp+28h] [rbp-13F0h] BYREF
    int sscanf_out_d2;                    // [rsp+2Ch] [rbp-13ECh] BYREF
    ns_msg v30;                           // [rsp+30h] [rbp-13E8h] BYREF
    ns_msg v31;                           // [rsp+80h] [rbp-1398h] BYREF
    ns_rr ns_rr_struct_parser_out;        // [rsp+D0h] [rbp-1348h] BYREF
    ns_rr ns_rr_struct_parser_out2;       // [rsp+4F0h] [rbp-F28h] BYREF
    unsigned char ns_rev_lac_name[14];    // [rsp+915h] [rbp-B03h] BYREF
    unsigned char decoded_fmt_string[14]; // [rsp+923h] [rbp-AF5h] BYREF
    unsigned char hostname_str_2[15];     // [rsp+931h] [rbp-AE7h] BYREF
    char input_flag_shuffled[144];        // [rsp+940h] [rbp-AD8h] BYREF
    char decoded_snprintf[256];           // [rsp+9D0h] [rbp-A48h] BYREF
    char ns_rdata_out[256];               // [rsp+AD0h] [rbp-948h] BYREF
    unsigned char const_1_qq[512];        // [rsp+BD0h] [rbp-848h] BYREF
    unsigned char v41[512];               // [rsp+DD0h] [rbp-648h] BYREF
    char dns_msg_str[1032];               // [rsp+FD0h] [rbp-448h] BYREF
    uint64_t v43;                         // [rsp+13D8h] [rbp-40h]

    // v43 = __readfsqword(0x28u);
    setvbuf(stdout, 0LL, 2, 0LL);

    __printf_chk(2LL, "Enter the flag: ");
    v3 = 129LL;

    v4 = input_flag_shuffled;
    fgets_err = fgets(input_flag_shuffled, 129, stdin);
    result = 1LL;

    if (!fgets_err)
        goto exit_label;

    input_flag_shuffled[strcspn(input_flag_shuffled, "\n")] = 0; // Null/newline terminate?
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
    myflag_len = strlen(input_flag_shuffled); // obfuscated?
    if (myflag_len != (int)strtol(ns_rdata_out, 0LL, 10))
    {
        v4 = "\nIncorrect.";
        puts("\nIncorrect.");
        goto LABEL_38;
    }
    dns_base_num = 281583;
    while (1)
    {
        *(_QWORD *)decoded_fmt_string = 0x7D3F6774633F7534LL;
        *(_QWORD *)&decoded_fmt_string[6] = 0x1177653F72707D3FLL;
        decode_formatstring((int64_t)decoded_fmt_string);
        __snprintf_chk(decoded_snprintf, 256LL, 2LL, 256LL, decoded_fmt_string, dns_base_num);
        v13 = res_query(decoded_snprintf, ns_c_in, ns_t_txt, const_1_qq, sizeof(const_1_qq));
        if (v13 < 0)
            break;
        ns_initparse(const_1_qq, v13, &v31);
        if (ns_parserr(&v31, ns_s_an, 0, &ns_rr_struct_parser_out2) < 0)
            break;
        if (ns_rr_struct_parser_out2.type == 16)
        {
            // DO COPYING
            maybe_output_rdata = dns_msg_str;                      // internal
            rr_data_len = *ns_rr_struct_parser_out2.rdata;         // internal
            ns_rr_data_start = ns_rr_struct_parser_out2.rdata + 1; // internal
            if ((unsigned int)rr_data_len >= 8)
            {
                memcpy(dns_msg_str, ns_rr_data_start, 8 * (rr_data_len >> 3));
                ns_rr_data_start += 8 * (rr_data_len >> 3);
                maybe_output_rdata = &dns_msg_str[8 * (rr_data_len >> 3)];
            }
            result_num_QQQ = 0LL; // internal
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
            dns_msg_str[rr_data_len] = 0;
            // COPYING DONE

            // <next dns num>;<bit info 1>,<bit info 2>


            // Print dns_msg_str
            printf("DNS Message: %s\n", dns_msg_str);

            part_one = strtok(dns_msg_str, ";");
            part_two = strtok(0LL, ";");

            // From part 1, collect next dns_base_num
            if (part_one)
            {
                printf("Part 1: %s, updating base_num\n", part_one);
                dns_base_num = strtol(part_one, 0LL, 10);

                // If second string is null but first string is not, check if finished
                if (!part_two)
                {
                    printf("Part 2 is null, checking if finished\n");
                    goto sleep_putchar_corrcheck;
                }
                goto sscanf_stuff;
            }
            if (part_two)
            {
                printf("Part 2 exists: (%s)\n", part_two);
            sscanf_stuff:
                int num_one, num_two;
                unsigned int result_num = sscanf(part_two, "%d,%d", &num_one, &num_two);
                if (result_num == 2)
                {
                    if (num_one < 8 * strlen(input_flag_shuffled))
                    {
                        if (is_incorrect_bit(num_one, num_two, input_flag_shuffled))
                        {
                            printf("Incorrect bit found: %d, %d\n", num_one, num_two);
                            return 1;
                        }
                    }
                }
            sleep_putchar_corrcheck:
                // usleep(550000);
                sleep(1);
                putchar(46);
                // Last dns base num will be max-1
                if (dns_base_num == -1)
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
                putchar(46);
            }
        }
    }
    v3 = 1LL;
    v4 = "\nAn unexpected error occurred.\n";
    fwrite("\nAn unexpected error occurred.\n", 1uLL, 0x1FuLL, stderr);
exit_ret_negone:
    result = 0xFFFFFFFFLL;
exit_label:
    return result;
}
/* Orphan comments:


*/