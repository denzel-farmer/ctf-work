#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void fail()
{
    printf("Fail\n");
    exit(1);
}

void win()
{
    printf("Win\n");
    exit(0);
}

bool check_index(char in_elem_char, int base_elem)
{
    unsigned int in_elem = (unsigned int)in_elem_char;
    if (in_elem < 32)
        return false;
    if (!base_elem)
        return false;

    int inner_iter = 0;
    while ((in_elem & 1) == 0)
    {
        ++inner_iter;
        in_elem = in_elem >> 1;
        if (base_elem == inner_iter)
            goto last_idx_check;

    back_in_while:
        if (in_elem == 1)
            return false;
    }

    ++inner_iter;
    in_elem = 3 * in_elem + 1;
    if (base_elem != inner_iter)
        goto back_in_while;

last_idx_check:
    if (in_elem != 1)
        return false;
    
    return true;
}

void test_check_index(int base_elem)
{
    for (int in_elem_char = 0; in_elem_char < 300; ++in_elem_char)
    {
        if (check_index((char) in_elem_char, base_elem))
        {
            printf("check_index returned true for in_elem_char: %c (0x%x) and base_elem: %d\n", in_elem_char, in_elem_char, base_elem);
        }
       //printf("In_elem_char: %c (0x%x) and base_elem: %d\n", in_elem_char, in_elem_char, base_elem);
    }
}

int main()
{
    test_check_index(0x1b);
    test_check_index(0x26);
    test_check_index(0x57);
    test_check_index(0x5f);
    test_check_index(0x76);
    test_check_index(0x09);
    return 0;
}

void process_input()
{
    char in_array[6];
    int base_array[6] = {0x1b, 0x26, 0x57, 0x5f, 0x76, 0x09};
    int last_check_var = 0;

    fgets(in_array, sizeof(in_array), stdin);

    for (int i = 0; i < 6; ++i)
    {
        int in_elem = in_array[i];
        if (in_elem < 32)
            fail();

        int base_elem = base_array[i];
        if (!base_elem)
            fail();

        int inner_iter = 0;

        while ((in_elem & 1) == 0)
        {
            ++inner_iter;
            in_elem = in_elem >> 1;
            if (base_elem == inner_iter)
                goto not_one_check;

        back_in_while:
            if (in_elem == 1)
                fail();
        }

        ++inner_iter;
        in_elem = 3 * in_elem + 1;
        if (base_elem != inner_iter)
            goto back_in_while;

    not_one_check:
        if (in_elem != 1)
            fail();
    }

    if (!last_check_var || last_check_var == 10)
    {
        win();
    }
}

// int main()
// {
//     process_input();
//     return 0;
// }