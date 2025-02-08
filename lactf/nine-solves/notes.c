char in_array[6] // by reference 

int base_array = {0x1b, 0x26, 0x57, 0x5f, 0x76, 0x09}
fgets(in_array, 16, stdin);


for (int i = 0; i != 6, ++i)
{
    // All char elements must be greater than 32d
    in_elem = in_array[i];
    if (in_elem < 32)
        fail();
    
    int base_elem = base_array[i];
    if !(base_elem)
        fail();
    
    int inner_iter;
    inner_iter = 0;
  
   // While in_elem is even, so (last digit of in_elem) == 0 
    while ( (in_elem & 1) == 0) {
        ++inner_iter;

        // Right shift in_elem  
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

if (!last_check_var || last_check_var == 10){
    win();
}
