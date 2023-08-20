// ----- .bss = global un-initialized data ----- V
// #include <stdio.h>
// #include <stdlib.h>
// int b;

// int main(int argc, char *argv[]){
//     b = 0;
//     printf("b = %d\n", b);

//     b = 100;
//     printf("b = %d\n", b);


//     return 0;
// }

// ----- .data = global initialized data ----- V
// #include <stdio.h>
// #include <stdlib.h>
// int b = 0;

// int main(int argc, char *argv[]){

//     printf("b = %d\n", b);

//     b = 100;
//     printf("b = %d\n", b);


//     return 0;
// }

// ----- stack = local variable ----- V
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[]){
    int b = 0;
    printf("b = %d\n", b);

    b = 100;
    printf("b = %d\n", b);


    return 0;
}


// ----- heap = calloc ----- V 
// #include <stdio.h>
// #include <stdlib.h>

// int main(int argc, char *argv[]){
//     int *a = (int *)calloc(1, sizeof(int));

//     printf("b = %d\n", *a);

//     *a = 100;
//     printf("b = %d\n", *a);


//     return 0;
// }