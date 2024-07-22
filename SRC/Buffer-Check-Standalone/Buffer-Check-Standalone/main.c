#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>


#define DEBUG

void function1(void);

void function2(void);

int main(void) {
    printf("Calling Function 1\n");
    function1();
    printf("Calling Function 2\n");
    function2();
}

void function1(void) {
#ifdef DEBUG
    __asm int 3
#endif 
    int check;
    char v_buff[20];
    
    printf("User Input: ");
    scanf("%s", v_buff);

    printf("Exiting Function 1\n");
#ifdef DEBUG
    __asm int 3
#endif 
    return;
}

void function2(void) {
#ifdef DEBUG
    __asm int 3
#endif 
    return;
#ifdef DEBUG
    __asm int 3
#endif 
}