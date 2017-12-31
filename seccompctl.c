// [eval.in](http://eval.in) is a really cool website that lets you run
// source code under a variety of interpreters.

// I've always found the idea of sandboxes fascinating, so I tried to figure out how it's built. After some reading, I ended up building my own sandbox system, [Minival](https://seccomp-eval.herokuapp.com/).
//
// What you are reading right now is the commented source for this sandbox, which also serve as a tutorial of sorts about sandboxing. 
//
// You shouldn't need to have more than some passing knowledge of C and UNIX syscalls to understand this tutorial, so let's jump right in!
//
// ## What's a sandbox?
//
// Simply put, a sandbox is a restricted environment that lets you run 3rd-party code without any risks. For example, browsing the web usually doesn't crash you computer or let hackers steal your personal data. That's because your browser runs Javascript code in a sandbox, to prevents it from doing dangerous things (mostly).
//
// What we're going to build here a similar, but simpler type of sandbox. We want to let people run simply Python and Perl scripts on our server.
// Because some people have a tendency to break things, we need to limit users in what they can do. Basically, we want to let people run simple scripts that will write to stdout and that's about it. To do that there's a couple of ways we could go with:
// 1. we could use a language feature to limit what 3rd-party code can do ([rpython](https://docs.python.org/2/library/restricted.html) or [Safe PERL](http://perldoc.perl.org/Safe.html) are examples of this).
// 2. we could ask the operating system to restrict what the program can do. It's hard to break out of a sandbox if the OS kills the process whenever it tries to do an I/O operation.
// 3. we could do some complicated static analysis of the code. Google's [NaCL](https://media.blackhat.com/bh-us-12/Briefings/Rohlf/BH_US_12_Rohlf_Google_Native_Client_WP.pdf) uses this approach.

// 1/ is hard to implement because we'd have to think through every possible way people could use Python to break out of the sandbox.
// 3/ would require an expertise about assembly and binary that I don't have.
//
// That leaves us with 2/ – using OS primitives to somehow constrain processes.

// After reading a lot of Stackoverflow questions, I found out that there really are two ways to limit processes:
// 1. use ptrace(2), a debugging interface that lets you [peek around a process](http://man7.org/linux/man-pages/man2/ptrace.2.html)
// 2. use seccomp(2), a Linux-only system call that lets a process define a whitelist of system calls it's allowed to make.

// Ptrace seems fine – I heard that that's what [eval.in](https://eval.in) uses - but it would be a little annoying to implement in Python. It also has a non-negligible performance hit.

// Seccomp seemed a bit better at the time, even though it didn't really have a good Python interface, which caused me to end up writing everything in C.


//
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <seccomp.h>
#include <signal.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage: seccompctl <python|perl|ruby> source_file\n");
        exit(-1);
    }

    // First, setup an rlimit limit.
    struct rlimit rl;
    rl.rlim_cur = 10;
    setrlimit (RLIMIT_CPU, &rl);

    // Init the filter
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

    // setup basic whitelist
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getaffinity), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);

    // Don't let people open files in read-write mode.
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
            SCMP_A1(SCMP_CMP_EQ, O_RDONLY));

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
            SCMP_A1(SCMP_CMP_EQ, O_RDONLY|O_CLOEXEC));

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
            SCMP_A1(SCMP_CMP_EQ, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC));

    // Disable sockets that aren't local
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
            SCMP_A0(SCMP_CMP_EQ, AF_LOCAL));

    // This is a one-off rule for perl
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
            SCMP_A2(SCMP_CMP_EQ, FD_CLOEXEC));


    // Limit writes to the stdin, stdout and stderr.
    for (int i = 0; i < 3; i++) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                                  SCMP_A0(SCMP_CMP_EQ, i));
    }

    // build and load the filter
    seccomp_load(ctx);

    if (strncmp(argv[1], "python", 16) == 0) {
        char *args[] = { "/usr/bin/python", argv[2], 0};
        execve(args[0], (char **const) &args, NULL);
    } else if (strncmp(argv[1], "perl", 16) == 0) {
        char *args[] = { "/usr/bin/perl", argv[2], 0};
        execve(args[0], (char **const) &args, NULL);
    }

    return 0;
}
