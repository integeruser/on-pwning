# on-pwning
This repository contains my solutions to some CTF challenges and a list of interesting resources about pwning stuff.

## Readings

- [A binary analysis, count me if you can](http://shell-storm.org/blog/A-binary-analysis-count-me-if-you-can/)
- [A Memory Allocator](http://g.oswego.edu/dl/html/malloc.html)
- [About Exploits Writing](https://paper.seebug.org/papers/Archive/refs/2002.gera_.About_Exploits_Writing.pdf)
- [Collection of Known Patching Techniques](https://github.com/secretsquirrel/the-backdoor-factory/wiki/5.-Collection-of-Known-Patching-Techniques) • ELF
- [Common Pitfalls When Writing Exploits](http://www.mathyvanhoef.com/2012/11/common-pitfalls-when-writing-exploits.html)
- [Controlling uninitialized memory with LD_PRELOAD](http://vulnfactory.org/blog/2010/04/08/controlling-uninitialized-memory-with-ld_preload/)
- [Cross debugging for MIPS ELF with QEMU/toolchain](https://reverseengineering.stackexchange.com/questions/8829/cross-debugging-for-mips-elf-with-qemu-toolchain)
- [[CB16] House of Einherjar — Yet Another Heap Exploitation Technique on GLIBC by Hiroki Matsukuma](https://www.slideshare.net/codeblue_jp/cb16-matsukuma-en-68459606)
- [ELF Binary Code Injection, Loader/'Decrypter'](http://www.pinkstyle.org/elfcrypt.html)
- [Exploiting Format String Vulnerabilities](https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf)
- [Heap Exploitation](https://heap-exploitation.dhavalkapil.com/)
- [How main() is executed on Linux](http://www.tldp.org/LDP/LG/issue84/hawk.html)
- [How to Create a Virus Using the Assembly Language](https://cranklin.wordpress.com/2016/12/26/how-to-create-a-virus-using-the-assembly-language/)
- [Injecting missing methods at runtime \| Hopper Disassembler](https://www.hopperapp.com/blog/?p=219)
- [Linux x86 Program Start Up](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)
- [linux-insides](https://0xax.gitbooks.io/linux-insides/)
- [Memory Corruption Attacks: The (almost) Complete History](https://media.blackhat.com/bh-us-10/whitepapers/Meer/BlackHat-USA-2010-Meer-History-of-Memory-Corruption-Attacks-wp.pdf)
- [Playing with canaries](https://www.elttam.com.au/blog/playing-with-canaries/)
- [Pwning coworkers thanks to LaTeX](https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)
- [Qualys Security Advisory - The Stack Clash](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt)
- [Radare2 of the Lost Magic Gadget](https://0xabe.io/howto/exploit/2016/03/30/Radare2-of-the-Lost-Magic-Gadget.html)
- [Return to VDSO using ELF Auxiliary Vectors](http://v0ids3curity.blogspot.it/2014/12/return-to-vdso-using-elf-auxiliary.html)
- [The Art Of ELF: Analysis and Exploitations](http://fluxius.handgrep.se/2011/10/20/the-art-of-elf-analysises-and-exploitations/)
- [The Chakra Exploit And The Limitations Of Modern Cyber Security Threat Mitigation Techniques](https://www.endgame.com/blog/technical-blog/chakra-exploit-and-limitations-modern-mitigation-techniques)
- [The hacker known as "Alex" — Operation Luigi: How I hacked my friend without her noticing](https://defaultnamehere.tumblr.com/post/163734466355/operation-luigi-how-i-hacked-my-friend-without)
- [The one-gadget in glibc](https://david942j.blogspot.it/2017/02/project-one-gadget-in-glibc.html)
- [Unix ELF parasites and virus](http://vxheaven.org/lib/vsc01.html)
- [What are vdso and vsyscall?](https://stackoverflow.com/questions/19938324/what-are-vdso-and-vsyscall)
- [What is the difference between .got and .got.plt section?](https://stackoverflow.com/questions/11676472/what-is-the-difference-between-got-and-got-plt-section)
- [What is this protection that seems to prevent ROP when ASLR in ON?](https://reverseengineering.stackexchange.com/questions/13811/what-is-this-protection-that-seems-to-prevent-rop-when-aslr-in-on)

## Exploits

- ["Bypassing" Microsoft's Patch for CVE-2017-0199](http://justhaifei1.blogspot.it/2017/07/bypassing-microsofts-cve-2017-0199-patch.html?m=1)
- [AnC - VUSec](https://www.vusec.net/projects/anc/) • ASLR⊕Cache
- [ArmisSecurity/blueborne: PoC scripts demonstrating the BlueBorne vulnerabilities](https://github.com/ArmisSecurity/blueborne)
- [Attacking a co-hosted VM: A hacker, a hammer and two memory modules - This is Security :: by Stormshield](https://thisissecurity.stormshield.com/2017/10/19/attacking-co-hosted-vm-hacker-hammer-two-memory-modules/)
- [Avast Antivirus: Remote Stack Buffer Overflow with Magic Numbers](https://landave.io/2017/06/avast-antivirus-remote-stack-buffer-overflow-with-magic-numbers/)
- [Back to 28: Grub2 Authentication 0-Day](http://hmarco.org/bugs/CVE-2015-8370-Grub2-authentication-bypass.html)
- [Broadpwn: Remotely Compromising Android and iOS via a Bug in Broadcom's Wi-Fi Chipsets \| Exodus Intelligence](https://blog.exodusintel.com/2017/07/26/broadpwn/)
- [Dirty COW and why lying is bad even if you are the Linux kernel](https://chao-tic.github.io/blog/2017/05/24/dirty-cow)
- [Educational Heap Exploitation](https://github.com/shellphish/how2heap)
- [Exploit writing tutorial part 11 : Heap Spraying Demystified](https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/#0x0c0c0c0c)
- [Exploiting the DRAM rowhammer bug to gain kernel privileges](https://googleprojectzero.blogspot.it/2015/03/exploiting-dram-rowhammer-bug-to-gain.html)
- [fail0verflow :: The First PS4 Kernel Exploit: Adieu](https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/)
- [Finding Function's Load Address](http://uaf.io/exploitation/misc/2016/04/02/Finding-Functions.html) • DT_STRTAB
- [File Stream Pointer Overflows](http://www.ouah.org/fsp-overflows.txt)
- [Flash JIT – Spraying info leak gadgets](http://zhodiac.hispahack.com/my-stuff/security/Flash_Jit_InfoLeak_Gadgets.pdf)
- [Fun with FORTIFY_SOURCE](http://vulnfactory.org/blog/2010/04/27/fun-with-fortify_source/)
- [geohot presents an evasi0n7 writeup](http://geohot.com/e7writeup.html)
- [Kernel Pool Overflow Exploitation In Real World – Windows 10 \| TRACKWATCH](http://trackwatch.com/kernel-pool-overflow-exploitation-in-real-world-windows-10/)
- [Linux/x86 - sockfd trick + dup2(0,0), dup2(0,1), dup2(0,2) + execve /bin/sh - 50 bytes](http://shell-storm.org/shellcode/files/shellcode-881.php)
- [Mental Snapshot - _int_free and unlink](http://uaf.io/exploitation/misc/2016/09/11/_int_free-Mental-Snapshot.html) • free, heap, unlink
- [Offset2lib: bypassing full ASLR on 64bit Linux](http://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html)
- [Playing with signals : An overview on Sigreturn Oriented Programming](https://thisissecurity.net/2015/01/03/playing-with-signals-an-overview-on-sigreturn-oriented-programming/)
- [Pwn2Own: Safari sandbox part 1 – Mount yourself a root shell](https://phoenhex.re/2017-06-09/pwn2own-diskarbitrationd-privesc)
- [Pwn2Own: Safari sandbox part 2 – Wrap your way around to root](https://phoenhex.re/2017-07-06/pwn2own-sandbox-escape)
- [Pwning (sometimes) with style - Dragons' notes on CTFs](http://j00ru.vexillium.org/slides/2015/insomnihack.pdf)
- [pwnlib.dynelf — Resolving remote functions using leaks](https://docs.pwntools.com/en/stable/dynelf.html)
- [The info leak era on software exploitation](https://media.blackhat.com/bh-us-12/Briefings/Serna/BH_US_12_Serna_Leak_Era_Slides.pdf)
- [What is vulnerable about this C code?](http://stackoverflow.com/questions/8304396/what-is-vulnerable-about-this-c-code) • env
- [x86 Exploitation 101: heap overflows… unlink me, would you please?](https://gbmaster.wordpress.com/2014/08/11/x86-exploitation-101-heap-overflows-unlink-me-would-you-please/) • dlmalloc, heap, unlink
- [Zero Day Initiative — Use-After-Silence: Exploiting a quietly patched UAF in VMware](https://www.thezdi.com/blog/2017/6/26/use-after-silence-exploiting-a-quietly-patched-uaf-in-vmware)

## Papers

- [A Eulogy for Format Strings](http://phrack.org/issues/67/9.html) • Phrack
- [Advanced Doug Lea's malloc exploits](http://phrack.org/issues/61/6.html) • Phrack
- [Advances in format string exploitation](http://phrack.org/issues/59/7.html) • Phrack
- [AEG: Automatic Exploit Generation](http://security.ece.cmu.edu/aeg/aeg-current.pdf) • NDSS&nbsp;2011
- [ASLR on the Line: Practical Cache Attacks on the MMU](http://www.cs.vu.nl/~herbertb/download/papers/anc_ndss17.pdf) • NDSS&nbsp;2017, ASLR⊕Cache
- [Drammer: Deterministic Rowhammer Attacks on Mobile Platforms](https://vvdveen.com/publications/drammer.pdf) • CCS&nbsp;2016
- [Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors](https://users.ece.cmu.edu/~yoonguk/papers/kim-isca14.pdf) • ISCA&nbsp;2014
- [Hacking Blind](http://www.scs.stanford.edu/brop/bittau-brop.pdf) • S&P&nbsp;2014, BROP
- [How the ELF Ruined Christmas](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf) • USENIX&nbsp;2015, \_dl\_runtime\_resolve
- [Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR](http://www.cs.ucr.edu/~nael/pubs/micro16.pdf) • MICRO&nbsp;2016
- [On the Effectiveness of Address-Space Randomization](https://benpfaff.org/papers/asrandom.pdf) • CCS&nbsp;2004, ASLR
- [On the Effectiveness of Full-ASLR on 64-bit Linux](http://cybersecurity.upv.es/attacks/offset2lib/offset2lib-paper.pdf) • DeepSec&nbsp;2014, offset2lib
- [Once upon a free()...](http://phrack.org/issues/57/9.html) • Phrack
- [Smashing The Stack For Fun And Profit](http://phrack.org/issues/49/14.html) • Phrack
- [The advanced return-into-lib(c) exploits: PaX case study](http://phrack.org/issues/58/4.html) • Phrack, ret-into-dl
- [The Malloc Maleficarum](http://phrack.org/issues/66/10.html) • Phrack
- [Vudo - An object superstitiously believed to embody magical powers](http://www.phrack.org/issues/57/8.html) • Phrack, dlmalloc, frontlink, unlink

## Talks/Presentations

- [$hell on Earth: From Browser to System Compromise](https://www.youtube.com/watch?v=7wIiqqgDWdQ) • Black Hat USA&nbsp;2016
- [Attacking The XNU Kernel In El Capitan](https://www.youtube.com/watch?v=k550C0V79ts) • Black Hat Europe&nbsp;2015
- [Behind the Scenes with iOS Security](https://www.youtube.com/watch?v=BLGFriOKz6U) • Black Hat USA&nbsp;2016
- [Breaking the x86 Instruction Set](https://www.youtube.com/watch?v=KrksBdWcZgQ) • Black Hat USA&nbsp;2017
- [Fixing/Making Holes in Binaries](https://www.youtube.com/watch?v=18DKETYfvjg) • Black Hat USA&nbsp;2002
- [Heap Feng Shui in JavaScript](https://www.blackhat.com/presentations/bh-europe-07/Sotirov/Presentation/bh-eu-07-sotirov-apr19.pdf) • Black Hat Europe&nbsp;2007
- [Infosec and failure](https://www.youtube.com/watch?v=erZ2JlfTtcE) by 杏👼Ąż • Hack.lu&nbsp;2017
- [Pwned By The Owner: What Happens When You Steal A Hacker's Computer](https://www.youtube.com/watch?v=Jwpg-AwJ0Jc) by Zoz • DEF&nbsp;CON&nbsp;18
- [Unexpected Stories From a Hacker Inside the Government](https://www.youtube.com/watch?v=TSR-b9yuTbM) by Mudge • DEF&nbsp;CON&nbsp;21

## Write-ups

- [0ctf Quals 2017 - BabyHeap2017](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) • fastbins
- [33C3 CTF – babyfengshui](https://galhacktictrendsetters.wordpress.com/2017/01/05/33c3-ctf-babyfengshui/)
- [c00kies@venice - FAUST CTF 2017 Write-Up: Alexa](https://secgroup.github.io/2017/05/29/faustctf2017-writeup-alexa/)
- [c00kies@venice - Google CTF 2017 (Quals) Write-Up: Inst Prof](https://secgroup.github.io/2017/06/22/googlectf2017quals-writeup-inst-prof/)
- [CSAW '17 PWN - Auir (200pt)](https://glennmcgui.re/csaw-17-auir/)
- [CSAW Quals 2017 - FuntimeJS](http://blog.rpis.ec/2017/09/csaw-quals-2017-funtimejs.html)
- [CSAW Quals 2017: Zone Writeup](https://amritabi0s.wordpress.com/2017/09/18/csaw-quals-2017-zone-writeup/)
- [Dragon Sector: Pwn2Win 2017 - Shift Register](http://blog.dragonsector.pl/2017/10/pwn2win-2017-shift-register.html)
- [Exploit Exercise - Format String FORTIFY_SOURCE Bypass](http://v0ids3curity.blogspot.it/2012/09/exploit-exercise-format-string.html) • FORTIFY_SOURCE
- [exploit exercises - protostar - heap levels \| research \| sprawl](http://thesprawl.org/research/exploit-exercises-protostar-heap/#heap-3)
- [Hack.lu's OREO with ret2dl-resolve](http://wapiflapi.github.io/2014/11/17/hacklu-oreo-with-ret2dl-resolve/)
- [Hohoho](https://github.com/InfoSecIITR/write-ups/tree/master/2016/33c3-ctf-2016/misc/hohoho) • bash
- [Nebula level15 write-up](http://www.pwntester.com/blog/2013/11/26/nebula-level15-write-up/) • RPATH
- [Play With Capture The Flag: [Write-up] Google CTF 2017 - pwn474 primary](https://david942j.blogspot.it/2017/06/write-up-google-ctf-2017-pwn474-primary.html)
- [RingZer0Team - Shellcoding](https://github.com/VulnHub/ctf-writeups/blob/master/2015/ringzer0/shellcoding.md)
- [Tokyo Westerns MMA 2016 - Diary](http://uaf.io/exploitation/2016/09/06/TokyoWesterns-MMA-Diary.html) • seccomp
