#	$OpenBSD: Makefile,v 1.16 2019/08/03 15:22:21 deraadt Exp $
#       $NetBSD: Makefile,v 1.1 1996/09/30 16:35:05 ws Exp $

S=      ${.CURDIR}/../../../..
R=              ..
.PATH:          $(.CURDIR)/$(R)
RELOC=		E00000
ENTRY=		_entry
NOMAN=
PROG=           boot.mac
CFLAGS+=	-D_STANDALONE
SRCS=           Locore.c main.c ofdev.c net.c netif_of.c netudp.c
SRCS+=		alloc.c cache.c hfs.c fchmod.c
SRCS+=          boot.c conf.c cmd.c vars.c ctime.c strtol.c

INSTALL_STRIP=
BINDIR=         /usr/mdec
OBJCOPY?=	objcopy
OBJCOPY_ARGS=	-O aixcoff-rs6000 -R .comment -R .note
LDFLAGS=	-nopie -znorelro -X -Ttext ${RELOC} -e $(ENTRY)
LDFLAGS+=	-T ${.CURDIR}/elf32_powerpc_merge.x -Bstatic

.PATH:          ${S}/stand/boot
.PATH:          ${S}/lib/libsa
SRCS+=		getchar.c

.PATH:		${S}/lib/libkern/arch/powerpc ${S}/lib/libkern
SRCS+=		strlcpy.c memcpy.c memmove.c strlen.c strrchr.c strlcat.c ashrdi3.c
SRCS+=		moddi3.c

CPPFLAGS+=	-I. -I${.CURDIR}/../../.. -I${.CURDIR}/../../../..
CPPFLAGS+=	-DRELOC=0x${RELOC} -DCONSPEED=57600
# for booting PCI Powermacs
CPPFLAGS+=	-DXCOFF_GLUE
CFLAGS+=	-fno-pie

LIBS!=          cd $(.CURDIR)/$(R); $(MAKE) libdep
CLEANFILES=	fixcoff

$(PROG):        $(OBJS) $(LIBS) fixcoff 
	$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o ${.TARGET}
	${OBJCOPY} ${OBJCOPY_ARGS} ${.TARGET}
	${.OBJDIR}/fixcoff ${.TARGET}

fixcoff:	fixcoff.c
	${HOSTCC} -I${.CURDIR} -o fixcoff ${.CURDIR}/fixcoff.c

.include <bsd.prog.mk>
