##############################################################################
#                                                                            #
# Copyright 2014 Intel Corporation                                           #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License");            #
# you may not use this file except in compliance with the License.           #
# You may obtain a copy of the License at                                    #
#                                                                            #
#    http://www.apache.org/licenses/LICENSE-2.0                              #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#                                                                            #
##############################################################################
#                                                                            #
#  Developers and authors:                                                   #
#  Shay Gueron (1, 2), and Vlad Krasnov (1)                                  #
#  (1) Intel Corporation, Israel Development Center                          #
#  (2) University of Haifa                                                   #
#                                                                            #
##############################################################################

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
                =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
        $avx = ($1>=2.19) + ($1>=2.22);
}

if ($win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
            `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)/) {
        $avx = ($1>=2.09) + ($1>=2.10);
}

if ($win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
            `ml64 2>&1` =~ /Version ([0-9]+)\./) {
        $avx = ($1>=10) + ($1>=11);
}

if (`$ENV{CC} -v 2>&1` =~ /(^clang version|based on LLVM) ([3-9])\.([0-9]+)/) {
        my $ver = $2 + $3/100.0;        # 3.1->3.01, 3.10->3.10
        $avx = ($ver>=3.0) + ($ver>=3.01);
}

if ($avx>=1) {{

my ($_r0_, $_r1_, $_r2_, $_r3_, $_r4_,
    $_r1_x5, $_r2_x5, $_r3_x5, $_r4_x5,
    $_k_,
    $_A0_, $_A1_, $_A2_, $_A3_, $_A4_)
 = (64, 96, 128, 160, 192,
    224, 256, 288, 320,
    40,
    352, 356, 360, 364, 368);

$code.=<<___;
.text
.align 32
.LandMask:
.quad 0x3FFFFFF, 0x3FFFFFF, 0x3FFFFFF, 0x3FFFFFF
.LsetBit:
.quad 0x1000000, 0x1000000, 0x1000000, 0x1000000
.LrSet:
.quad 0xFFFFFFC0FFFFFFF, 0xFFFFFFC0FFFFFFF, 0xFFFFFFC0FFFFFFF, 0xFFFFFFC0FFFFFFF
.quad 0xFFFFFFC0FFFFFFC, 0xFFFFFFC0FFFFFFC, 0xFFFFFFC0FFFFFFC, 0xFFFFFFC0FFFFFFC

.LpermFix:
.long 6,7,6,7,6,7,6,7
.long 4,5,6,7,6,7,6,7
.long 2,3,6,7,4,5,6,7
.long 0,1,4,5,2,3,6,7
___


{
my ($A0, $A1, $A2, $A3, $A4,
    $r0, $r1, $r2, $r3, $r4,
    $T0, $T1, $A5, $A6, $A7, $A8)=map("%xmm$_",(0..15));

my ($A0_y, $A1_y, $A2_y, $A3_y, $A4_y,
    $r0_y, $r1_y, $r2_y, $r3_y, $r4_y)=map("%ymm$_",(0..9));

my ($state, $key)
   =("%rdi", "%rsi");

$code.=<<___;
################################################################################
# void poly1305_init_avx2(void *state)

.type poly1305_init_avx2, \@function, 2
.align 64
poly1305_init_avx2:
  vzeroupper

  # Init the MAC value
  mov   8*0($state), %r8
  mov   8*1($state), %r9
  mov   8*2($state), %r10

  mov   %r8, %rax
  mov   %r9, %rcx

  sub   \$-5, %r8
  sbb   \$-1, %r9
  sbb   \$3, %r10

  cmovc %rax, %r8
  cmovc %rcx, %r9
  cmovc 8*2($state), %r10

  mov   %r8, %rax
  and   \$0x3ffffff, %rax
  mov   %eax, $_A0_($state)

  shrd  \$26, %r9, %r8
  shrd  \$26, %r10, %r9

  mov   %r8, %rax
  and   \$0x3ffffff, %rax
  mov   %eax, $_A1_($state)

  shrd  \$26, %r9, %r8
  shr   \$26, %r9

  mov   %r8, %rax
  and   \$0x3ffffff, %rax
  mov   %eax, $_A2_($state)

  shrd  \$26, %r9, %r8

  mov   %r8, %rax
  and   \$0x3ffffff, %rax
  mov   %eax, $_A3_($state)

  shr   \$26, %r8

  mov   %r8, %rax
  and   \$0x3ffffff, %rax
  mov   %eax, $_A4_($state)

  # load and convert r
  vmovq  8*3($state), $r0
  vmovq  8*4($state), $T0
  vpand  .LrSet(%rip), $r0, $r0
  vpand  .LrSet+32(%rip), $T0, $T0

  vpsrlq \$26, $r0, $r1
  vpand  .LandMask(%rip), $r0, $r0
  vpsrlq \$26, $r1, $r2
  vpand  .LandMask(%rip), $r1, $r1
  vpsllq \$12, $T0, $T1
  vpxor  $T1, $r2, $r2
  vpsrlq \$26, $r2, $r3
  vpsrlq \$40, $T0, $r4
  vpand  .LandMask(%rip), $r2, $r2
  vpand  .LandMask(%rip), $r3, $r3
  # SQR R
  vpmuludq  $r0, $r0, $A0
  vpmuludq  $r1, $r0, $A1
  vpmuludq  $r2, $r0, $A2
  vpmuludq  $r3, $r0, $A3
  vpmuludq  $r4, $r0, $A4

  vpsllq    \$1, $A1, $A1
  vpsllq    \$1, $A2, $A2
  vpmuludq  $r1, $r1, $T0
  vpaddq    $T0, $A2, $A2
  vpmuludq  $r2, $r1, $T0
  vpaddq    $T0, $A3, $A3
  vpmuludq  $r3, $r1, $T0
  vpaddq    $T0, $A4, $A4
  vpmuludq  $r4, $r1, $A5

  vpsllq    \$1, $A3, $A3
  vpsllq    \$1, $A4, $A4
  vpmuludq  $r2, $r2, $T0
  vpaddq    $T0, $A4, $A4
  vpmuludq  $r3, $r2, $T0
  vpaddq    $T0, $A5, $A5
  vpmuludq  $r4, $r2, $A6

  vpsllq    \$1, $A5, $A5
  vpsllq    \$1, $A6, $A6
  vpmuludq  $r3, $r3, $T0
  vpaddq    $T0, $A6, $A6
  vpmuludq  $r4, $r3, $A7

  vpsllq    \$1, $A7, $A7
  vpmuludq  $r4, $r4, $A8

  # Reduce
  vpsrlq  \$26, $A4, $T0
  vpand   .LandMask(%rip), $A4, $A4
  vpaddq  $T0, $A5, $A5

  vpsllq  \$2, $A5, $T0
  vpaddq  $T0, $A5, $A5
  vpsllq  \$2, $A6, $T0
  vpaddq  $T0, $A6, $A6
  vpsllq  \$2, $A7, $T0
  vpaddq  $T0, $A7, $A7
  vpsllq  \$2, $A8, $T0
  vpaddq  $T0, $A8, $A8

  vpaddq  $A5, $A0, $A0
  vpaddq  $A6, $A1, $A1
  vpaddq  $A7, $A2, $A2
  vpaddq  $A8, $A3, $A3

  vpsrlq  \$26, $A0, $T0
  vpand   .LandMask(%rip), $A0, $A0
  vpaddq  $T0, $A1, $A1
  vpsrlq  \$26, $A1, $T0
  vpand   .LandMask(%rip), $A1, $A1
  vpaddq  $T0, $A2, $A2
  vpsrlq  \$26, $A2, $T0
  vpand   .LandMask(%rip), $A2, $A2
  vpaddq  $T0, $A3, $A3
  vpsrlq  \$26, $A3, $T0
  vpand   .LandMask(%rip), $A3, $A3
  vpaddq  $T0, $A4, $A4

  vpunpcklqdq  $r0, $A0, $r0
  vpunpcklqdq  $r1, $A1, $r1
  vpunpcklqdq  $r2, $A2, $r2
  vpunpcklqdq  $r3, $A3, $r3
  vpunpcklqdq  $r4, $A4, $r4

  vmovdqu $r0, $_r0_+16($state)
  vmovdqu $r1, $_r1_+16($state)
  vmovdqu $r2, $_r2_+16($state)
  vmovdqu $r3, $_r3_+16($state)
  vmovdqu $r4, $_r4_+16($state)

  vpsllq  \$2, $r1, $A1
  vpsllq  \$2, $r2, $A2
  vpsllq  \$2, $r3, $A3
  vpsllq  \$2, $r4, $A4

  vpaddq  $A1, $r1, $A1
  vpaddq  $A2, $r2, $A2
  vpaddq  $A3, $r3, $A3
  vpaddq  $A4, $r4, $A4

  vmovdqu $A1, $_r1_x5+16($state)
  vmovdqu $A2, $_r2_x5+16($state)
  vmovdqu $A3, $_r3_x5+16($state)
  vmovdqu $A4, $_r4_x5+16($state)

  # Compute r^3 and r^4
  vpshufd \$0x44, $r0, $A0
  vpshufd \$0x44, $r1, $A1
  vpshufd \$0x44, $r2, $A2
  vpshufd \$0x44, $r3, $A3
  vpshufd \$0x44, $r4, $A4

  # Multiply input by R[0]
  vmovdqu  $_r0_+16($state), $T0
  vpmuludq $T0, $A0, $r0
  vpmuludq $T0, $A1, $r1
  vpmuludq $T0, $A2, $r2
  vpmuludq $T0, $A3, $r3
  vpmuludq $T0, $A4, $r4
  # Multiply input by R[1] (and R[1]*5)
  vmovdqu  $_r1_x5+16($state), $T0
  vpmuludq $T0, $A4, $T1
  vpaddq   $T1, $r0, $r0
  vmovdqu  $_r1_+16($state), $T0
  vpmuludq $T0, $A0, $T1
  vpaddq   $T1, $r1, $r1
  vpmuludq $T0, $A1, $T1
  vpaddq   $T1, $r2, $r2
  vpmuludq $T0, $A2, $T1
  vpaddq   $T1, $r3, $r3
  vpmuludq $T0, $A3, $T1
  vpaddq   $T1, $r4, $r4
  # Etc
  vmovdqu  $_r2_x5+16($state), $T0
  vpmuludq $T0, $A3, $T1
  vpaddq   $T1, $r0, $r0
  vpmuludq $T0, $A4, $T1
  vpaddq   $T1, $r1, $r1
  vmovdqu  $_r2_+16($state), $T0
  vpmuludq $T0, $A0, $T1
  vpaddq   $T1, $r2, $r2
  vpmuludq $T0, $A1, $T1
  vpaddq   $T1, $r3, $r3
  vpmuludq $T0, $A2, $T1
  vpaddq   $T1, $r4, $r4

  vmovdqu  $_r3_x5+16($state), $T0
  vpmuludq $T0, $A2, $T1
  vpaddq   $T1, $r0, $r0
  vpmuludq $T0, $A3, $T1
  vpaddq   $T1, $r1, $r1
  vpmuludq $T0, $A4, $T1
  vpaddq   $T1, $r2, $r2
  vmovdqu  $_r3_+16($state), $T0
  vpmuludq $T0, $A0, $T1
  vpaddq   $T1, $r3, $r3
  vpmuludq $T0, $A1, $T1
  vpaddq   $T1, $r4, $r4

  vmovdqu  $_r4_x5+16($state), $T0
  vpmuludq $T0, $A1, $T1
  vpaddq   $T1, $r0, $r0
  vpmuludq $T0, $A2, $T1
  vpaddq   $T1, $r1, $r1
  vpmuludq $T0, $A3, $T1
  vpaddq   $T1, $r2, $r2
  vpmuludq $T0, $A4, $T1
  vpaddq   $T1, $r3, $r3
  vmovdqu  $_r4_+16($state), $T0
  vpmuludq $T0, $A0, $T1
  vpaddq   $T1, $r4, $r4
  # Reduce
  vpsrlq  \$26, $r3, $T0
  vpaddq  $T0, $r4, $r4
  vpand   .LandMask(%rip), $r3, $r3
  vpsrlq  \$26, $r4, $T0
  vpsllq  \$2, $T0, $T1
  vpaddq  $T1, $T0, $T0
  vpaddq  $T0, $r0, $r0
  vpand   .LandMask(%rip), $r4, $r4
  vpsrlq  \$26, $r0, $T0
  vpand   .LandMask(%rip), $r0, $r0
  vpaddq  $T0, $r1, $r1
  vpsrlq  \$26, $r1, $T0
  vpand   .LandMask(%rip), $r1, $r1
  vpaddq  $T0, $r2, $r2
  vpsrlq  \$26, $r2, $T0
  vpand   .LandMask(%rip), $r2, $r2
  vpaddq  $T0, $r3, $r3
  vpsrlq  \$26, $r3, $T0
  vpand   .LandMask(%rip), $r3, $r3
  vpaddq  $T0, $r4, $r4

  vmovdqu $r0, $_r0_($state)
  vmovdqu $r1, $_r1_($state)
  vmovdqu $r2, $_r2_($state)
  vmovdqu $r3, $_r3_($state)
  vmovdqu $r4, $_r4_($state)

  vpsllq  \$2, $r1, $A1
  vpsllq  \$2, $r2, $A2
  vpsllq  \$2, $r3, $A3
  vpsllq  \$2, $r4, $A4

  vpaddq  $A1, $r1, $A1
  vpaddq  $A2, $r2, $A2
  vpaddq  $A3, $r3, $A3
  vpaddq  $A4, $r4, $A4

  vmovdqu $A1, $_r1_x5($state)
  vmovdqu $A2, $_r2_x5($state)
  vmovdqu $A3, $_r3_x5($state)
  vmovdqu $A4, $_r4_x5($state)

  movq  \$1, 8*7($state)

  ret
.size poly1305_init_avx2,.-poly1305_init_avx2
___
}

{

my ($A0, $A1, $A2, $A3, $A4,
    $T0, $T1, $R0, $R1, $R2,
    $R3, $R4, $AND_MASK, $PERM_MASK, $SET_MASK)
  =map("%ymm$_",(0..14));

my ($A0_x, $A1_x, $A2_x, $A3_x, $A4_x,
    $T0_x, $T1_x, $R0_x, $R1_x, $R2_x,
    $R3_x, $R4_x, $AND_MASK_x, $PERM_MASK_x, $SET_MASK_x)
  =map("%xmm$_",(0..14));

my ($state, $in, $in_len, $hlp, $rsp_save)
  =("%rdi", "%rsi", "%rdx", "%rcx", "%rax");

$code.=<<___;

###############################################################################
# void poly1305_update_avx2(void* $state, void* in, uint64_t in_len)
.globl poly1305_update_avx2
.type poly1305_update_avx2, \@function, 2
.align 64
poly1305_update_avx2:


  test  $in_len, $in_len
  jz    6f

  cmpq  \$0, 8*7($state)
  jne   1f  # This means we already started avx2, and must finish

  # If we are here we need to check in_len is longer than the min for avx2

  cmp   \$512, $in_len
  jge   2f

  jmp   poly1305_update_x64

2:
  call poly1305_init_avx2

1:
  vmovd  $_A0_($state), $A0_x
  vmovd  $_A1_($state), $A1_x
  vmovd  $_A2_($state), $A2_x
  vmovd  $_A3_($state), $A3_x
  vmovd  $_A4_($state), $A4_x

  vmovdqa  .LandMask(%rip), $AND_MASK
1:
    cmp \$32*4, $in_len
    jb  1f
    sub \$32*2, $in_len

    # load the next four blocks
    vmovdqu 32*0($in), $R2
    vmovdqu 32*1($in), $R3
    add \$32*2, $in

    vpunpcklqdq  $R3, $R2, $R0
    vpunpckhqdq  $R3, $R2, $R1

    vpermq  \$0xD8, $R0, $R0  # it is possible to rearrange the precomputations, and save this shuffle
    vpermq  \$0xD8, $R1, $R1

    vpsrlq  \$26, $R0, $R2
    vpand   $AND_MASK, $R0, $R0
    vpaddq  $R0, $A0, $A0

    vpsrlq  \$26, $R2, $R0
    vpand   $AND_MASK, $R2, $R2
    vpaddq  $R2, $A1, $A1

    vpsllq  \$12, $R1, $R2
    vpxor   $R2, $R0, $R0
    vpand   $AND_MASK, $R0, $R0
    vpaddq  $R0, $A2, $A2

    vpsrlq  \$26, $R2, $R0
    vpsrlq  \$40, $R1, $R2
    vpand   $AND_MASK, $R0, $R0
    vpxor   .LsetBit(%rip), $R2, $R2
    vpaddq  $R0, $A3, $A3
    vpaddq  $R2, $A4, $A4

    # Multiply input by R[0]
    vpbroadcastq  $_r0_($state), $T0
    vpmuludq  $T0, $A0, $R0
    vpmuludq  $T0, $A1, $R1
    vpmuludq  $T0, $A2, $R2
    vpmuludq  $T0, $A3, $R3
    vpmuludq  $T0, $A4, $R4
    # Multiply input by R[1] (and R[1]*5)
    vpbroadcastq  $_r1_x5($state), $T0
    vpmuludq  $T0, $A4, $T1
    vpaddq    $T1, $R0, $R0
    vpbroadcastq  $_r1_($state), $T0
    vpmuludq  $T0, $A0, $T1
    vpaddq    $T1, $R1, $R1
    vpmuludq  $T0, $A1, $T1
    vpaddq    $T1, $R2, $R2
    vpmuludq  $T0, $A2, $T1
    vpaddq    $T1, $R3, $R3
    vpmuludq  $T0, $A3, $T1
    vpaddq    $T1, $R4, $R4
    # Etc
    vpbroadcastq  $_r2_x5($state), $T0
    vpmuludq  $T0, $A3, $T1
    vpaddq    $T1, $R0, $R0
    vpmuludq  $T0, $A4, $T1
    vpaddq    $T1, $R1, $R1
    vpbroadcastq  $_r2_($state), $T0
    vpmuludq  $T0, $A0, $T1
    vpaddq    $T1, $R2, $R2
    vpmuludq  $T0, $A1, $T1
    vpaddq    $T1, $R3, $R3
    vpmuludq  $T0, $A2, $T1
    vpaddq    $T1, $R4, $R4

    vpbroadcastq  $_r3_x5($state), $T0
    vpmuludq  $T0, $A2, $T1
    vpaddq    $T1, $R0, $R0
    vpmuludq  $T0, $A3, $T1
    vpaddq    $T1, $R1, $R1
    vpmuludq  $T0, $A4, $T1
    vpaddq    $T1, $R2, $R2
    vpbroadcastq  $_r3_($state), $T0
    vpmuludq  $T0, $A0, $T1
    vpaddq    $T1, $R3, $R3
    vpmuludq  $T0, $A1, $T1
    vpaddq    $T1, $R4, $R4

    vpbroadcastq  $_r4_x5($state), $T0
    vpmuludq  $T0, $A1, $T1
    vpaddq    $T1, $R0, $R0
    vpmuludq  $T0, $A2, $T1
    vpaddq    $T1, $R1, $R1
    vpmuludq  $T0, $A3, $T1
    vpaddq    $T1, $R2, $R2
    vpmuludq  $T0, $A4, $T1
    vpaddq    $T1, $R3, $R3
    vpbroadcastq  $_r4_($state), $T0
    vpmuludq  $T0, $A0, $T1
    vpaddq    $T1, $R4, $R4
    # Reduce
    vpsrlq  \$26, $R3, $T0
    vpaddq  $T0, $R4, $R4
    vpand   $AND_MASK, $R3, $R3

    vpsrlq  \$26, $R4, $T0
    vpsllq  \$2, $T0, $T1
    vpaddq  $T1, $T0, $T0
    vpaddq  $T0, $R0, $R0
    vpand   $AND_MASK, $R4, $R4

    vpsrlq  \$26, $R0, $T0
    vpand   $AND_MASK, $R0, $A0
    vpaddq  $T0, $R1, $R1
    vpsrlq  \$26, $R1, $T0
    vpand   $AND_MASK, $R1, $A1
    vpaddq  $T0, $R2, $R2
    vpsrlq  \$26, $R2, $T0
    vpand   $AND_MASK, $R2, $A2
    vpaddq  $T0, $R3, $R3
    vpsrlq  \$26, $R3, $T0
    vpand   $AND_MASK, $R3, $A3
    vpaddq  $T0, $R4, $A4
  jmp 1b
1:

  cmp  \$32*2, $in_len
  jb  1f
  sub  \$32*2, $in_len
  # load the next four blocks
  vmovdqu  32*0($in), $R2
  vmovdqu  32*1($in), $R3
  add  \$32*2, $in

  vpunpcklqdq  $R3, $R2, $R0
  vpunpckhqdq  $R3, $R2, $R1

  vpermq  \$0xD8, $R0, $R0
  vpermq  \$0xD8, $R1, $R1

  vpsrlq  \$26, $R0, $R2
  vpand   $AND_MASK, $R0, $R0
  vpaddq  $R0, $A0, $A0

  vpsrlq  \$26, $R2, $R0
  vpand   $AND_MASK, $R2, $R2
  vpaddq  $R2, $A1, $A1

  vpsllq  \$12, $R1, $R2
  vpxor   $R2, $R0, $R0
  vpand   $AND_MASK, $R0, $R0
  vpaddq  $R0, $A2, $A2

  vpsrlq  \$26, $R2, $R0
  vpsrlq  \$40, $R1, $R2
  vpand   $AND_MASK, $R0, $R0
  vpxor   .LsetBit(%rip), $R2, $R2
  vpaddq  $R0, $A3, $A3
  vpaddq  $R2, $A4, $A4

  # Multiply input by R[0]
  vmovdqu   $_r0_($state), $T0
  vpmuludq  $T0, $A0, $R0
  vpmuludq  $T0, $A1, $R1
  vpmuludq  $T0, $A2, $R2
  vpmuludq  $T0, $A3, $R3
  vpmuludq  $T0, $A4, $R4
  # Multiply input by R[1] (and R[1]*5)
  vmovdqu   $_r1_x5($state), $T0
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R0, $R0
  vmovdqu   $_r1_($state), $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R4, $R4
  # Etc
  vmovdqu   $_r2_x5($state), $T0
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R1, $R1
  vmovdqu   $_r2_($state), $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R4, $R4

  vmovdqu   $_r3_x5($state), $T0
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R2, $R2
  vmovdqu   $_r3_($state), $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R4, $R4

  vmovdqu   $_r4_x5($state), $T0
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R3, $R3
  vmovdqu   $_r4_($state), $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R4, $R4
  # Reduce
  vpsrlq  \$26, $R3, $T0
  vpaddq  $T0, $R4, $R4
  vpand   $AND_MASK, $R3, $R3
  vpsrlq  \$26, $R4, $T0
  vpsllq  \$2, $T0, $T1
  vpaddq  $T1, $T0, $T0
  vpaddq  $T0, $R0, $R0
  vpand   $AND_MASK, $R4, $R4
  vpsrlq  \$26, $R0, $T0
  vpand   $AND_MASK, $R0, $A0
  vpaddq  $T0, $R1, $R1
  vpsrlq  \$26, $R1, $T0
  vpand   $AND_MASK, $R1, $A1
  vpaddq  $T0, $R2, $R2
  vpsrlq  \$26, $R2, $T0
  vpand   $AND_MASK, $R2, $A2
  vpaddq  $T0, $R3, $R3
  vpsrlq  \$26, $R3, $T0
  vpand   $AND_MASK, $R3, $A3
  vpaddq  $T0, $R4, $A4

  vpsrldq \$8, $A0, $R0
  vpsrldq \$8, $A1, $R1
  vpsrldq \$8, $A2, $R2
  vpsrldq \$8, $A3, $R3
  vpsrldq \$8, $A4, $R4

  vpaddq  $R0, $A0, $A0
  vpaddq  $R1, $A1, $A1
  vpaddq  $R2, $A2, $A2
  vpaddq  $R3, $A3, $A3
  vpaddq  $R4, $A4, $A4

  vpermq  \$0xAA, $A0, $R0
  vpermq  \$0xAA, $A1, $R1
  vpermq  \$0xAA, $A2, $R2
  vpermq  \$0xAA, $A3, $R3
  vpermq  \$0xAA, $A4, $R4

  vpaddq  $R0, $A0, $A0
  vpaddq  $R1, $A1, $A1
  vpaddq  $R2, $A2, $A2
  vpaddq  $R3, $A3, $A3
  vpaddq  $R4, $A4, $A4
1:
  test  $in_len, $in_len
  jz  5f
  # In case 1,2 or 3 blocks remain, we want to multiply them correctly
  vmovq  $A0_x, $A0_x
  vmovq  $A1_x, $A1_x
  vmovq  $A2_x, $A2_x
  vmovq  $A3_x, $A3_x
  vmovq  $A4_x, $A4_x

  mov  .LsetBit(%rip), $hlp
  mov  %rsp, $rsp_save
  test \$15, $in_len
  jz   1f
  xor  $hlp, $hlp
  sub  \$64, %rsp
  vpxor   $R0, $R0, $R0
  vmovdqu $R0, (%rsp)
  vmovdqu $R0, 32(%rsp)
3:
  movb  ($in, $hlp), %r8b
  movb  %r8b, (%rsp, $hlp)
  inc  $hlp
  cmp  $hlp, $in_len
  jne  3b

  movb \$1, (%rsp, $hlp)
  xor  $hlp, $hlp
  mov  %rsp, $in

1:

  cmp  \$16, $in_len
  ja  2f
  vmovq  8*0($in), $R0_x
  vmovq  8*1($in), $R1_x
  vmovq  $hlp, $SET_MASK_x
  vmovdqa  .LpermFix(%rip), $PERM_MASK
  jmp  1f
2:
  cmp  \$32, $in_len
  ja  2f
  vmovdqu 16*0($in), $R2_x
  vmovdqu 16*1($in), $R3_x
  vmovq   .LsetBit(%rip), $SET_MASK_x
  vpinsrq  \$1, $hlp, $SET_MASK_x, $SET_MASK_x
  vmovdqa .LpermFix+32(%rip), $PERM_MASK

  vpunpcklqdq  $R3, $R2, $R0
  vpunpckhqdq  $R3, $R2, $R1
  jmp  1f
2:
  cmp  \$48, $in_len
  ja  2f
  vmovdqu  32*0($in), $R2
  vmovdqu  32*1($in), $R3_x
  vmovq  .LsetBit(%rip), $SET_MASK_x
  vpinsrq \$1, $hlp, $SET_MASK_x, $SET_MASK_x
  vpermq  \$0xc4, $SET_MASK, $SET_MASK
  vmovdqa  .LpermFix+64(%rip), $PERM_MASK

  vpunpcklqdq  $R3, $R2, $R0
  vpunpckhqdq  $R3, $R2, $R1
  jmp  1f
2:
  vmovdqu 32*0($in), $R2
  vmovdqu 32*1($in), $R3
  vmovq   .LsetBit(%rip), $SET_MASK_x
  vpinsrq \$1, $hlp, $SET_MASK_x, $SET_MASK_x
  vpermq  \$0x40, $SET_MASK, $SET_MASK
  vmovdqa .LpermFix+96(%rip), $PERM_MASK

  vpunpcklqdq     $R3, $R2, $R0
  vpunpckhqdq     $R3, $R2, $R1

1:
  mov  $rsp_save, %rsp

  vpsrlq \$26, $R0, $R2
  vpand  $AND_MASK, $R0, $R0
  vpaddq $R0, $A0, $A0

  vpsrlq \$26, $R2, $R0
  vpand  $AND_MASK, $R2, $R2
  vpaddq $R2, $A1, $A1

  vpsllq \$12, $R1, $R2
  vpxor  $R2, $R0, $R0
  vpand  $AND_MASK, $R0, $R0
  vpaddq $R0, $A2, $A2

  vpsrlq \$26, $R2, $R0
  vpsrlq \$40, $R1, $R2
  vpand  $AND_MASK, $R0, $R0
  vpxor  $SET_MASK, $R2, $R2
  vpaddq $R0, $A3, $A3
  vpaddq $R2, $A4, $A4

  # Multiply input by R[0]
  vmovdqu   $_r0_($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A0, $R0
  vpmuludq  $T0, $A1, $R1
  vpmuludq  $T0, $A2, $R2
  vpmuludq  $T0, $A3, $R3
  vpmuludq  $T0, $A4, $R4
  # Multiply input by R[1] (and R[1]*5)
  vmovdqu   $_r1_x5($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R0, $R0
  vmovdqu   $_r1_($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R4, $R4
  # Etc
  vmovdqu   $_r2_x5($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R1, $R1
  vmovdqu   $_r2_($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R4, $R4

  vmovdqu   $_r3_x5($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R2, $R2
  vmovdqu   $_r3_($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R4, $R4

  vmovdqu   $_r4_x5($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R3, $R3
  vmovdqu   $_r4_($state), $T0
  vpermd    $T0, $PERM_MASK, $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R4, $R4
  # Reduce
  vpsrlq  \$26, $R3, $T0
  vpaddq  $T0, $R4, $R4
  vpand   $AND_MASK, $R3, $R3
  vpsrlq  \$26, $R4, $T0
  vpsllq  \$2, $T0, $T1
  vpaddq  $T1, $T0, $T0
  vpaddq  $T0, $R0, $R0
  vpand   $AND_MASK, $R4, $R4
  vpsrlq  \$26, $R0, $T0
  vpand   $AND_MASK, $R0, $A0
  vpaddq  $T0, $R1, $R1
  vpsrlq  \$26, $R1, $T0
  vpand   $AND_MASK, $R1, $A1
  vpaddq  $T0, $R2, $R2
  vpsrlq  \$26, $R2, $T0
  vpand   $AND_MASK, $R2, $A2
  vpaddq  $T0, $R3, $R3
  vpsrlq  \$26, $R3, $T0
  vpand   $AND_MASK, $R3, $A3
  vpaddq  $T0, $R4, $A4

  vpsrldq \$8, $A0, $R0
  vpsrldq \$8, $A1, $R1
  vpsrldq \$8, $A2, $R2
  vpsrldq \$8, $A3, $R3
  vpsrldq \$8, $A4, $R4

  vpaddq  $R0, $A0, $A0
  vpaddq  $R1, $A1, $A1
  vpaddq  $R2, $A2, $A2
  vpaddq  $R3, $A3, $A3
  vpaddq  $R4, $A4, $A4

  vpermq  \$0xAA, $A0, $R0
  vpermq  \$0xAA, $A1, $R1
  vpermq  \$0xAA, $A2, $R2
  vpermq  \$0xAA, $A3, $R3
  vpermq  \$0xAA, $A4, $R4

  vpaddq  $R0, $A0, $A0
  vpaddq  $R1, $A1, $A1
  vpaddq  $R2, $A2, $A2
  vpaddq  $R3, $A3, $A3
  vpaddq  $R4, $A4, $A4

5:
  vmovd  $A0_x, $_A0_($state)
  vmovd  $A1_x, $_A1_($state)
  vmovd  $A2_x, $_A2_($state)
  vmovd  $A3_x, $_A3_($state)
  vmovd  $A4_x, $_A4_($state)
6:
  ret
.size poly1305_update_avx2,.-poly1305_update_avx2
###############################################################################
# void poly1305_finish_avx2(void* $state, uint8_t mac[16]);
.type poly1305_finish_avx2,\@function,2
.globl poly1305_finish_avx2
poly1305_finish_avx2:
___
my $mac="%rsi";
my ($A0, $A1, $A2, $A3, $A4, $T0, $T1)
  =map("%xmm$_",(0..6));

$code.=<<___;
  cmpq  \$0, 8*7($state)
  jne 1f
  jmp poly1305_finish_x64

1:
  mov  $_A0_($state), %r8d
  mov  $_A1_($state), %eax
  mov  $_A2_($state), %r9d
  mov  $_A3_($state), %ecx
  mov  $_A4_($state), %r10d

  shl \$26, %rax
  add %rax, %r8

  mov %r9, %rax
  shl \$52, %rax
  shr \$12, %r9
  add %rax, %r8
  adc \$0, %r9

  mov %r10, %rax
  shl \$14, %rcx
  shl \$40, %rax
  shr \$24, %r10

  add %rcx, %r9
  add %rax, %r9
  adc \$0, %r10

  mov %r10, %rax
  shr \$2, %rax
  and \$3, %r10

  mov %rax, %rcx
  shl \$2, %rax
  add %rcx, %rax

  add %rax, %r8
  adc \$0, %r9
  adc \$0, %r10

  mov %r8, %rax
  mov %r9, %rcx
  sub \$-5, %rax
  sbb \$-1, %rcx
  sbb \$3, %r10

  cmovc %r8, %rax
  cmovc %r9, %rcx
  add  $_k_($state), %rax
  adc  $_k_+8($state), %rcx
  mov %rax, ($mac)
  mov %rcx, 8($mac)

  ret
.size poly1305_finish_avx2,.-poly1305_finish_avx2
___
}
}}

$code =~ s/\`([^\`]*)\`/eval(\$1)/gem;
print $code;
close STDOUT;

