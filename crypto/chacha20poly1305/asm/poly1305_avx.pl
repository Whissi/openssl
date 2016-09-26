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
# state:
#  0: r[0] || r^2[0]
# 16: r[1] || r^2[1]
# 32: r[2] || r^2[2]
# 48: r[3] || r^2[3]
# 64: r[4] || r^2[4]
# 80: r[1]*5 || r^2[1]*5
# 96: r[2]*5 || r^2[2]*5
#112: r[3]*5 || r^2[3]*5
#128: r[4]*5 || r^2[4]*5
#144: k
#160: A0
#164: A1
#168: A2
#172: A3
#176: A4
#180: END

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
  = (0, 16, 32, 48, 64,
     80, 96, 112, 128,
     144,
     160, 164, 168, 172, 176);

$code.=<<___;
.text
.align 32
.LandMask:
.quad 0x3FFFFFF, 0x3FFFFFF
.LsetBit:
.quad 0x1000000, 0x1000000
.LrSet:
.quad 0x0FFFFFFC0FFFFFFF, 0x0FFFFFFC0FFFFFFF
.quad 0x0FFFFFFC0FFFFFFC, 0x0FFFFFFC0FFFFFFC
.Lone:
.quad 1,0
.Lpoly:
.quad 0xfffffffffffffffb, 0xffffffffffffffff
___


{
my ($A0, $A1, $A2, $A3, $A4,
    $r0, $r1, $r2, $r3, $r4,
    $T0, $T1, $A5, $A6, $A7, $A8)=map("%xmm$_",(0..15));
my ($state, $key)
   =("%rdi", "%rsi");

$code.=<<___;
################################################################################
# void poly1305_init_avx(void *state, uint8_t key[32])

.globl poly1305_init_avx
.type poly1305_init_avx, \@function, 2
.align 64
poly1305_init_avx:
  vzeroupper
  # load and convert r
  vmovq   8*0($key), $r0
  vmovq   8*1($key), $T0
  vpand   .LrSet(%rip), $r0, $r0
  vpand   .LrSet+16(%rip), $T0, $T0

  vpsrlq  \$26, $r0, $r1
  vpand   .LandMask(%rip), $r0, $r0
  vpsrlq  \$26, $r1, $r2
  vpand   .LandMask(%rip), $r1, $r1
  vpsllq  \$12, $T0, $T1
  vpxor   $T1, $r2, $r2
  vpsrlq  \$26, $r2, $r3
  vpsrlq  \$40, $T0, $r4
  vpand   .LandMask(%rip), $r2, $r2
  vpand   .LandMask(%rip), $r3, $r3

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
  # Store k
  vmovdqu 16*1($key), $T0
  vmovdqu $T0, $_k_($state)
  # Init the MAC value
  vpxor   $T0, $T0, $T0
  vmovdqu $T0, $_A0_($state)
  vmovd   $T0, $_A4_($state)
  vzeroupper
  ret
.size poly1305_init_avx,.-poly1305_init_avx
___
}

{

my ($A0, $A1, $A2, $A3, $A4,
    $T0, $T1, $R0, $R1, $R2,
    $R3, $R4, $AND_MASK)
   = map("%xmm$_",(0..12));

my ($state, $in, $in_len)
  =("%rdi", "%rsi", "%rdx");

$code.=<<___;

###############################################################################
# void* poly1305_update_avx(void* state, void* in, uint64_t in_len)
.globl poly1305_update_avx
.type poly1305_update_avx, \@function, 2
.align 64
poly1305_update_avx:

  vzeroupper
  vmovd  $_A0_($state), $A0
  vmovd  $_A1_($state), $A1
  vmovd  $_A2_($state), $A2
  vmovd  $_A3_($state), $A3
  vmovd  $_A4_($state), $A4
  vmovdqa  .LandMask(%rip), $AND_MASK
  # Skip to single block case
  cmp \$32, $in_len
  jb  3f
1:
    cmp  \$16*4, $in_len
    jb   1f
    sub  \$16*2, $in_len
    # load the next two blocks
    vmovdqu  16*0($in), $R2
    vmovdqu  16*1($in), $R3
    add  \$16*2, $in

    vpunpcklqdq  $R3, $R2, $R0
    vpunpckhqdq  $R3, $R2, $R1

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
    vbroadcastss  $_r0_($state), $T0
    vpmuludq  $T0, $A0, $R0
    vpmuludq  $T0, $A1, $R1
    vpmuludq  $T0, $A2, $R2
    vpmuludq  $T0, $A3, $R3
    vpmuludq  $T0, $A4, $R4
    # Multiply input by R[1] (and R[1]*5)
    vbroadcastss  $_r1_x5($state), $T0
    vpmuludq  $T0, $A4, $T1
    vpaddq    $T1, $R0, $R0
    vbroadcastss  $_r1_($state), $T0
    vpmuludq  $T0, $A0, $T1
    vpaddq    $T1, $R1, $R1
    vpmuludq  $T0, $A1, $T1
    vpaddq    $T1, $R2, $R2
    vpmuludq  $T0, $A2, $T1
    vpaddq    $T1, $R3, $R3
    vpmuludq  $T0, $A3, $T1
    vpaddq    $T1, $R4, $R4
    # Etc
    vbroadcastss  $_r2_x5($state), $T0
    vpmuludq  $T0, $A3, $T1
    vpaddq    $T1, $R0, $R0
    vpmuludq  $T0, $A4, $T1
    vpaddq    $T1, $R1, $R1
    vbroadcastss  $_r2_($state), $T0
    vpmuludq  $T0, $A0, $T1
    vpaddq    $T1, $R2, $R2
    vpmuludq  $T0, $A1, $T1
    vpaddq    $T1, $R3, $R3
    vpmuludq  $T0, $A2, $T1
    vpaddq    $T1, $R4, $R4

    vbroadcastss  $_r3_x5($state), $T0
    vpmuludq  $T0, $A2, $T1
    vpaddq    $T1, $R0, $R0
    vpmuludq  $T0, $A3, $T1
    vpaddq    $T1, $R1, $R1
    vpmuludq  $T0, $A4, $T1
    vpaddq    $T1, $R2, $R2
    vbroadcastss  $_r3_($state), $T0
    vpmuludq  $T0, $A0, $T1
    vpaddq    $T1, $R3, $R3
    vpmuludq  $T0, $A1, $T1
    vpaddq    $T1, $R4, $R4

    vbroadcastss  $_r4_x5($state), $T0
    vpmuludq  $T0, $A1, $T1
    vpaddq    $T1, $R0, $R0
    vpmuludq  $T0, $A2, $T1
    vpaddq    $T1, $R1, $R1
    vpmuludq  $T0, $A3, $T1
    vpaddq    $T1, $R2, $R2
    vpmuludq  $T0, $A4, $T1
    vpaddq    $T1, $R3, $R3
    vbroadcastss  $_r4_($state), $T0
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
  cmp \$16*2, $in_len
  jb  1f
  sub \$16*2, $in_len
  # load the next two blocks
  vmovdqu 16*0($in), $R2
  vmovdqu 16*1($in), $R3
  add \$16*2, $in

  vpunpcklqdq  $R3, $R2, $R0
  vpunpckhqdq  $R3, $R2, $R1

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
1:
  vpsrldq  \$8, $R0, $A0
  vpsrldq  \$8, $R1, $A1
  vpsrldq  \$8, $R2, $A2
  vpsrldq  \$8, $R3, $A3
  vpsrldq  \$8, $R4, $A4

  vpaddq  $R0, $A0, $A0
  vpaddq  $R1, $A1, $A1
  vpaddq  $R2, $A2, $A2
  vpaddq  $R3, $A3, $A3
  vpaddq  $R4, $A4, $A4
  # Reduce
  vpsrlq  \$26, $A3, $T0
  vpaddq  $T0, $A4, $A4
  vpand   $AND_MASK, $A3, $A3
  vpsrlq  \$26, $A4, $T0
  vpsllq  \$2, $T0, $T1
  vpaddq  $T1, $T0, $T0
  vpaddq  $T0, $A0, $A0
  vpand   $AND_MASK, $A4, $A4
  vpsrlq  \$26, $A0, $T0
  vpand   $AND_MASK, $A0, $A0
  vpaddq  $T0, $A1, $A1
  vpsrlq  \$26, $A1, $T0
  vpand   $AND_MASK, $A1, $A1
  vpaddq  $T0, $A2, $A2
  vpsrlq  \$26, $A2, $T0
  vpand   $AND_MASK, $A2, $A2
  vpaddq  $T0, $A3, $A3
  vpsrlq  \$26, $A3, $T0
  vpand   $AND_MASK, $A3, $A3
  vpaddq  $T0, $A4, $A4
3:
  cmp  \$16, $in_len
  jb  1f

  # load the next block
  vmovq  8*0($in), $R0
  vmovq  8*1($in), $R1
  add    \$16, $in
  sub    \$16, $in_len

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
2:
  # Multiply input by R[0]
  vmovq     $_r0_+8($state), $T0
  vpmuludq  $T0, $A0, $R0
  vpmuludq  $T0, $A1, $R1
  vpmuludq  $T0, $A2, $R2
  vpmuludq  $T0, $A3, $R3
  vpmuludq  $T0, $A4, $R4
  # Multiply input by R[1] (and R[1]*5)
  vmovq     $_r1_x5+8($state), $T0
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R0, $R0
  vmovq     $_r1_+8($state), $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R4, $R4
  # Etc
  vmovq     $_r2_x5+8($state), $T0
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R1, $R1
  vmovq     $_r2_+8($state), $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R4, $R4

  vmovq     $_r3_x5+8($state), $T0
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R2, $R2
  vmovq     $_r3_+8($state), $T0
  vpmuludq  $T0, $A0, $T1
  vpaddq    $T1, $R3, $R3
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R4, $R4

  vmovq     $_r4_x5+8($state), $T0
  vpmuludq  $T0, $A1, $T1
  vpaddq    $T1, $R0, $R0
  vpmuludq  $T0, $A2, $T1
  vpaddq    $T1, $R1, $R1
  vpmuludq  $T0, $A3, $T1
  vpaddq    $T1, $R2, $R2
  vpmuludq  $T0, $A4, $T1
  vpaddq    $T1, $R3, $R3
  vmovq     $_r4_+8($state), $T0
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

1:
  test $in_len, $in_len
  jz  1f

  vmovdqa  .Lone(%rip), $R0
3:
  dec  $in_len
  vpslldq  \$1, $R0, $R0
  vpinsrb  \$0, ($in, $in_len), $R0, $R0
  test $in_len, $in_len
  jnz  3b

  vpsrldq \$8, $R0, $R1
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
  vpaddq  $R0, $A3, $A3
  vpaddq  $R2, $A4, $A4
  xor  $in_len, $in_len
  jmp  2b
1:

  vmovd   $A0, $_A0_($state)
  vmovd   $A1, $_A1_($state)
  vmovd   $A2, $_A2_($state)
  vmovd   $A3, $_A3_($state)
  vmovd   $A4, $_A4_($state)

  mov $in, %rax
  vzeroupper
  ret
.size poly1305_update_avx,.-poly1305_update_avx
###############################################################################
# void poly1305_finish_avx(void* $state, uint64_t mac[2]);
.type poly1305_finish_avx,\@function, 2
.globl poly1305_finish_avx
poly1305_finish_avx:
___
my $mac="%rsi";
$code.=<<___;
  mov $_A0_($state), %r8d
  mov $_A1_($state), %eax
  mov $_A2_($state), %r9d
  mov $_A3_($state), %ecx
  mov $_A4_($state), %r10d

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
  add $_k_($state), %rax
  adc $_k_+8($state), %rcx
  mov %rax, ($mac)
  mov %rcx, 8($mac)
  ret
.size poly1305_finish_avx,.-poly1305_finish_avx
___
}
}}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;
print $code;
close STDOUT;

