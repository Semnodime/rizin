// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * This file describes the memory map of PICF16882 device in PIC16F family.
 * */

#ifndef RZ_PIC_MIDRANGE_PIC_MEMMAP_PIC16F882_H
#define RZ_PIC_MIDRANGE_PIC_MEMMAP_PIC16F882_H

#include "regtypes.h"

// clang-format off
PicMidrangeRegType pic16f882_reg_map[] = {
    /* BANK 0 */
    INDF,                   /* 0x00 */
    TMR0,                   /* 0x01 */
    PCL,                    /* 0x02 */
    STATUS,                 /* 0x03 */
    FSR,                    /* 0x04 */
    PORTA,                  /* 0x05 */
    PORTB,                  /* 0x06 */
    PORTC,                  /* 0x07 */
    UNIMPLEMENTED,          /* 0x08 */
    PORTE,                  /* 0x09 */
    PCLATH,                 /* 0x0a */
    INTCON,                 /* 0x0b */
    PIR1,                   /* 0x0c */
    PIR2,                   /* 0x0d */
    TMR1L,                  /* 0x0e */
    TMR1H,                  /* 0x0f */
    T1CON,                  /* 0x10 */
    TMR2,                   /* 0x11 */
    T2CON,                  /* 0x12 */
    SSPBUF,                 /* 0x13 */
    SSPCON,                 /* 0x14 */
    CCPR1L,                 /* 0x15 */
    CCPR1H,                 /* 0x16 */
    CCP1CON,                /* 0x17 */
    RCSTA,                  /* 0x18 */
    TXREG,                  /* 0x19 */
    RCREG,                  /* 0x1a */
    CCPR2L,                 /* 0x1b */
    CCPR2H,                 /* 0x1c */
    CCP2CON,                /* 0x1d */
    ADRESH,                 /* 0x1e */
    ADCON0,                 /* 0x1f */
    FREG,                   /* 0x20 */
    FREG,                   /* 0x21 */
    FREG,                   /* 0x22 */
    FREG,                   /* 0x23 */
    FREG,                   /* 0x24 */
    FREG,                   /* 0x25 */
    FREG,                   /* 0x26 */
    FREG,                   /* 0x27 */
    FREG,                   /* 0x28 */
    FREG,                   /* 0x29 */
    FREG,                   /* 0x2a */
    FREG,                   /* 0x2b */
    FREG,                   /* 0x2c */
    FREG,                   /* 0x2d */
    FREG,                   /* 0x2e */
    FREG,                   /* 0x2f */
    FREG,                   /* 0x30 */
    FREG,                   /* 0x31 */
    FREG,                   /* 0x32 */
    FREG,                   /* 0x33 */
    FREG,                   /* 0x34 */
    FREG,                   /* 0x35 */
    FREG,                   /* 0x36 */
    FREG,                   /* 0x37 */
    FREG,                   /* 0x38 */
    FREG,                   /* 0x39 */
    FREG,                   /* 0x3a */
    FREG,                   /* 0x3b */
    FREG,                   /* 0x3c */
    FREG,                   /* 0x3d */
    FREG,                   /* 0x3e */
    FREG,                   /* 0x3f */
    FREG,                   /* 0x40 */
    FREG,                   /* 0x41 */
    FREG,                   /* 0x42 */
    FREG,                   /* 0x43 */
    FREG,                   /* 0x44 */
    FREG,                   /* 0x45 */
    FREG,                   /* 0x46 */
    FREG,                   /* 0x47 */
    FREG,                   /* 0x48 */
    FREG,                   /* 0x49 */
    FREG,                   /* 0x4a */
    FREG,                   /* 0x4b */
    FREG,                   /* 0x4c */
    FREG,                   /* 0x4d */
    FREG,                   /* 0x4e */
    FREG,                   /* 0x4f */
    FREG,                   /* 0x50 */
    FREG,                   /* 0x51 */
    FREG,                   /* 0x52 */
    FREG,                   /* 0x53 */
    FREG,                   /* 0x54 */
    FREG,                   /* 0x55 */
    FREG,                   /* 0x56 */
    FREG,                   /* 0x57 */
    FREG,                   /* 0x58 */
    FREG,                   /* 0x59 */
    FREG,                   /* 0x5a */
    FREG,                   /* 0x5b */
    FREG,                   /* 0x5c */
    FREG,                   /* 0x5d */
    FREG,                   /* 0x5e */
    FREG,                   /* 0x5f */
    FREG,                   /* 0x60 */
    FREG,                   /* 0x61 */
    FREG,                   /* 0x62 */
    FREG,                   /* 0x63 */
    FREG,                   /* 0x64 */
    FREG,                   /* 0x65 */
    FREG,                   /* 0x66 */
    FREG,                   /* 0x67 */
    FREG,                   /* 0x68 */
    FREG,                   /* 0x69 */
    FREG,                   /* 0x6a */
    FREG,                   /* 0x6b */
    FREG,                   /* 0x6c */
    FREG,                   /* 0x6d */
    FREG,                   /* 0x6e */
    FREG,                   /* 0x6f */
    FREG,                   /* 0x70 */
    FREG,                   /* 0x71 */
    FREG,                   /* 0x72 */
    FREG,                   /* 0x73 */
    FREG,                   /* 0x74 */
    FREG,                   /* 0x75 */
    FREG,                   /* 0x76 */
    FREG,                   /* 0x77 */
    FREG,                   /* 0x78 */
    FREG,                   /* 0x79 */
    FREG,                   /* 0x7a */
    FREG,                   /* 0x7b */
    FREG,                   /* 0x7c */
    FREG,                   /* 0x7d */
    FREG,                   /* 0x7e */
    FREG,                   /* 0x7f */

    /* BANK1 */

    INDF,                   /* 0x80 */
    OPTION_REG,             /* 0x81 */
    PCL,                    /* 0x82 */
    STATUS,                 /* 0x83 */
    FSR,                    /* 0x84 */
    TRISA,                  /* 0x85 */
    TRISB,                  /* 0x86 */
    TRISC,                  /* 0x87 */
    UNIMPLEMENTED,          /* 0x88 */
    TRISE,                  /* 0x89 */
    PCLATH,                 /* 0x8a */
    INTCON,                 /* 0x8b */
    PIE1,                   /* 0x8c */
    PIE2,                   /* 0x8d */
    PCON,                   /* 0x8e */
    OSCCON,                 /* 0x8f */
    OSCTUNE,                /* 0x90 */
    SSPCON2,                /* 0x91 */
    PR2,                    /* 0x92 */
    SSPADD,                 /* 0x93 */
    SSPSTAT,                /* 0x94 */
    WPUB,                   /* 0x95 */
    IOCB,                   /* 0x96 */
    VRCON,                  /* 0x97 */
    RCSTA,                  /* 0x98 */
    TXSTA,                  /* 0x99 */
    SPBRG,                  /* 0x9a */
    SPBRGH,                 /* 0x9b */
    PWM1CON,                /* 0x9c */
    ECCPAS,                 /* 0x9d */
    ADRESL,                 /* 0x9e */
    ADCON1,                 /* 0x9f */
    FREG,                   /* 0xa0 */
    FREG,                   /* 0xa1 */
    FREG,                   /* 0xa2 */
    FREG,                   /* 0xa3 */
    FREG,                   /* 0xa4 */
    FREG,                   /* 0xa5 */
    FREG,                   /* 0xa6 */
    FREG,                   /* 0xa7 */
    FREG,                   /* 0xa8 */
    FREG,                   /* 0xa9 */
    FREG,                   /* 0xaa */
    FREG,                   /* 0xab */
    FREG,                   /* 0xac */
    FREG,                   /* 0xad */
    FREG,                   /* 0xae */
    FREG,                   /* 0xaf */
    FREG,                   /* 0xb0 */
    FREG,                   /* 0xb1 */
    FREG,                   /* 0xb2 */
    FREG,                   /* 0xb3 */
    FREG,                   /* 0xb4 */
    FREG,                   /* 0xb5 */
    FREG,                   /* 0xb6 */
    FREG,                   /* 0xb7 */
    FREG,                   /* 0xb8 */
    FREG,                   /* 0xb9 */
    FREG,                   /* 0xba */
    FREG,                   /* 0xbb */
    FREG,                   /* 0xbc */
    FREG,                   /* 0xbd */
    FREG,                   /* 0xbe */
    FREG,                   /* 0xbf */
    UNIMPLEMENTED,          /* 0xc0 */
    UNIMPLEMENTED,          /* 0xc1 */
    UNIMPLEMENTED,          /* 0xc2 */
    UNIMPLEMENTED,          /* 0xc3 */
    UNIMPLEMENTED,          /* 0xc4 */
    UNIMPLEMENTED,          /* 0xc5 */
    UNIMPLEMENTED,          /* 0xc6 */
    UNIMPLEMENTED,          /* 0xc7 */
    UNIMPLEMENTED,          /* 0xc8 */
    UNIMPLEMENTED,          /* 0xc9 */
    UNIMPLEMENTED,          /* 0xca */
    UNIMPLEMENTED,          /* 0xcb */
    UNIMPLEMENTED,          /* 0xcc */
    UNIMPLEMENTED,          /* 0xcd */
    UNIMPLEMENTED,          /* 0xce */
    UNIMPLEMENTED,          /* 0xcf */
    UNIMPLEMENTED,          /* 0xd0 */
    UNIMPLEMENTED,          /* 0xd1 */
    UNIMPLEMENTED,          /* 0xd2 */
    UNIMPLEMENTED,          /* 0xd3 */
    UNIMPLEMENTED,          /* 0xd4 */
    UNIMPLEMENTED,          /* 0xd5 */
    UNIMPLEMENTED,          /* 0xd6 */
    UNIMPLEMENTED,          /* 0xd7 */
    UNIMPLEMENTED,          /* 0xd8 */
    UNIMPLEMENTED,          /* 0xd9 */
    UNIMPLEMENTED,          /* 0xda */
    UNIMPLEMENTED,          /* 0xdb */
    UNIMPLEMENTED,          /* 0xdc */
    UNIMPLEMENTED,          /* 0xdd */
    UNIMPLEMENTED,          /* 0xde */
    UNIMPLEMENTED,          /* 0xdf */
    UNIMPLEMENTED,          /* 0xe0 */
    UNIMPLEMENTED,          /* 0xe1 */
    UNIMPLEMENTED,          /* 0xe2 */
    UNIMPLEMENTED,          /* 0xe3 */
    UNIMPLEMENTED,          /* 0xe4 */
    UNIMPLEMENTED,          /* 0xe5 */
    UNIMPLEMENTED,          /* 0xe6 */
    UNIMPLEMENTED,          /* 0xe7 */
    UNIMPLEMENTED,          /* 0xe8 */
    UNIMPLEMENTED,          /* 0xe9 */
    UNIMPLEMENTED,          /* 0xea */
    UNIMPLEMENTED,          /* 0xeb */
    UNIMPLEMENTED,          /* 0xec */
    UNIMPLEMENTED,          /* 0xed */
    UNIMPLEMENTED,          /* 0xee */
    UNIMPLEMENTED,          /* 0xef */
    FREG,                   /* 0xf0 */
    FREG,                   /* 0xf1 */
    FREG,                   /* 0xf2 */
    FREG,                   /* 0xf3 */
    FREG,                   /* 0xf4 */
    FREG,                   /* 0xf5 */
    FREG,                   /* 0xf6 */
    FREG,                   /* 0xf7 */
    FREG,                   /* 0xf8 */
    FREG,                   /* 0xf9 */
    FREG,                   /* 0xfa */
    FREG,                   /* 0xfb */
    FREG,                   /* 0xfc */
    FREG,                   /* 0xfd */
    FREG,                   /* 0xfe */
    FREG,                   /* 0xff */

    /* BANK 2 */

    INDF,                   /* 0x100 */
    TMR0,                   /* 0x101 */
    PCL,                    /* 0x102 */
    STATUS,                 /* 0x103 */
    FSR,                    /* 0x104 */
    WDTCON,                 /* 0x105 */
    PORTB,                  /* 0x106 */
    CM1CON0,                /* 0x107 */
    CM2CON0,                /* 0x108 */
    CM2CON1,                /* 0x109 */
    PCLATH,                 /* 0x10a */
    INTCON,                 /* 0x10b */
    EEDAT,                  /* 0x10c */
    EEADR,                  /* 0x10d */
    EEDATH,                 /* 0x10e */
    EEADRH,                 /* 0x10f */
    UNIMPLEMENTED,          /* 0x110 */
    UNIMPLEMENTED,          /* 0x111 */
    UNIMPLEMENTED,          /* 0x112 */
    UNIMPLEMENTED,          /* 0x113 */
    UNIMPLEMENTED,          /* 0x114 */
    UNIMPLEMENTED,          /* 0x115 */
    UNIMPLEMENTED,          /* 0x116 */
    UNIMPLEMENTED,          /* 0x117 */
    UNIMPLEMENTED,          /* 0x118 */
    UNIMPLEMENTED,          /* 0x119 */
    UNIMPLEMENTED,          /* 0x11a */
    UNIMPLEMENTED,          /* 0x11b */
    UNIMPLEMENTED,          /* 0x11c */
    UNIMPLEMENTED,          /* 0x11d */
    UNIMPLEMENTED,          /* 0x11e */
    UNIMPLEMENTED,          /* 0x11f */
    UNIMPLEMENTED,          /* 0x120 */
    UNIMPLEMENTED,          /* 0x121 */
    UNIMPLEMENTED,          /* 0x122 */
    UNIMPLEMENTED,          /* 0x123 */
    UNIMPLEMENTED,          /* 0x124 */
    UNIMPLEMENTED,          /* 0x125 */
    UNIMPLEMENTED,          /* 0x126 */
    UNIMPLEMENTED,          /* 0x127 */
    UNIMPLEMENTED,          /* 0x128 */
    UNIMPLEMENTED,          /* 0x129 */
    UNIMPLEMENTED,          /* 0x12a */
    UNIMPLEMENTED,          /* 0x12b */
    UNIMPLEMENTED,          /* 0x12c */
    UNIMPLEMENTED,          /* 0x12d */
    UNIMPLEMENTED,          /* 0x12e */
    UNIMPLEMENTED,          /* 0x12f */
    UNIMPLEMENTED,          /* 0x130 */
    UNIMPLEMENTED,          /* 0x131 */
    UNIMPLEMENTED,          /* 0x132 */
    UNIMPLEMENTED,          /* 0x133 */
    UNIMPLEMENTED,          /* 0x134 */
    UNIMPLEMENTED,          /* 0x135 */
    UNIMPLEMENTED,          /* 0x136 */
    UNIMPLEMENTED,          /* 0x137 */
    UNIMPLEMENTED,          /* 0x138 */
    UNIMPLEMENTED,          /* 0x139 */
    UNIMPLEMENTED,          /* 0x13a */
    UNIMPLEMENTED,          /* 0x13b */
    UNIMPLEMENTED,          /* 0x13c */
    UNIMPLEMENTED,          /* 0x13d */
    UNIMPLEMENTED,          /* 0x13e */
    UNIMPLEMENTED,          /* 0x13f */
    UNIMPLEMENTED,          /* 0x140 */
    UNIMPLEMENTED,          /* 0x141 */
    UNIMPLEMENTED,          /* 0x142 */
    UNIMPLEMENTED,          /* 0x143 */
    UNIMPLEMENTED,          /* 0x144 */
    UNIMPLEMENTED,          /* 0x145 */
    UNIMPLEMENTED,          /* 0x146 */
    UNIMPLEMENTED,          /* 0x147 */
    UNIMPLEMENTED,          /* 0x148 */
    UNIMPLEMENTED,          /* 0x149 */
    UNIMPLEMENTED,          /* 0x14a */
    UNIMPLEMENTED,          /* 0x14b */
    UNIMPLEMENTED,          /* 0x14c */
    UNIMPLEMENTED,          /* 0x14d */
    UNIMPLEMENTED,          /* 0x14e */
    UNIMPLEMENTED,          /* 0x14f */
    UNIMPLEMENTED,          /* 0x150 */
    UNIMPLEMENTED,          /* 0x151 */
    UNIMPLEMENTED,          /* 0x152 */
    UNIMPLEMENTED,          /* 0x153 */
    UNIMPLEMENTED,          /* 0x154 */
    UNIMPLEMENTED,          /* 0x155 */
    UNIMPLEMENTED,          /* 0x156 */
    UNIMPLEMENTED,          /* 0x157 */
    UNIMPLEMENTED,          /* 0x158 */
    UNIMPLEMENTED,          /* 0x159 */
    UNIMPLEMENTED,          /* 0x15a */
    UNIMPLEMENTED,          /* 0x15b */
    UNIMPLEMENTED,          /* 0x15c */
    UNIMPLEMENTED,          /* 0x15d */
    UNIMPLEMENTED,          /* 0x15e */
    UNIMPLEMENTED,          /* 0x15f */
    UNIMPLEMENTED,          /* 0x160 */
    UNIMPLEMENTED,          /* 0x161 */
    UNIMPLEMENTED,          /* 0x162 */
    UNIMPLEMENTED,          /* 0x163 */
    UNIMPLEMENTED,          /* 0x164 */
    UNIMPLEMENTED,          /* 0x165 */
    UNIMPLEMENTED,          /* 0x166 */
    UNIMPLEMENTED,          /* 0x167 */
    UNIMPLEMENTED,          /* 0x168 */
    UNIMPLEMENTED,          /* 0x169 */
    UNIMPLEMENTED,          /* 0x16a */
    UNIMPLEMENTED,          /* 0x16b */
    UNIMPLEMENTED,          /* 0x16c */
    UNIMPLEMENTED,          /* 0x16d */
    UNIMPLEMENTED,          /* 0x16e */
    UNIMPLEMENTED,          /* 0x16f */
    FREG,                   /* 0x170 */
    FREG,                   /* 0x171 */
    FREG,                   /* 0x172 */
    FREG,                   /* 0x173 */
    FREG,                   /* 0x174 */
    FREG,                   /* 0x175 */
    FREG,                   /* 0x176 */
    FREG,                   /* 0x177 */
    FREG,                   /* 0x178 */
    FREG,                   /* 0x179 */
    FREG,                   /* 0x17a */
    FREG,                   /* 0x17b */
    FREG,                   /* 0x17c */
    FREG,                   /* 0x17d */
    FREG,                   /* 0x17e */
    FREG,                   /* 0x17f */

    /* BANK 3 */

    INDF,                   /* 0x180 */
    OPTION_REG,             /* 0x181 */
    PCL,                    /* 0x182 */
    STATUS,                 /* 0x183 */
    FSR,                    /* 0x184 */
    SRCON,                  /* 0x185 */
    TRISB,                  /* 0x186 */
    BAUDCTL,                /* 0x187 */
    ANSEL,                  /* 0x188 */
    ANSELH,                 /* 0x189 */
    PCLATH,                 /* 0x18a */
    INTCON,                 /* 0x18b */
    EECON1,                 /* 0x18c */
    EECON2,                 /* 0x18d */
    _RESERVED,               /* 0x18e */
    _RESERVED,               /* 0x18f */
    UNIMPLEMENTED,          /* 0x190 */
    UNIMPLEMENTED,          /* 0x191 */
    UNIMPLEMENTED,          /* 0x192 */
    UNIMPLEMENTED,          /* 0x193 */
    UNIMPLEMENTED,          /* 0x194 */
    UNIMPLEMENTED,          /* 0x195 */
    UNIMPLEMENTED,          /* 0x196 */
    UNIMPLEMENTED,          /* 0x197 */
    UNIMPLEMENTED,          /* 0x198 */
    UNIMPLEMENTED,          /* 0x199 */
    UNIMPLEMENTED,          /* 0x19a */
    UNIMPLEMENTED,          /* 0x19b */
    UNIMPLEMENTED,          /* 0x19c */
    UNIMPLEMENTED,          /* 0x19d */
    UNIMPLEMENTED,          /* 0x19e */
    UNIMPLEMENTED,          /* 0x19f */
    UNIMPLEMENTED,          /* 0x1a0 */
    UNIMPLEMENTED,          /* 0x1a1 */
    UNIMPLEMENTED,          /* 0x1a2 */
    UNIMPLEMENTED,          /* 0x1a3 */
    UNIMPLEMENTED,          /* 0x1a4 */
    UNIMPLEMENTED,          /* 0x1a5 */
    UNIMPLEMENTED,          /* 0x1a6 */
    UNIMPLEMENTED,          /* 0x1a7 */
    UNIMPLEMENTED,          /* 0x1a8 */
    UNIMPLEMENTED,          /* 0x1a9 */
    UNIMPLEMENTED,          /* 0x1aa */
    UNIMPLEMENTED,          /* 0x1ab */
    UNIMPLEMENTED,          /* 0x1ac */
    UNIMPLEMENTED,          /* 0x1ad */
    UNIMPLEMENTED,          /* 0x1ae */
    UNIMPLEMENTED,          /* 0x1af */
    UNIMPLEMENTED,          /* 0x1b0 */
    UNIMPLEMENTED,          /* 0x1b1 */
    UNIMPLEMENTED,          /* 0x1b2 */
    UNIMPLEMENTED,          /* 0x1b3 */
    UNIMPLEMENTED,          /* 0x1b4 */
    UNIMPLEMENTED,          /* 0x1b5 */
    UNIMPLEMENTED,          /* 0x1b6 */
    UNIMPLEMENTED,          /* 0x1b7 */
    UNIMPLEMENTED,          /* 0x1b8 */
    UNIMPLEMENTED,          /* 0x1b9 */
    UNIMPLEMENTED,          /* 0x1ba */
    UNIMPLEMENTED,          /* 0x1bb */
    UNIMPLEMENTED,          /* 0x1bc */
    UNIMPLEMENTED,          /* 0x1bd */
    UNIMPLEMENTED,          /* 0x1be */
    UNIMPLEMENTED,          /* 0x1bf */
    UNIMPLEMENTED,          /* 0x1c0 */
    UNIMPLEMENTED,          /* 0x1c1 */
    UNIMPLEMENTED,          /* 0x1c2 */
    UNIMPLEMENTED,          /* 0x1c3 */
    UNIMPLEMENTED,          /* 0x1c4 */
    UNIMPLEMENTED,          /* 0x1c5 */
    UNIMPLEMENTED,          /* 0x1c6 */
    UNIMPLEMENTED,          /* 0x1c7 */
    UNIMPLEMENTED,          /* 0x1c8 */
    UNIMPLEMENTED,          /* 0x1c9 */
    UNIMPLEMENTED,          /* 0x1ca */
    UNIMPLEMENTED,          /* 0x1cb */
    UNIMPLEMENTED,          /* 0x1cc */
    UNIMPLEMENTED,          /* 0x1cd */
    UNIMPLEMENTED,          /* 0x1ce */
    UNIMPLEMENTED,          /* 0x1cf */
    UNIMPLEMENTED,          /* 0x1d0 */
    UNIMPLEMENTED,          /* 0x1d1 */
    UNIMPLEMENTED,          /* 0x1d2 */
    UNIMPLEMENTED,          /* 0x1d3 */
    UNIMPLEMENTED,          /* 0x1d4 */
    UNIMPLEMENTED,          /* 0x1d5 */
    UNIMPLEMENTED,          /* 0x1d6 */
    UNIMPLEMENTED,          /* 0x1d7 */
    UNIMPLEMENTED,          /* 0x1d8 */
    UNIMPLEMENTED,          /* 0x1d9 */
    UNIMPLEMENTED,          /* 0x1da */
    UNIMPLEMENTED,          /* 0x1db */
    UNIMPLEMENTED,          /* 0x1dc */
    UNIMPLEMENTED,          /* 0x1dd */
    UNIMPLEMENTED,          /* 0x1de */
    UNIMPLEMENTED,          /* 0x1df */
    UNIMPLEMENTED,          /* 0x1e0 */
    UNIMPLEMENTED,          /* 0x1e1 */
    UNIMPLEMENTED,          /* 0x1e2 */
    UNIMPLEMENTED,          /* 0x1e3 */
    UNIMPLEMENTED,          /* 0x1e4 */
    UNIMPLEMENTED,          /* 0x1e5 */
    UNIMPLEMENTED,          /* 0x1e6 */
    UNIMPLEMENTED,          /* 0x1e7 */
    UNIMPLEMENTED,          /* 0x1e8 */
    UNIMPLEMENTED,          /* 0x1e9 */
    UNIMPLEMENTED,          /* 0x1ea */
    UNIMPLEMENTED,          /* 0x1eb */
    UNIMPLEMENTED,          /* 0x1ec */
    UNIMPLEMENTED,          /* 0x1ed */
    UNIMPLEMENTED,          /* 0x1ee */
    UNIMPLEMENTED,          /* 0x1ef */
    FREG,                   /* 0x1f0 */
    FREG,                   /* 0x1f1 */
    FREG,                   /* 0x1f2 */
    FREG,                   /* 0x1f3 */
    FREG,                   /* 0x1f4 */
    FREG,                   /* 0x1f5 */
    FREG,                   /* 0x1f6 */
    FREG,                   /* 0x1f7 */
    FREG,                   /* 0x1f8 */
    FREG,                   /* 0x1f9 */
    FREG,                   /* 0x1fa */
    FREG,                   /* 0x1fb */
    FREG,                   /* 0x1fc */
    FREG,                   /* 0x1fd */
    FREG,                   /* 0x1fe */
    FREG,                   /* 0x1ff */
};
// clang-format on

#endif // RZ_PIC_MIDRANGE_PIC_MEMMAP_PIC16F882_H
