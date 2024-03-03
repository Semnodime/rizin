// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015-2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_analysis.h>

#include "pic/pic_midrange.h"
#include "pic/pic_il.h"

typedef struct _pic_midrange_op_args_val {
	ut16 f;
	ut16 k;
	ut8 d;
	ut8 m;
	ut8 n;
	ut8 b;
} PicMidrangeOpArgsVal;

typedef void (*pic_midrange_inst_handler_t)(RzAnalysis *analysis, RzAnalysisOp *op,
	ut64 addr,
	PicMidrangeOpArgsVal *args);

typedef struct _pic_midrange_op_analysis_info {
	PicMidrangeOpcode opcode;
	PicMidrangeOpArgs args;
	pic_midrange_inst_handler_t handler;
	pic_midrange_il_handler il_handler;
} PicMidrangeOpAnalysisInfo;

#define INST_HANDLER(OPCODE_NAME) \
	static void _inst__##OPCODE_NAME(RzAnalysis *analysis, RzAnalysisOp *op, \
		ut64 addr, \
		PicMidrangeOpArgsVal *args)
#define INST_DECL(NAME, ARGS) \
	[PIC_MIDRANGE_OPCODE_##NAME] = { \
		PIC_MIDRANGE_OPCODE_##NAME, PIC_MIDRANGE_OP_ARGS_##ARGS, \
		_inst__##NAME, IL_LIFTER(NAME) \
	}

#define e(frag)       rz_strbuf_append(&op->esil, frag)
#define ef(frag, ...) rz_strbuf_appendf(&op->esil, frag, __VA_ARGS__)

#define PIC_MIDRANGE_ESIL_SRAM_START (1 << 16)
#define PIC_MIDRANGE_ESIL_CSTACK_TOP ((1 << 16) + (1 << 12))

#define PIC_MIDRANGE_ESIL_BSR_ADDR "bsr,0x80,*,0x%x,+,_sram,+"

#define PIC_MIDRANGE_ESIL_OPTION_ADDR "0x95,_sram,+"

#define PIC_MIDRANGE_ESIL_UPDATE_FLAGS \
	"$z,z,:=," \
	"7,$c,c,:=," \
	"4,$c,dc,:=,"

#define PIC_MIDRANGE_ESIL_LW_OP(O) \
	"0x%x,wreg," #O "=," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

#define PIC_MIDRANGE_ESIL_FWF_OP(O) \
	"wreg," PIC_MIDRANGE_ESIL_BSR_ADDR "," #O \
	"=[1]," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

#define PIC_MIDRANGE_ESIL_WWF_OP(O) \
	PIC_MIDRANGE_ESIL_BSR_ADDR \
	",[1]," \
	"wreg," #O "=," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

#define PIC_MIDRANGE_ESIL_FWF_OP_C(O) \
	"c,wreg," \
	"+," PIC_MIDRANGE_ESIL_BSR_ADDR "," #O \
	"=[1]," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

#define PIC_MIDRANGE_ESIL_WWF_OP_C(O) \
	"c," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1]," #O "," \
	"wreg," #O "=," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

INST_HANDLER(NOP) {}

INST_HANDLER(RETFIE) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
}

INST_HANDLER(OPTION) {
	op->type = RZ_ANALYSIS_OP_TYPE_STORE;
}

INST_HANDLER(TRIS) {
	op->type = RZ_ANALYSIS_OP_TYPE_STORE;
}

INST_HANDLER(RETURN) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	e("0x1f,stkptr,==,$z,?{,BREAK,},");
	e("_stack,stkptr,2,*,+,[2],2,*,pc,=,");
	e("0x01,stkptr,-=,");
	e("0xff,stkptr,==,$z,?{,0x1f,stkptr,=,},");
}

INST_HANDLER(CALL) {
	ut64 pclath;
	op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	rz_analysis_esil_reg_read(analysis->esil, "pclath", &pclath, NULL);
	op->jump = 2 * (((pclath & 0x78) << 8) + args->k);
	ef("8,pclath,0x78,&,<<,0x%x,+,2,*,pc,=,", args->k);
	e("0x1f,stkptr,==,$z,?{,0xff,stkptr,=,},");
	e("0x0f,stkptr,==,$z,?{,0xff,stkptr,=,},");
	e("0x01,stkptr,+=,");
	ef("0x%" PFMT64x ",_stack,stkptr,2,*,+,=[2],", (addr + 2) / 2);
}

INST_HANDLER(GOTO) {
	ut64 pclath;
	op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	rz_analysis_esil_reg_read(analysis->esil, "pclath", &pclath, NULL);
	op->jump = 2 * (((pclath & 0x78) << 8) + args->k);
	ef("8,pclath,0x78,&,<<,0x%x,+,2,*,pc,=,", args->k);
}

INST_HANDLER(BCF) {
	ut8 mask = ~(1 << args->b);
	ef(PIC_MIDRANGE_ESIL_BSR_ADDR
		",[1],0x%x,&," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],",
		args->f, mask, args->f);
}

INST_HANDLER(BSF) {
	ut8 mask = (1 << args->b);
	ef(PIC_MIDRANGE_ESIL_BSR_ADDR
		",[1],0x%x,|," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],",
		args->f, mask, args->f);
}

INST_HANDLER(BTFSC) {
	ut8 mask = (1 << args->b);
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	op->jump = addr + 4;
	op->fail = addr + 2;
	ef(PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],0x%x,&,!,?{,0x%" PFMT64x ",pc,=,},",
		args->f, mask, op->jump);
}

INST_HANDLER(BTFSS) {
	ut8 mask = (1 << args->b);
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	op->jump = addr + 4;
	op->fail = addr + 2;
	ef(PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],0x%x,&,?{,0x%" PFMT64x ",pc,=,},", args->f,
		mask, op->jump);
}

INST_HANDLER(BRA) {
	st16 branch = args->k;
	op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	branch |= ((branch & 0x100) ? 0xfe00 : 0);
	op->jump = addr + 2 * (branch + 1);
	ef("%s0x%x,1,+,2,*,pc,+=,", branch < 0 ? "-" : "",
		branch < 0 ? -branch : branch);
}

INST_HANDLER(BRW) {
	ut64 wreg;
	op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
	rz_analysis_esil_reg_read(analysis->esil, "wreg", &wreg, NULL);
	op->jump = addr + 2 * (wreg + 1);
	e("wreg,1,+,2,*,pc,+=,");
}

INST_HANDLER(CLR) {
	if (args->d) {
		ef("0x00," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],", args->f);
	} else {
		e("0x00,wreg,=,");
	}
	e("1,z,=,");
}

INST_HANDLER(SUBWF) {
	op->type = RZ_ANALYSIS_OP_TYPE_SUB;
	if (args->d) {
		ef(PIC_MIDRANGE_ESIL_FWF_OP(-), args->f);
	} else {
		ef(PIC_MIDRANGE_ESIL_WWF_OP(-), args->f);
		e("wreg,0x00,-,wreg,=,c,!=,dc,!=,");
	}
}

INST_HANDLER(DECFSZ) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	op->jump = addr + 4;
	op->fail = addr + 2;
	if (args->d) {
		ef("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",-=[1],", args->f);
	} else {
		ef("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],-,wreg,=,",
			args->f);
	}
	ef(PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],!,?{,0x%" PFMT64x ",pc,=,},", args->f,
		op->jump);
}

INST_HANDLER(INCFSZ) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	op->jump = addr + 4;
	op->fail = addr + 2;
	if (args->d) {
		ef("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",+=[1],", args->f);
	} else {
		ef("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],+,wreg,=,",
			args->f);
	}
	ef(PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],!,?{,0x%" PFMT64x ",pc,=,},", args->f,
		op->jump);
}

INST_HANDLER(INCF) {
	op->type = RZ_ANALYSIS_OP_TYPE_ADD;
	if (args->d) {
		ef("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",+=[1],", args->f);
	} else {
		ef("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],+,wreg,=,",
			args->f);
	}
	e("$z,z,:=,");
}

INST_HANDLER(DECF) {
	op->type = RZ_ANALYSIS_OP_TYPE_SUB;
	if (args->d) {
		ef("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",-=[1],", args->f);
	} else {
		ef("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],-,wreg,=,",
			args->f);
	}
	e("$z,z,:=,");
}

INST_HANDLER(IORWF) {
	op->type = RZ_ANALYSIS_OP_TYPE_OR;
	if (args->d) {
		ef(PIC_MIDRANGE_ESIL_FWF_OP(|), args->f);
	} else {
		ef(PIC_MIDRANGE_ESIL_WWF_OP(|), args->f);
	}
}

INST_HANDLER(ANDWF) {
	op->type = RZ_ANALYSIS_OP_TYPE_AND;
	if (args->d) {
		ef(PIC_MIDRANGE_ESIL_FWF_OP(&), args->f);
	} else {
		ef(PIC_MIDRANGE_ESIL_WWF_OP(&), args->f);
	}
}

INST_HANDLER(XORWF) {
	op->type = RZ_ANALYSIS_OP_TYPE_XOR;
	if (args->d) {
		ef(PIC_MIDRANGE_ESIL_FWF_OP(^), args->f);
	} else {
		ef(PIC_MIDRANGE_ESIL_WWF_OP(^), args->f);
	}
}

INST_HANDLER(ADDWF) {
	op->type = RZ_ANALYSIS_OP_TYPE_ADD;
	if (args->d) {
		ef(PIC_MIDRANGE_ESIL_FWF_OP(+), args->f);
	} else {
		ef(PIC_MIDRANGE_ESIL_WWF_OP(+), args->f);
	}
}

INST_HANDLER(SUBLW) {
	op->type = RZ_ANALYSIS_OP_TYPE_SUB;
	ef(PIC_MIDRANGE_ESIL_LW_OP(-), args->k);
}

INST_HANDLER(ADDLW) {
	op->type = RZ_ANALYSIS_OP_TYPE_ADD;
	ef(PIC_MIDRANGE_ESIL_LW_OP(+), args->k);
}

INST_HANDLER(IORLW) {
	op->type = RZ_ANALYSIS_OP_TYPE_OR;
	ef(PIC_MIDRANGE_ESIL_LW_OP(|), args->k);
}

INST_HANDLER(ANDLW) {
	op->type = RZ_ANALYSIS_OP_TYPE_AND;
	ef(PIC_MIDRANGE_ESIL_LW_OP(&), args->k);
}

INST_HANDLER(XORLW) {
	op->type = RZ_ANALYSIS_OP_TYPE_XOR;
	ef(PIC_MIDRANGE_ESIL_LW_OP(^), args->k);
}

INST_HANDLER(MOVLW) {
	op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
	ef("0x%x,wreg,=,", args->k);
}

INST_HANDLER(RETLW) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	ef("0x%x,wreg,=,", args->k);
	e("0x1f,stkptr,==,$z,?{,BREAK,},");
	e("_stack,stkptr,2,*,+,[2],2,*,pc,=,");
	e("0x01,stkptr,-=,");
	e("0xff,stkptr,==,$z,?{,0x1f,stkptr,=,},");
}

INST_HANDLER(MOVLP) {
	op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
	ef("0x%x,pclath,=,", args->f);
}

INST_HANDLER(MOVLB) {
	op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
	ef("0x%x,bsr,=,", args->k);
}

INST_HANDLER(CALLW) {
	op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
	e("8,pclath,<<,0x%x,+,wreg,2,*,pc,=,");
	e("0x1f,stkptr,==,$z,?{,0xff,stkptr,=,},");
	e("0x0f,stkptr,==,$z,?{,0xff,stkptr,=,},");
	e("0x01,stkptr,+=,");
	ef("0x%" PFMT64x ",_stack,stkptr,2,*,+,=[2],", (addr + 2) / 2);
}

INST_HANDLER(MOVWF) {
	op->type = RZ_ANALYSIS_OP_TYPE_STORE;
	ef("wreg," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],", args->f);
}

INST_HANDLER(MOVF) {
	op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
	if (args->d) {
		ef(PIC_MIDRANGE_ESIL_BSR_ADDR
			",[1]," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],",
			args->f, args->f);
	} else {
		ef(PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],wreg,=,", args->f);
	}
	e("$z,z,:=,");
}

INST_HANDLER(SWAPF) {
	ef("4," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,0x0f,&,", args->f);
	ef("4," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],<<,0xf0,&,", args->f);
	e("|,");
	ef(PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],", args->f);
}

INST_HANDLER(LSLF) {
	op->type = RZ_ANALYSIS_OP_TYPE_SHL;
	ef("7," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,c,=,", args->f);
	if (args->d) {
		ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",<<=[1],", args->f);
	} else {
		ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],<<,wreg,=,",
			args->f);
	}
	e("$z,z,:=,");
}

INST_HANDLER(LSRF) {
	op->type = RZ_ANALYSIS_OP_TYPE_SHR;
	ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],&,c,=,", args->f);
	if (args->d) {
		ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",>>=[1],", args->f);
	} else {
		ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,wreg,=,",
			args->f);
	}
	e("$z,z,:=,");
}

INST_HANDLER(ASRF) {
	op->type = RZ_ANALYSIS_OP_TYPE_SHR;
	ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],&,c,=,", args->f);
	ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,", args->f);
	ef("0x80," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],&,", args->f);
	if (args->d) {
		ef("|," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],", args->f);
	} else {
		e("|,wreg,=,");
	}
	e("$z,z,:=,");
}

INST_HANDLER(RRF) {
	op->type = RZ_ANALYSIS_OP_TYPE_ROR;
	ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],&,", args->f);
	if (args->d) {
		ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",>>=[1],"
		   "c," PIC_MIDRANGE_ESIL_BSR_ADDR ",|=[1],",
			args->f, args->f);
	} else {
		ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,wreg,=,"
		   "c,wreg,|=[1],",
			args->f);
	}
	e("c,=,");
}

INST_HANDLER(RLF) {
	op->type = RZ_ANALYSIS_OP_TYPE_ROL;
	ef("7," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,", args->f);
	if (args->d) {
		ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",<<=[1],"
		   "c," PIC_MIDRANGE_ESIL_BSR_ADDR ",|=[1],",
			args->f, args->f);
	} else {
		ef("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],<<,wreg,=,"
		   "c,wreg,|=[1],",
			args->f);
	}
	e("c,=,");
}

INST_HANDLER(COMF) {
	if (args->d) {
		ef("0xff," PIC_MIDRANGE_ESIL_BSR_ADDR ",^=[1],", args->f);
	} else {
		ef("0xff," PIC_MIDRANGE_ESIL_BSR_ADDR ",^,wreg,=,", args->f);
	}
	e("$z,z,:=,");
}

INST_HANDLER(RESET) {
	op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	op->jump = 0;
	e("0x0,pc,=,");
	e("0x1f,stkptr,=,");
}

INST_HANDLER(ADDFSR) {
	op->type = RZ_ANALYSIS_OP_TYPE_ADD;
	if (args->n == 0) {
		ef("0x%x,fsr0l,+=,", args->k);
		e("7,$c,?{,0x01,fsr0h,+=,},");
	} else {
		ef("0x%x,fsr1l,+=,", args->k);
		e("7,$c,?{,0x01,fsr1h,+=,},");
	}
}

INST_HANDLER(CLRWDT) {
	e("1,to,=,");
	e("1,pd,=,");
}

INST_HANDLER(SLEEP) {
	e("1,to,=,");
	e("0,pd,=,");
}

INST_HANDLER(SUBWFB) {
	op->type = RZ_ANALYSIS_OP_TYPE_SUB;
	e("c,!=,");
	if (args->d) {
		ef(PIC_MIDRANGE_ESIL_FWF_OP_C(-), args->f);
	} else {
		ef(PIC_MIDRANGE_ESIL_WWF_OP_C(-), args->f);
		e("wreg,0x00,-,wreg,=,c,!=,dc,!=,");
	}
}

INST_HANDLER(ADDWFC) {
	op->type = RZ_ANALYSIS_OP_TYPE_ADD;
	if (args->d) {
		ef(PIC_MIDRANGE_ESIL_FWF_OP_C(+), args->f);
	} else {
		ef(PIC_MIDRANGE_ESIL_WWF_OP_C(+), args->f);
	}
}

INST_HANDLER(MOVIW_1) {
	if (args->n == 0) {
		if (!(args->m & 2)) {
			ef("1,fsr0l,%s=,", (args->m & 1) ? "-" : "+");
			ef("7,$c%s,fsr0h,%s,", (args->m & 1) ? ",!" : "",
				(args->m & 1) ? "-" : "+");
		}
		e("indf0,wreg,=,");
		e("$z,z,:=,");
		if (args->m & 2) {
			ef("1,fsr0l,%s=,", (args->m & 1) ? "-" : "+");
			ef("7,$c%s,fsr0h,%s,", (args->m & 1) ? ",!" : "",
				(args->m & 1) ? "-" : "+");
		}
	} else {
		if (!(args->m & 2)) {
			ef("1,fsr1l,%s=,", (args->m & 1) ? "-" : "+");
			ef("7,$c%s,fsr1h,%s,", (args->m & 1) ? ",!" : "",
				(args->m & 1) ? "-" : "+");
		}
		e("indf1,wreg,=,");
		e("$z,z,:=,");
		if (args->m & 2) {
			ef("1,fsr1l,%s=,", (args->m & 1) ? "-" : "+");
			ef("7,$c%s,fsr1h,%s,", (args->m & 1) ? ",!" : "",
				(args->m & 1) ? "-" : "+");
		}
	}
}

INST_HANDLER(MOVWI_1) {
	if (args->n == 0) {
		if (!(args->m & 2)) {
			ef("1,fsr0l,%s=,", (args->m & 1) ? "-" : "+");
			ef("$c7%s,fsr0h,%s,", (args->m & 1) ? ",!" : "",
				(args->m & 1) ? "-" : "+");
		}
		e("wreg,indf0=,");
		e("$z,z,:=,");
		if (args->m & 2) {
			ef("1,fsr0l,%s=,", (args->m & 1) ? "-" : "+");
			ef("$c7%s,fsr0h,%s,", (args->m & 1) ? ",!" : "",
				(args->m & 1) ? "-" : "+");
		}
	} else {
		if (!(args->m & 2)) {
			ef("1,fsr1l,%s=,", (args->m & 1) ? "-" : "+");
			ef("$c7,fsr1h,%s,", (args->m & 1) ? ",!" : "");
		}
		e("wreg,indf1=,");
		e("$z,z,:=,");
		if (args->m & 2) {
			ef("1,fsr1l,%s=,", (args->m & 1) ? "-" : "+");
			ef("$c7%s,fsr1h,%s,", (args->m & 1) ? ",!" : "",
				(args->m & 1) ? "-" : "+");
		}
	}
}

INST_HANDLER(MOVIW_2) {
	if (args->n == 0) {
		e("fsr0l,8,fsr0h,<<,+,");
	} else {
		e("fsr1l,8,fsr1h,<<,+,");
	}
	ef("0x%x,+,[1],wreg,=,", args->k);
}

INST_HANDLER(MOVWI_2) {
	e("wreg,");
	if (args->n == 0) {
		e("fsr0l,8,fsr0h,<<,+,");
	} else {
		e("fsr1l,8,fsr1h,<<,+,");
	}
	e("=[1],");
}

INST_HANDLER(CLRF) {}

static const PicMidrangeOpAnalysisInfo pic_midrange_op_analysis_info[] = {
	INST_DECL(NOP, NONE),
	INST_DECL(RETURN, NONE),
	INST_DECL(RETFIE, NONE),
	INST_DECL(OPTION, NONE),
	INST_DECL(SLEEP, NONE),
	INST_DECL(CLRWDT, NONE),
	INST_DECL(TRIS, 2F),
	INST_DECL(MOVWF, 7F),
	INST_DECL(CLR, 1D_7F),
	INST_DECL(SUBWF, 1D_7F),
	INST_DECL(DECF, 1D_7F),
	INST_DECL(IORWF, 1D_7F),
	INST_DECL(ANDWF, 1D_7F),
	INST_DECL(XORWF, 1D_7F),
	INST_DECL(ADDWF, 1D_7F),
	INST_DECL(MOVF, 1D_7F),
	INST_DECL(COMF, 1D_7F),
	INST_DECL(INCF, 1D_7F),
	INST_DECL(DECFSZ, 1D_7F),
	INST_DECL(RRF, 1D_7F),
	INST_DECL(RLF, 1D_7F),
	INST_DECL(SWAPF, 1D_7F),
	INST_DECL(INCFSZ, 1D_7F),
	INST_DECL(BCF, 3B_7F),
	INST_DECL(BSF, 3B_7F),
	INST_DECL(BTFSC, 3B_7F),
	INST_DECL(BTFSS, 3B_7F),
	INST_DECL(CALL, 11K),
	INST_DECL(GOTO, 11K),
	INST_DECL(MOVLW, 8K),
	INST_DECL(RETLW, 8K),
	INST_DECL(IORLW, 8K),
	INST_DECL(ANDLW, 8K),
	INST_DECL(XORLW, 8K),
	INST_DECL(SUBLW, 8K),
	INST_DECL(ADDLW, 8K),
	INST_DECL(RESET, NONE),
	INST_DECL(CALLW, NONE),
	INST_DECL(BRW, NONE),
	INST_DECL(MOVIW_1, 1N_2M),
	INST_DECL(MOVWI_1, 1N_2M),
	INST_DECL(MOVLB, 4K),
	INST_DECL(LSLF, 1D_7F),
	INST_DECL(LSRF, 1D_7F),
	INST_DECL(ASRF, 1D_7F),
	INST_DECL(SUBWFB, 1D_7F),
	INST_DECL(ADDWFC, 1D_7F),
	INST_DECL(ADDFSR, 1N_6K),
	INST_DECL(MOVLP, 7F),
	INST_DECL(BRA, 9K),
	INST_DECL(MOVIW_2, 1N_6K),
	INST_DECL(MOVWI_2, 1N_6K),
	INST_DECL(CLRF, 7F),
};

static void analysis_pic_midrange_extract_args(ut16 instr,
	PicMidrangeOpArgs args,
	PicMidrangeOpArgsVal *args_val) {

	memset(args_val, 0, sizeof(PicMidrangeOpArgsVal));

	switch (args) {
	case PIC_MIDRANGE_OP_ARGS_NONE: return;
	case PIC_MIDRANGE_OP_ARGS_2F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_2F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_7F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_7F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_1D_7F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_1D_7F_MASK_F;
		args_val->d =
			(instr & PIC_MIDRANGE_OP_ARGS_1D_7F_MASK_D) >> 7;
		return;
	case PIC_MIDRANGE_OP_ARGS_1N_6K:
		args_val->n =
			(instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_N) >> 6;
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_3B_7F:
		args_val->b =
			(instr & PIC_MIDRANGE_OP_ARGS_3B_7F_MASK_B) >> 7;
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_3B_7F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_4K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_4K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_8K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_8K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_9K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_9K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_11K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_11K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_1N_2M:
		args_val->n =
			(instr & PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_N) >> 2;
		args_val->m = instr & PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_M;
		return;
	}
}

static RzIODesc *cpu_memory_map(RzIOBind *iob, RzIODesc *desc, ut32 addr,
	ut32 size) {
	char mstr[16];
	rz_strf(mstr, "malloc://%d", size);
	if (desc && iob->fd_get_name(iob->io, desc->fd)) {
		iob->fd_remap(iob->io, desc->fd, addr);
	} else {
		desc = iob->open_at(iob->io, mstr, RZ_PERM_RW, 0, addr, NULL);
	}
	return desc;
}

static bool pic_midrange_reg_write(RzReg *reg, const char *regname, ut32 num) {
	if (reg) {
		RzRegItem *item = rz_reg_get(reg, regname, RZ_REG_TYPE_GPR);
		if (item) {
			rz_reg_set_value(reg, item, num);
			return true;
		}
	}
	return false;
}

typedef struct {
	RzIODesc *mem_sram;
	RzIODesc *mem_stack;
	bool init_done;
} PicContext;

#include "../arch/pic/pic_midrange_analysis.inc"
#include "../arch/pic/pic18_analysis.inc"

static bool pic_init(void **user) {
	PicContext *ctx = RZ_NEW0(PicContext);
	if (!ctx) {
		return false;
	}
	ctx->init_done = false;
	*user = ctx;
	return true;
}

static bool pic_fini(void *user) {
	PicContext *ctx = (PicContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

static int analysis_pic_op(
	RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (analysis->cpu && strcasecmp(analysis->cpu, "baseline") == 0) {
		// TODO: implement
		return -1;
	}
	if (analysis->cpu && strcasecmp(analysis->cpu, "midrange") == 0) {
		return analysis_pic_midrange_op(analysis, op, addr, buf, len, mask);
	}
	if (analysis->cpu && strcasecmp(analysis->cpu, "pic18") == 0) {
		return analysis_pic_pic18_op(analysis, op, addr, buf, len, mask);
	}
	return -1;
}

static char *analysis_pic_get_reg_profile(RzAnalysis *analysis) {
	if (analysis->cpu && strcasecmp(analysis->cpu, "baseline") == 0) {
		// TODO: We are using the midrange profile as the baseline
		return analysis_pic_midrange_get_reg_profile(analysis);
	}
	if (analysis->cpu && strcasecmp(analysis->cpu, "midrange") == 0) {
		return analysis_pic_midrange_get_reg_profile(analysis);
	}
	if (analysis->cpu && strcasecmp(analysis->cpu, "pic18") == 0) {
		return analysis_pic_pic18_get_reg_profile(analysis);
	}
	return NULL;
}

RzAnalysisPlugin rz_analysis_plugin_pic = {
	.name = "pic",
	.desc = "PIC analysis plugin",
	.license = "LGPL3",
	.arch = "pic",
	.bits = 8,
	.op = &analysis_pic_op,
	.init = pic_init,
	.fini = pic_fini,
	.get_reg_profile = &analysis_pic_get_reg_profile,
	.esil = true
};
