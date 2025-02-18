// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015 alvarofe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// FIXME deallocate all the port when they are not longer needed

#include "xnu_debug.h"
#include "xnu_threads.h"

#if defined __i386__ || __x86_64__ // intel processors

/* Set/clear bit 8 (Trap Flag) of the EFLAGS processor control
   register to enable/disable single-step mode.
   ENABLE is a boolean, indicating whether to set (1) the Trap Flag
   or clear it (0).  */

RZ_IPI bool xnu_modify_trace_bit(RzDebug *dbg, xnu_thread_t *th, int enable) {
	rz_return_val_if_fail(dbg && dbg->plugin_data, false);
	RzXnuDebug *ctx = dbg->plugin_data;
	RZ_REG_T *state;
	int ret;
	ret = rz_xnu_thread_get_gpr(ctx, th);
	if (!ret) {
		eprintf("error to get gpr registers in trace bit intel\n");
		return false;
	}
	state = (RZ_REG_T *)&th->gpr;
	if (state->tsh.flavor == x86_THREAD_STATE32) {
		state->uts.ts32.__eflags = (state->uts.ts32.__eflags &
						   ~0x100UL) |
			(enable ? 0x100UL : 0);
	} else if (state->tsh.flavor == x86_THREAD_STATE64) {
		state->uts.ts64.__rflags = (state->uts.ts64.__rflags &
						   ~0x100UL) |
			(enable ? 0x100UL : 0);
	} else {
		eprintf("Invalid bit size\n");
		return false;
	}
	if (!rz_xnu_thread_set_gpr(ctx, th)) {
		eprintf("error xnu_thread_set_gpr in modify_trace_bit intel\n");
		return false;
	}
	return true;
}

#elif __POWERPC__ // ppc processor
// TODO: Implement and test this for ppc too. Below is an old example for reference.
RZ_IPI bool xnu_modify_trace_bit(RzDebug *dbg, xnu_thread_t *th, int enable) {
	return false;
}
#if 0
static bool xnu_modify_trace_bit(RzDebug *dbg, xnu_thread *th, int enable) {
	return false;
	RZ_REG_T state;
	unsigned int state_count = RZ_REG_STATE_SZ;
	kern_return_t kr;
	kr = thread_get_state (th->tid, RZ_REG_STATE_T,
			(thread_state_t)&state, &state_count);
	if (kr != KERN_SUCCESS) {
		eprintf ("error modify_trace_bit\n");
		return false;
	}
	state.srr1 = (state.srr1 & ~0x400UL) | (enable ? 0x400UL : 0);
	kr = thread_set_state (th->tid, RZ_REG_STATE_T,
			(thread_state_t)&state, state_count);
	if (kr != KERN_SUCCESS) {
		eprintf ("Error to set thread state modificy_trace_bit ppc\n");
		return false;
	}
	return true;
}
#endif

#elif __arm || __arm64 || __aarch64 // arm processor

// BCR address match type
#define BCR_M_IMVA_MATCH       ((uint32_t)(0u << 21))
#define BCR_M_CONTEXT_ID_MATCH ((uint32_t)(1u << 21))
#define BCR_M_IMVA_MISMATCH    ((uint32_t)(2u << 21))
#define BCR_M_RESERVED         ((uint32_t)(3u << 21))

// Link a BVR/BCR or WVR/WCR pair to another
#define E_ENABLE_LINKING       ((uint32_t)(1u << 20))

// Byte Address Select
#define BAS_IMVA_PLUS_0        ((uint32_t)(1u << 5))
#define BAS_IMVA_PLUS_1        ((uint32_t)(1u << 6))
#define BAS_IMVA_PLUS_2        ((uint32_t)(1u << 7))
#define BAS_IMVA_PLUS_3        ((uint32_t)(1u << 8))
#define BAS_IMVA_0_1           ((uint32_t)(3u << 5))
#define BAS_IMVA_2_3           ((uint32_t)(3u << 7))
#define BAS_IMVA_ALL           ((uint32_t)(0xfu << 5))

// Break only in privileged or user mode
#define S_RSVD                 ((uint32_t)(0u << 1))
#define S_PRIV                 ((uint32_t)(1u << 1))
#define S_USER                 ((uint32_t)(2u << 1))
#define S_PRIV_USER            ((S_PRIV) | (S_USER))

#define BCR_ENABLE ((uint32_t)(1u))
#define WCR_ENABLE ((uint32_t)(1u))

// Watchpoint load/store
#define WCR_LOAD   ((uint32_t)(1u << 3))
#define WCR_STORE  ((uint32_t)(1u << 4))

// Single instruction step
// (SS bit in the MDSCR_EL1 register)
#define SS_ENABLE  ((uint32_t)(1u))

#if __arm || __arm__ || __armv7 || __armv7__
static bool is_thumb_32(ut16 op) {
	return (((op & 0xE000) == 0xE000) && (op & 0x1800));
}
#endif

RZ_IPI bool xnu_modify_trace_bit(RzDebug *dbg, xnu_thread_t *th, int enable) {
	rz_return_val_if_fail(dbg && dbg->plugin_data, false);
	RzXnuDebug *ctx = dbg->plugin_data;
	int ret = rz_xnu_thread_get_drx(ctx, th);
	if (!ret) {
		eprintf("error to get drx registers modificy_trace_bit arm\n");
		return false;
	}
#if __arm64 || __arm64__ || __aarch64 || __aarch64__
	if (th->flavor == ARM_DEBUG_STATE32) {
		arm_debug_state32_t *state = &th->debug.drx32;
		if (enable) {
			state->__mdscr_el1 = state->__mdscr_el1 | SS_ENABLE;
		} else {
			state->__mdscr_el1 = state->__mdscr_el1 & ~SS_ENABLE;
		}
	} else if (th->flavor == ARM_DEBUG_STATE64) {
		arm_debug_state64_t *state = &th->debug.drx64;
		if (enable) {
			state->__mdscr_el1 = state->__mdscr_el1 | SS_ENABLE;
		} else {
			state->__mdscr_el1 = state->__mdscr_el1 & ~SS_ENABLE;
		}
	} else
#elif __arm || __arm__ || __armv7 || __armv7__
	if (th->flavor == ARM_DEBUG_STATE) {
		int i = 0;
		arm_debug_state_t *state = &th->debug.drx;
		RZ_REG_T *regs;
		ret = rz_xnu_thread_get_gpr(dbg, th);
		if (!ret) {
			eprintf("error to get gpr register modificy_trace_bit arm\n");
			return false;
		}
		regs = (RZ_REG_T *)&th->gpr;
		if (enable) {
			static ut64 chained_address = 0; // TODO: static is bad, move this into RzXnuDebug or handle differently somehow
			RzIOBind *bio = &dbg->iob;
			// set a breakpoint that will stop when the PC doesn't
			// match the current one
			// set the current PC as the breakpoint address
			if (chained_address) {
				state->__bvr[i] = chained_address & 0xFFFFFFFCu;
				chained_address = 0;
			} else {
				state->__bvr[i] = regs->ts_32.__pc & 0xFFFFFFFCu;
			}
			state->__bcr[i] = BCR_M_IMVA_MISMATCH | // stop on
								// address
								// mismatch
				S_USER | // stop only in user mode
				BCR_ENABLE; // enable this breakpoint
			if (regs->ts_32.__cpsr & 0x20) {
				ut16 op;
				// Thumb breakpoint
				if (regs->ts_32.__pc & 2)
					state->__bcr[i] |= BAS_IMVA_2_3;
				else
					state->__bcr[i] |= BAS_IMVA_0_1;
				if (bio->read_at(bio->io, regs->ts_32.__pc, (void *)&op, 2) < 1) {
					eprintf("Failed to read opcode modify_trace_bit\n");
					return false;
				}
				if (is_thumb_32(op)) {
					chained_address = regs->ts_32.__pc + 2;
				} else {
					// Extend the number of bits to ignore for the mismatch
					state->__bcr[i] |= BAS_IMVA_ALL;
				}
			} else {
				// ARM breakpoint
				state->__bcr[i] |= BAS_IMVA_ALL; // Stop when any address bits change
			}
			// disable bits
			for (i = i + 1; i < 16; i++) {
				// Disable all others
				state->__bcr[i] = 0;
				state->__bvr[i] = 0;
			}
		} else {
			if (state->__bcr[i] & BCR_ENABLE) {
				state->__bvr[i] = 0;
				state->__bcr[i] = 0;
			}
		}
	} else
#endif
	{
		eprintf("Bad flavor modificy_trace_bit arm\n");
		return false;
	}
	// set state
	if (!rz_xnu_thread_set_drx(ctx, th)) {
		eprintf("error to set drx modificy_trace_bit arm\n");
		return false;
	}
	return true;
}

#elif __POWERPC__
// no need to do this here
static int modify_trace_bit(RzDebug *dbg, xnu_thread *th, int enable) {
	return true;
}
#else
#error "unknown architecture"
#endif

RZ_IPI bool xnu_restore_exception_ports(RzXnuDebug *ctx, int pid) {
	kern_return_t kr;
	int i;
	task_t task = pid_to_task(ctx, pid);
	if (!task)
		return false;
	for (i = 0; i < ctx->ex.count; i++) {
		kr = task_set_exception_ports(task, ctx->ex.masks[i], ctx->ex.ports[i],
			ctx->ex.behaviors[i], ctx->ex.flavors[i]);
		if (kr != KERN_SUCCESS) {
			eprintf("fail to restore exception ports\n");
			return false;
		}
	}
	kr = mach_port_deallocate(mach_task_self(), ctx->ex.exception_port);
	if (kr != KERN_SUCCESS) {
		eprintf("failed to deallocate exception port\n");
		return false;
	}
	return true;
}

// TODO review more closely we are failing here
static void encode_reply(mig_reply_error_t *reply, mach_msg_header_t *hdr, int code) {
	mach_msg_header_t *rh = &reply->Head;
	rh->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(hdr->msgh_bits), 0);
	rh->msgh_remote_port = hdr->msgh_remote_port;
	rh->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
	rh->msgh_local_port = MACH_PORT_NULL;
	rh->msgh_id = hdr->msgh_id + 100;
	reply->NDR = NDR_record;
	reply->RetCode = code;
}

static bool validate_mach_message(RzXnuDebug *ctx, int pid, exc_msg *msg) {
	kern_return_t kr;
#if __POWERPC__
	return false;
#else
	/*check if the message is for us*/
	if (msg->hdr.msgh_local_port != ctx->ex.exception_port) {
		return false;
	}
	/*gdb from apple check this so why not us*/
	if (!(msg->hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return false;
	}
	/*Mach exception we are interested*/
	// XXX for i386 this id seems to be different
	if (msg->hdr.msgh_id > 2405 || msg->hdr.msgh_id < 2401) {
		return false;
	}
	/* check descriptors.  */
	if (msg->hdr.msgh_size <
		sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) +
			2 * sizeof(mach_msg_port_descriptor_t) +
			sizeof(NDR_record_t) + sizeof(exception_type_t) +
			sizeof(mach_msg_type_number_t) +
			sizeof(mach_exception_data_t))
		return false;
	/* check data representation.  */
	if (msg->NDR.mig_vers != NDR_PROTOCOL_2_0 ||
		msg->NDR.if_vers != NDR_PROTOCOL_2_0 ||
		msg->NDR.mig_encoding != NDR_record.mig_encoding ||
		msg->NDR.int_rep != NDR_record.int_rep ||
		msg->NDR.char_rep != NDR_record.char_rep ||
		msg->NDR.float_rep != NDR_record.float_rep) {
		return false;
	}
	if (pid_to_task(ctx, pid) != msg->task.name) {
		// we receive a exception from an unknown process this could
		// happen if the child fork, as the created process will inherit
		// its exception port
		/*we got new rights to the task, get rid of it.*/
		kr = mach_port_deallocate(mach_task_self(), msg->task.name);
		if (kr != KERN_SUCCESS) {
			eprintf("validate_mach_message: failed to deallocate task port\n");
		}
		kr = mach_port_deallocate(mach_task_self(), msg->thread.name);
		if (kr != KERN_SUCCESS) {
			eprintf("validate_mach_message2: failed to deallocated task port\n");
		}
		return false;
	}
	return true;
#endif
}

static bool handle_dead_notify(RzDebug *dbg, exc_msg *msg) {
	if (msg->hdr.msgh_id == 0x48) {
		dbg->pid = -1;
		return true;
	}
	return false;
}

static int handle_exception_message(RzDebug *dbg, exc_msg *msg, int *ret_code, bool quiet_signal) {
	int ret = RZ_DEBUG_REASON_UNKNOWN;
	kern_return_t kr;
	*ret_code = KERN_SUCCESS;
	ut64 code = (ut64)msg->code[0] | ((ut64)msg->code[1] << 32);
	ut64 subcode = (ut64)msg->code[2] | ((ut64)msg->code[3] << 32);
	switch (msg->exception) {
	case EXC_BAD_ACCESS:
		ret = RZ_DEBUG_REASON_SEGFAULT;
		*ret_code = KERN_FAILURE;
		kr = task_suspend(msg->task.name);
		if (kr != KERN_SUCCESS) {
			eprintf("failed to suspend task bad access\n");
		}
		eprintf("EXC_BAD_ACCESS\n");
		break;
	case EXC_BAD_INSTRUCTION:
		ret = RZ_DEBUG_REASON_ILLEGAL;
		*ret_code = KERN_FAILURE;
		kr = task_suspend(msg->task.name);
		if (kr != KERN_SUCCESS) {
			eprintf("failed to suspend task bad instruction\n");
		}
		eprintf("EXC_BAD_INSTRUCTION\n");
		break;
	case EXC_ARITHMETIC:
		eprintf("EXC_ARITHMETIC\n");
		break;
	case EXC_EMULATION:
		eprintf("EXC_EMULATION\n");
		break;
	case EXC_SOFTWARE:
		// TODO: make these eprintfs RZ_LOG_INFO
		// Right now we can't because the default log level is < info and the info about the
		// signal is important to the user.
		if (!quiet_signal) {
			eprintf("EXC_SOFTWARE: ");
		}
		if (code == EXC_SOFT_SIGNAL) {
			// standard unix signal
			ret = RZ_DEBUG_REASON_SIGNAL;
			dbg->reason.signum = subcode;
			if (!quiet_signal) {
				eprintf(" EXC_SOFT_SIGNAL %" PFMT64u, subcode);
				const char *signame = rz_signal_to_string((int)subcode);
				if (signame) {
					eprintf(" = %s", signame);
				}
				eprintf("\n");
			}
		} else {
			eprintf("code = 0x%" PFMT64u ", subcode = 0x%" PFMT64u "\n", code, subcode);
		}
		// We want to stop and examine when getting signals
		kr = task_suspend(msg->task.name);
		if (kr != KERN_SUCCESS) {
			RZ_LOG_ERROR("Failed to suspend after EXC_SOFTWARE");
		}
		break;
	case EXC_BREAKPOINT:
		kr = task_suspend(msg->task.name);
		if (kr != KERN_SUCCESS) {
			eprintf("failed to suspend task breakpoint\n");
		}
		ret = RZ_DEBUG_REASON_BREAKPOINT;
		break;
	default:
		eprintf("UNKNOWN\n");
		break;
	}
	kr = mach_port_deallocate(mach_task_self(), msg->task.name);
	if (kr != KERN_SUCCESS) {
		eprintf("failed to deallocate task port\n");
	}
	kr = mach_port_deallocate(mach_task_self(), msg->thread.name);
	if (kr != KERN_SUCCESS) {
		eprintf("failed to deallocated task port\n");
	}
	return ret;
}

/**
 * Wait for a Mach exception, reply to it and handle it.
 *
 * \param timeout_ms if zero, wait infinitely, otherwise specifies a timeout for receiving
 * \param quiet_signal don't print when receiving a standard unix signal
 */
RZ_IPI RzDebugReasonType xnu_wait_for_exception(RzDebug *dbg, int pid, ut32 timeout_ms, bool quiet_signal) {
	rz_return_val_if_fail(dbg && dbg->plugin_data, RZ_DEBUG_REASON_ERROR);
	RzXnuDebug *ctx = dbg->plugin_data;
	kern_return_t kr;
	int ret_code;
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	mig_reply_error_t reply;
	bool ret;
	exc_msg msg = { 0 };
	if (!dbg) {
		return reason;
	}
	msg.hdr.msgh_local_port = ctx->ex.exception_port;
	msg.hdr.msgh_size = sizeof(exc_msg);
	for (;;) {
		kr = mach_msg(
			&msg.hdr,
			MACH_RCV_MSG | MACH_RCV_INTERRUPT | (timeout_ms ? MACH_RCV_TIMEOUT : 0), 0,
			sizeof(exc_msg), ctx->ex.exception_port,
			timeout_ms ? timeout_ms : MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (kr == MACH_RCV_INTERRUPTED) {
			reason = RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED;
			break;
		} else if (kr == MACH_RCV_TIMED_OUT) {
			RZ_LOG_ERROR("Waiting for Mach exception timed out");
			reason = RZ_DEBUG_REASON_UNKNOWN;
			break;
		} else if (kr != MACH_MSG_SUCCESS) {
			RZ_LOG_ERROR("message didn't succeeded\n");
			break;
		}
		ret = validate_mach_message(ctx, dbg->pid, &msg);
		if (!ret) {
			ret = handle_dead_notify(dbg, &msg);
			if (ret) {
				reason = RZ_DEBUG_REASON_DEAD;
				break;
			}
		}
		if (!ret) {
			encode_reply(&reply, &msg.hdr, KERN_FAILURE);
			kr = mach_msg(&reply.Head, MACH_SEND_MSG | MACH_SEND_INTERRUPT,
				reply.Head.msgh_size, 0,
				MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
				MACH_PORT_NULL);
			if (reply.Head.msgh_remote_port != 0 && kr != MACH_MSG_SUCCESS) {
				kr = mach_port_deallocate(mach_task_self(), reply.Head.msgh_remote_port);
				if (kr != KERN_SUCCESS) {
					eprintf("failed to deallocate reply port\n");
				}
			}
			continue;
		}

		reason = handle_exception_message(dbg, &msg, &ret_code, quiet_signal);
		encode_reply(&reply, &msg.hdr, ret_code);
		kr = mach_msg(&reply.Head, MACH_SEND_MSG | MACH_SEND_INTERRUPT,
			reply.Head.msgh_size, 0,
			MACH_PORT_NULL, 0,
			MACH_PORT_NULL);
		if (reply.Head.msgh_remote_port != 0 && kr != MACH_MSG_SUCCESS) {
			kr = mach_port_deallocate(mach_task_self(), reply.Head.msgh_remote_port);
			if (kr != KERN_SUCCESS)
				eprintf("failed to deallocate reply port\n");
		}
		break; // to avoid infinite loops
	}
	dbg->stopaddr = rz_debug_reg_get(dbg, "PC");
	return reason;
}

RZ_IPI bool xnu_create_exception_thread(RzDebug *dbg) {
#if __POWERPC__
	return false;
#else
	rz_return_val_if_fail(dbg && dbg->plugin_data, false);
	RzXnuDebug *ctx = dbg->plugin_data;
	kern_return_t kr;
	mach_port_t exception_port = MACH_PORT_NULL;
	mach_port_t req_port;
	// Got the Mach port for the current process
	mach_port_t task_self = mach_task_self();
	task_t task = pid_to_task(ctx, dbg->pid);
	if (!task) {
		eprintf("error to get task for the debuggee process"
			" xnu_start_exception_thread\n");
		return false;
	}
	if (!MACH_PORT_VALID(task_self)) {
		eprintf("error to get the task for the current process"
			" xnu_start_exception_thread\n");
		return false;
	}
	// Allocate an exception port that we will use to track our child process
	kr = mach_port_allocate(task_self, MACH_PORT_RIGHT_RECEIVE,
		&exception_port);
	RETURN_ON_MACH_ERROR("error to allocate mach_port exception\n", false);
	// Add the ability to send messages on the new exception port
	kr = mach_port_insert_right(task_self, exception_port, exception_port,
		MACH_MSG_TYPE_MAKE_SEND);
	RETURN_ON_MACH_ERROR("error to allocate insert right\n", false);
	// Atomically swap out (and save) the child process's exception ports
	// for the one we just created. We'll want to receive all exceptions.
	ctx->ex.count = (sizeof(ctx->ex.ports) / sizeof(*ctx->ex.ports));
	kr = task_swap_exception_ports(task, EXC_MASK_ALL, exception_port,
		EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE,
		ctx->ex.masks, &ctx->ex.count, ctx->ex.ports, ctx->ex.behaviors, ctx->ex.flavors);
	RETURN_ON_MACH_ERROR("failed to swap exception ports\n", false);
	// get notification when process die
	kr = mach_port_request_notification(task_self, task, MACH_NOTIFY_DEAD_NAME,
		0, exception_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &req_port);
	if (kr != KERN_SUCCESS) {
		eprintf("Termination notification request failed\n");
	}
	ctx->ex.exception_port = exception_port;
	return true;
#endif
}
