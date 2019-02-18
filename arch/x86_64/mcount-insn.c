#include "libmcount/internal.h"
#include "mcount-arch.h"

#define CALL_INSN_SIZE  5

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &disasm->engine) != CS_ERR_OK) {
		pr_dbg("failed to init Capstone disasm engine\n");
		return;
	}

	cs_option(disasm->engine, CS_OPT_DETAIL, CS_OPT_ON);
}

void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
	cs_close(&disasm->engine);
}

/*
 * check whether the instruction can be executed regardless of its location.
 * TODO: this function does not completed, need more classify the cases.
 */
static int check_instrumentable(struct mcount_disasm_engine *disasm, cs_insn *ins)
{
	int i, n;
	cs_x86 *x86;
	cs_detail *detail;
	bool jmp_or_call = false;
	int status = CODE_PATCH_NO;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (ins->detail == NULL)
		return status;

	detail = ins->detail;

	/* print the groups this instruction belong to */
	if (detail->groups_count > 0) {
		for (n = 0; n < detail->groups_count; n++) {
			if (detail->groups[n] == X86_GRP_CALL ||
			    detail->groups[n] == X86_GRP_JUMP) {
				jmp_or_call = true;
			}
		}
	}

	x86 = &(ins->detail->x86);

	/* no operand */
	if (!x86->op_count)
		return CODE_PATCH_NO;

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
		case X86_OP_REG:
			status = CODE_PATCH_OK;
			break;
		case X86_OP_IMM:
			if (jmp_or_call)
				return CODE_PATCH_NO;
			status = CODE_PATCH_OK;
			break;
		case X86_OP_MEM:
			if (op->mem.base == X86_REG_RIP ||
			    op->mem.index == X86_REG_RIP)
				return CODE_PATCH_NO;

			status = CODE_PATCH_OK;
			break;
		default:
			break;
		}
	}
	return status;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       uintptr_t addr, uint32_t size)
{
	cs_insn *insn;
	uint32_t code_size = 0;
	uint32_t count, i;

	count = cs_disasm(disasm->engine, (void *)addr, size, addr, 0, &insn);

	for (i = 0; i < count; i++) {
		if (check_instrumentable(disasm, &insn[i]) == CODE_PATCH_NO) {
			pr_dbg3("instruction not supported: %s\t %s\n",
				insn[i].mnemonic, insn[i].op_str);
			return INSTRUMENT_FAILED;
		}

		code_size += insn[i].size;
		if (code_size >= CALL_INSN_SIZE)
			return code_size;
	}

	return INSTRUMENT_FAILED;
}

#else /* HAVE_LIBCAPSTONE */

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       uintptr_t addr, uint32_t size)
{
	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */
