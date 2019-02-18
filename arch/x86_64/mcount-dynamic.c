#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "mcount-arch.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define PAGE_SIZE  4096
#define XRAY_SECT  "xray_instr_map"

#define CALL_INSN_SIZE  5
#define JMP_INSN_SIZE   6
#define ORIG_INSN_SIZE  32

/* target instrumentation function it needs to call */
extern void __fentry__(void);
extern void __dentry__(void);
extern void __xray_entry(void);
extern void __xray_exit(void);

struct xray_instr_map {
	unsigned long addr;
	unsigned long entry;
	unsigned long type;
	unsigned long count;
};

enum mcount_x86_dynamic_type {
	DYNAMIC_NONE,
	DYNAMIC_FENTRY,
	DYNAMIC_XRAY,
};

struct arch_dynamic_info {
	enum mcount_x86_dynamic_type	type;
	struct xray_instr_map		*xrmap;
	unsigned			xrmap_count;
};

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	unsigned char trampoline[] = { 0xff, 0x25, 0x02, 0x00, 0x00, 0x00, 0xcc, 0xcc };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	unsigned long xray_entry_addr = (unsigned long)__xray_entry;
	unsigned long xray_exit_addr = (unsigned long)__xray_exit;
	struct arch_dynamic_info *adi = mdi->arch;
	size_t trampoline_size = 16;
	void *trampoline_check;

	if (adi->type == DYNAMIC_XRAY)
		trampoline_size *= 2;

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline  = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= trampoline_size;

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += trampoline_size;
		mdi->text_size  += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n",
			mdi->trampoline);

		trampoline_check = mmap((void *)mdi->trampoline, PAGE_SIZE,
					PROT_READ | PROT_WRITE,
		     			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
					-1, 0);

		if (trampoline_check == MAP_FAILED)
			pr_err("failed to mmap trampoline for setup");
	}

	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_READ | PROT_WRITE)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	if (adi->type == DYNAMIC_XRAY) {
		/* jmpq  *0x2(%rip)     # <xray_entry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &xray_entry_addr, sizeof(xray_entry_addr));

		/* jmpq  *0x2(%rip)     # <xray_exit_addr> */
		memcpy((void *)mdi->trampoline + 16, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + 16 + sizeof(trampoline),
		       &xray_exit_addr, sizeof(xray_exit_addr));
	}
	else if (adi->type == DYNAMIC_FENTRY) {
		/* jmpq  *0x2(%rip)     # <fentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &fentry_addr, sizeof(fentry_addr));
	}
	else if (adi->type == DYNAMIC_NONE) {
#ifdef HAVE_LIBCAPSTONE
		unsigned long dentry_addr = (unsigned long)__dentry__;

		/* jmpq  *0x2(%rip)     # <dentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &dentry_addr, sizeof(dentry_addr));

		if (mdi->nr_symbols) {
			mdi->orig_insns_len = mdi->nr_symbols * ORIG_INSN_SIZE;
			mdi->orig_insns_len = ALIGN(mdi->orig_insns_len, 4096);
			mdi->orig_insns_cnt = 0;

			mdi->orig_insns = mmap(NULL, mdi->orig_insns_len,
					       PROT_READ | PROT_WRITE,
					       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (mdi->orig_insns == MAP_FAILED)
				pr_err("failed to allocate space for original insns");
		}
#endif
	}
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");

	if (mdi->orig_insns &&
	    mprotect(mdi->orig_insns, mdi->orig_insns_len, PROT_EXEC) < 0)
		pr_err("cannot setup original instructions due to protection");
}

static void read_xray_map(struct arch_dynamic_info *adi,
			  struct uftrace_elf_data *elf,
			  struct uftrace_elf_iter *iter,
			  unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;

	adi->xrmap_count = shdr->sh_size / sizeof(*adi->xrmap);
	adi->xrmap = xmalloc(adi->xrmap_count * sizeof(*adi->xrmap));

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, adi->xrmap, shdr->sh_size);

	/* handle position independent code */
	if (elf->ehdr.e_type == ET_DYN) {
		struct xray_instr_map *xrmap;
		unsigned i;

		for (i = 0; i < adi->xrmap_count; i++) {
			xrmap = &adi->xrmap[i];

			xrmap->addr  += offset;
			xrmap->entry += offset;
		}
	}
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
			     struct symtab *symtab)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct arch_dynamic_info *adi;
	const char *adi_type_names[] = { "none", "fentry", "xray" };
	unsigned char fentry_patt1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char fentry_patt2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	int num_check = 5;
	unsigned i = 0;

	adi = xzalloc(sizeof(*adi));  /* DYNAMIC_NONE */

	if (elf_init(mdi->mod_name, &elf) < 0)
		goto out;

	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (!strcmp(shstr, XRAY_SECT)) {
			adi->type = DYNAMIC_XRAY;
			read_xray_map(adi, &elf, &iter, mdi->base_addr);
			goto out;
		}
	}

	/* check first few functions have fentry signature */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = &symtab->sym[i];

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* dont' check special functions */
		if (sym->name[0] == '_')
			continue;

		/* only support calls to __fentry__ at the beginning */
		if (!memcmp((void *)sym->addr, fentry_patt1, CALL_INSN_SIZE) ||
		    !memcmp((void *)sym->addr, fentry_patt2, CALL_INSN_SIZE)) {
			adi->type = DYNAMIC_FENTRY;
			break;
		}

		if (num_check-- == 0)
			break;
	}

out:
	pr_dbg("dynamic patch type: %d (%s)\n", adi->type,
	       adi_type_names[adi->type]);

	mdi->arch = adi;
	elf_finish(&elf);
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	return mdi->trampoline - (addr + CALL_INSN_SIZE);
}

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned char nop1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char nop2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char *insn = (void *)sym->addr;
	unsigned int target_addr;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop1, sizeof(nop1)) &&  /* old pattern */
	    memcmp(insn, nop2, sizeof(nop2))) {  /* new pattern */
		pr_dbg("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_FAILED;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, sym->addr);
	if (target_addr == 0)
		return INSTRUMENT_SKIPPED;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	return INSTRUMENT_SUCCESS;
}

static int update_xray_code(struct mcount_dynamic_info *mdi, struct sym *sym,
			    struct xray_instr_map *xrmap)
{
	unsigned char entry_insn[] = { 0xeb, 0x09 };
	unsigned char exit_insn[]  = { 0xc3, 0x2e };
	unsigned char pad[] = { 0x66, 0x0f, 0x1f, 0x84, 0x00,
				0x00, 0x02, 0x00, 0x00 };
	unsigned char nop6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char nop4[] = { 0x0f, 0x1f, 0x40, 0x00 };
	unsigned int target_addr;
	unsigned char *func = (void *)xrmap->addr;
	union {
		unsigned long word;
		char bytes[8];
	} patch;

	if (memcmp(func + 2, pad, sizeof(pad)))
		return INSTRUMENT_FAILED;

	if (xrmap->type == 0) {  /* ENTRY */
		if (memcmp(func, entry_insn, sizeof(entry_insn)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline - (xrmap->addr + 5);

		memcpy(func + 5, nop6, sizeof(nop6));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe8;  /* "call" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop6, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}
	else {  /* EXIT */
		if (memcmp(func, exit_insn, sizeof(exit_insn)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline + 16 - (xrmap->addr + 5);

		memcpy(func + 5, nop4, sizeof(nop4));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe9;  /* "jmp" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop4, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}

	pr_dbg3("update function '%s' dynamically to call xray functions\n",
		sym->name);
	return INSTRUMENT_SUCCESS;
}

static int patch_xray_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned i;
	int ret = -2;
	struct arch_dynamic_info *adi = mdi->arch;
	struct xray_instr_map *xrmap;

	/* xray provides a pair of entry and exit (or more) */
	for (i = 0; i < adi->xrmap_count; i++) {
		xrmap = &adi->xrmap[i];

		if (xrmap->addr < sym->addr || xrmap->addr >= sym->addr + sym->size)
			continue;

		while ((ret = update_xray_code(mdi, sym, xrmap)) == 0) {
			if (i == adi->xrmap_count - 1)
				break;
			i++;

			if (xrmap->entry != xrmap[1].entry)
				break;
			xrmap++;
		}

		break;
	}

	return ret;
}

/*
 *  we overwrite instructions over 5bytes from start of function
 *  to call '__dentry__' that seems similar like '__fentry__'.
 *
 *  while overwriting, After adding the generated instruction which
 *  returns to the address of the original instruction end,
 *  save it in the heap.
 *
 *  for example:
 *
 *   4005f0:       31 ed                   xor     %ebp,%ebp
 *   4005f2:       49 89 d1                mov     %rdx,%r9
 *   4005f5:       5e                      pop     %rsi
 *
 *  will changed like this :
 *
 *   4005f0	call qword ptr [rip + 0x200a0a] # 0x601000
 *
 *  and keeping original instruction :
 *
 *  Original Instructions---------------
 *    f1cff0:	xor ebp, ebp
 *    f1cff2:	mov r9, rdx
 *    f1cff5:	pop rsi
 *  Generated Instruction to return-----
 *    f1cff6:	jmp qword ptr [rip]
 *    f1cffc:	QW 0x00000000004005f6
 *
 *  In the original case, address 0x601000 has a dynamic symbol
 *  start address. It is also the first element in the GOT array.
 *  while initializing the mcount library, we will replace it with
 *  the address of the function '__dentry__'. so, the changed
 *  instruction will be calling '__dentry__'.
 *
 *  '__dentry__' has a similar function like '__fentry__'.
 *  the other thing is that it returns to original instructions
 *  we keeping. it makes it possible to execute the original
 *  instructions and return to the address at the end of the original
 *  instructions. Thus, the execution will goes on.
 *
 */

/* stored original instructions */
struct address_entry {
	uintptr_t addr;
	uintptr_t saved_addr;
	struct list_head list;
};
static LIST_HEAD(address_list);

uintptr_t mcount_arch_original_code(unsigned long addr)
{
	struct address_entry* entry;
	uintptr_t patched_addr, ret_addr = 0;

	patched_addr = addr - CALL_INSN_SIZE;

	list_for_each_entry(entry, &address_list, list) {
		if (entry->addr == patched_addr) {
			ret_addr = entry->saved_addr;
			break;
		}
	}
	return ret_addr;
}

/*
 * Patch the instruction to the address as given for arguments.
 */
static unsigned char * patch_code(struct mcount_dynamic_info *mdi,
				  uintptr_t addr, uint32_t origin_code_size)
{
	unsigned char *stored_addr, *origin_code_addr;
	unsigned char call_insn[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
	unsigned char jmp_insn[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00 };
	uint32_t target_addr = get_target_addr(mdi, addr);

	/*
	 *  stored origin instruction block:
	 *  ----------------------
	 *  | [origin_code_size] |
	 *  ----------------------
	 *  | [jmpq    *0x0(rip) |
	 *  ----------------------
	 *  | [Return   address] |
	 *  ----------------------
	 */

	stored_addr = mdi->orig_insns + (mdi->orig_insns_cnt++ * ORIG_INSN_SIZE);

	/* return address */
	origin_code_addr = (void *)addr + origin_code_size;

	memcpy(stored_addr, (void *)addr, origin_code_size);
	memcpy(stored_addr + origin_code_size, jmp_insn, JMP_INSN_SIZE);
	memcpy(stored_addr + origin_code_size + JMP_INSN_SIZE,
	       &origin_code_addr, sizeof(long));

	/* patch address */
	origin_code_addr = (void *)addr;

	/* build the instrumentation instruction */
	memcpy(&call_insn[1], &target_addr, CALL_INSN_SIZE - 1);

	/*
	 * we need 5-bytes at least to instrumentation. however,
	 * if instructions is not fit 5-bytes, we will overwrite the
	 * 5-bytes and fill the remaining part of the last
	 * instruction with nop.
	 *
	 * [example]
	 * In this example, we overwrite 9-bytes to use 5-bytes.
	 *
	 * dynamic: 0x19e98b0[01]:push rbp
	 * dynamic: 0x19e98b1[03]:mov rbp, rsp
	 * dynamic: 0x19e98b4[05]:mov edi, 0x4005f4
	 *
	 * dynamic: 0x40054c[05]:call 0x400ff0
	 * dynamic: 0x400551[01]:nop
	 * dynamic: 0x400552[01]:nop
	 * dynamic: 0x400553[01]:nop
	 * dynamic: 0x400554[01]:nop
	 */
	memcpy(origin_code_addr, call_insn, CALL_INSN_SIZE);
	memset(origin_code_addr + CALL_INSN_SIZE, 0x90,  /* NOP */
	       origin_code_size - CALL_INSN_SIZE);

	return stored_addr;
}

void do_instrument(struct mcount_dynamic_info *mdi,
		   uintptr_t addr, uint32_t insn_size)
{
	struct address_entry* el;
	unsigned char *stored_code;

	stored_code = patch_code(mdi, addr, insn_size);
	if (stored_code) {
		el = xmalloc(sizeof(*el));
		el->addr = addr;
		el->saved_addr = (uintptr_t)stored_code;

		list_add_tail(&el->list, &address_list);
	}
}

/* see mcount-insn.c */
int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       uintptr_t addr, uint32_t size);

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm)
{
	int instr_size;
	const char *skip_syms[] = { "_start", "__libc_csu_init", "__libc_csu_fini", };
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(skip_syms); i++) {
		if (!strcmp(sym->name, skip_syms[i]))
			return INSTRUMENT_SKIPPED;
	}

	instr_size = disasm_check_insns(disasm, sym->addr, sym->size);
	if (instr_size < CALL_INSN_SIZE)
		return instr_size;

	pr_dbg2("%s - patch instruction, size of %d\n", sym->name, instr_size);

	do_instrument(mdi, sym->addr, instr_size);
	return INSTRUMENT_SUCCESS;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm)
{
	struct arch_dynamic_info *adi = mdi->arch;
	int result = INSTRUMENT_SKIPPED;

	switch (adi->type) {
	case DYNAMIC_XRAY:
		result = patch_xray_func(mdi, sym);
		break;

	case DYNAMIC_FENTRY:
		result = patch_fentry_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		if (sym->size >= CALL_INSN_SIZE)
			result = patch_normal_func(mdi, sym, disasm);
		break;

	default:
		break;
	}
	return result;
}
