#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <cctype>
#include <ctime>
#include <string>
#include <algorithm>

#define MAX_VALUES 64
#define MAX_INSTRUCTIONS 128
#define MAX_LABELS 16
#define MAX_BLKS 16
#define MAX_PHI_PER_BLK 8
#define MAX_LINE 256
#define NAME_LEN 64
#define MAX_PRED 4
#define MAX_SUCC 4

// External symbols for executable boundaries
extern "C" {
extern char __executable_start;
extern char _end;
}

enum ValueType { TYPE_INT, TYPE_PTR, TYPE_FUNC };

struct SSAValue {
	ValueType type;
	union {
		int64_t int_val;
		void *ptr_val;
		void (*func_ptr)(void);
	} data;
} __attribute__((packed));

enum OpCode {
	OP_CONST,
	OP_ADD,
	OP_LOAD,
	OP_STORE,
	OP_CALL,
	OP_PRINT,
	OP_EXIT,
	OP_LABEL,
	OP_BR,
	OP_BRCOND,
	OP_RET,
	OP_PHI
};

struct Instruction {
	OpCode op;
	int dest;
	int src1;
	int src2;
	int64_t imm;
	char sarg1[NAME_LEN];
	char sarg2[NAME_LEN];
	char sarg3[NAME_LEN];
};

struct PhiEntry {
	int dest;
	int src_from_pred1;
	int src_from_pred2;
	char pred1[NAME_LEN];
	char pred2[NAME_LEN];
};

struct BasicBlk {
	char name[NAME_LEN];
	int start_pc;
	int end_pc;
	int phi_count;
	PhiEntry phis[MAX_PHI_PER_BLK];
	unsigned char visible[MAX_VALUES];
	int pred_count;
	char preds[MAX_PRED][NAME_LEN];
	int succ_count;
	char succs[MAX_SUCC][NAME_LEN];
};

struct LabelInfo {
	char name[NAME_LEN];
	int pc;
};

static int rand_slot;
static SSAValue values[MAX_VALUES];
static Instruction program[MAX_INSTRUCTIONS];
static int inst_count;
static LabelInfo labels[MAX_LABELS];
static int label_count;
static BasicBlk blks[MAX_BLKS];
static int blk_count;
static char input_buffer[MAX_LINE];
static unsigned char definedOnce[MAX_VALUES];
static uintptr_t exe_lo, exe_hi;

class SSAInterpreter {
    private:
	bool range_ok(uintptr_t a, size_t len, uintptr_t lo, uintptr_t hi)
	{
		if (len == 0)
			return false;
		if (a < lo)
			return false;
		if (a > hi)
			return false;
		if (len > static_cast<size_t>(hi - a))
			return false;
		return true;
	}

	bool in_exe(uintptr_t a, size_t len)
	{
		return range_ok(a, len, exe_lo, exe_hi);
	}

	bool in_values(uintptr_t a, size_t len)
	{
		uintptr_t lo = reinterpret_cast<uintptr_t>(&values[0]);
		uintptr_t hi = reinterpret_cast<uintptr_t>(&values[MAX_VALUES]);
		return range_ok(a, len, lo, hi);
	}

	void resetDefOnce()
	{
		std::memset(definedOnce, 0, sizeof(definedOnce));
		definedOnce[rand_slot] = 1;
	}

	void chkAndMarkDef(int id, const char *opname)
	{
		if (id < 0 || id >= MAX_VALUES) {
			std::cerr << "[!] Invalid destination id " << id
				  << " in " << opname << std::endl;
			std::exit(1);
		}
		if (definedOnce[id]) {
			std::cerr << "[!] SSA violation: values[" << id
				  << "] is defined more than once (via "
				  << opname << ")" << std::endl;
			std::exit(1);
		}
		definedOnce[id] = 1;
	}

	void fill_random(void *ptr, size_t size)
	{
		FILE *f = std::fopen("/dev/urandom", "rb");
		if (f) {
			std::fread(ptr, 1, size, f);
			std::fclose(f);
		}
	}

	void trim(char *s)
	{
		if (!s)
			return;
		char *start = s;
		while (*start &&
		       std::isspace(static_cast<unsigned char>(*start)))
			start++;
		if (start != s)
			std::memmove(s, start, std::strlen(start) + 1);
		char *end = s + std::strlen(s) - 1;
		while (end >= s &&
		       std::isspace(static_cast<unsigned char>(*end)))
			*end-- = '\0';
	}

	int findLabel(const char *name)
	{
		for (int i = 0; i < label_count; i++) {
			if (std::strncmp(labels[i].name, name, NAME_LEN) == 0)
				return labels[i].pc;
		}
		return -1;
	}

	int findBlkByLabel(const char *name)
	{
		for (int i = 0; i < blk_count; i++) {
			if (std::strncmp(blks[i].name, name, NAME_LEN) == 0)
				return i;
		}
		return -1;
	}

	int findBlkByPC(int pc)
	{
		for (int i = 0; i < blk_count; i++) {
			if (pc >= blks[i].start_pc &&
			    (blks[i].end_pc == -1 || pc <= blks[i].end_pc)) {
				return i;
			}
		}
		return -1;
	}

	int createBlk(const char *name, int pc)
	{
		if (blk_count >= MAX_BLKS) {
			std::cerr << "[!] Too many basic blks (max " << MAX_BLKS
				  << ")" << std::endl;
			std::exit(1);
		}
		BasicBlk *b = &blks[blk_count];
		std::memset(b, 0, sizeof(*b));
		std::strncpy(b->name, name, NAME_LEN - 1);
		b->name[NAME_LEN - 1] = '\0';
		b->start_pc = pc;
		b->end_pc = -1;
		b->phi_count = 0;
		std::memset(b->visible, 0, sizeof(b->visible));
		b->visible[rand_slot] = 1;
		b->pred_count = 0;
		b->succ_count = 0;
		return blk_count++;
	}

	void closeBlk(int prev_blk_idx, int end_pc)
	{
		if (prev_blk_idx >= 0 && prev_blk_idx < blk_count) {
			if (blks[prev_blk_idx].end_pc == -1) {
				blks[prev_blk_idx].end_pc = end_pc;
			}
		}
	}

	void addLabel(const char *name, int pc)
	{
		if (label_count >= MAX_LABELS) {
			std::cerr << "[!] Too many labels (max " << MAX_LABELS
				  << ")" << std::endl;
			std::exit(1);
		}
		std::strncpy(labels[label_count].name, name, NAME_LEN - 1);
		labels[label_count].name[NAME_LEN - 1] = '\0';
		labels[label_count].pc = pc;
		label_count++;
	}

	void addPhi(int blk_idx, PhiEntry *pe)
	{
		if (blk_idx < 0 || blk_idx >= blk_count) {
			std::cerr << "[!] addPhi: invalid blk index " << blk_idx
				  << std::endl;
			std::exit(1);
		}

		if (pe->dest < 0 || pe->dest >= MAX_VALUES ||
		    pe->src_from_pred1 < 0 ||
		    pe->src_from_pred1 >= MAX_VALUES ||
		    pe->src_from_pred2 < 0 ||
		    pe->src_from_pred2 >= MAX_VALUES) {
			std::cerr << "[!] Invalid PHI operands" << std::endl;
			std::exit(1);
		}

		BasicBlk *b = &blks[blk_idx];
		if (b->phi_count >= MAX_PHI_PER_BLK) {
			std::cerr << "[!] Too many PHI nodes in blk '"
				  << b->name << "' (max " << MAX_PHI_PER_BLK
				  << ")" << std::endl;
			std::exit(1);
		}
		b->phis[b->phi_count++] = *pe;
	}

	bool isTerminator(OpCode op)
	{
		return (op == OP_BR || op == OP_BRCOND || op == OP_RET ||
			op == OP_EXIT);
	}

	void buildBlks()
	{
		int current_blk = -1;

		if (inst_count > 0 && program[0].op != OP_LABEL) {
			std::cerr
				<< "[!] First instruction must be a label (no implicit entry)"
				<< std::endl;
			std::exit(1);
		}

		if (inst_count > 0 && program[0].op == OP_LABEL) {
			if (std::strncmp(program[0].sarg1, "entry", NAME_LEN) !=
			    0) {
				std::cerr << "[!] First label shouldn't be "
					  << program[0].sarg1 << std::endl;
				std::exit(1);
			}
		}

		for (int pc = 0; pc < inst_count; pc++) {
			Instruction *ins = &program[pc];
			if (ins->op == OP_LABEL) {
				closeBlk(current_blk, pc - 1);
				addLabel(ins->sarg1, pc);
				current_blk = createBlk(ins->sarg1, pc);
			} else if (ins->op == OP_PHI) {
				if (current_blk == -1) {
					std::cout
						<< "[!] PHI must appear after a label"
						<< std::endl;
					continue;
				}
				PhiEntry pe;
				std::memset(&pe, 0, sizeof(pe));
				pe.dest = ins->dest;
				pe.src_from_pred1 = ins->src1;
				pe.src_from_pred2 = ins->src2;
				std::strncpy(pe.pred1, ins->sarg1,
					     NAME_LEN - 1);
				pe.pred1[NAME_LEN - 1] = '\0';
				std::strncpy(pe.pred2, ins->sarg2,
					     NAME_LEN - 1);
				pe.pred2[NAME_LEN - 1] = '\0';
				addPhi(current_blk, &pe);
			} else if (isTerminator(ins->op)) {
				closeBlk(current_blk, pc);
				current_blk = -1;
			}
		}
		closeBlk(current_blk, inst_count - 1);

		for (int b = 0; b < blk_count; b++) {
			BasicBlk *blk = &blks[b];
			if (blk->start_pc > blk->end_pc || blk->end_pc < 0)
				continue;
			Instruction *last = &program[blk->end_pc];
			if (!isTerminator(last->op)) {
				std::cerr << "[!] Basic blk '" << blk->name
					  << "' does not end with a terminator"
					  << std::endl;
				std::exit(1);
			}
		}
	}

	void buildCFG()
	{
		for (int i = 0; i < blk_count; i++) {
			BasicBlk *b = &blks[i];
			int pc_end = b->end_pc;
			for (int pc = b->start_pc;
			     pc <= pc_end && pc < inst_count; pc++) {
				Instruction *ins = &program[pc];
				if (ins->op == OP_BR) {
					int tgt_pc = findLabel(ins->sarg1);
					int tgt_blk =
						(tgt_pc >= 0) ?
							findBlkByPC(tgt_pc) :
							-1;
					if (tgt_blk >= 0 &&
					    blks[i].succ_count < MAX_SUCC) {
						std::strncpy(
							blks[i].succs
								[blks[i].succ_count++],
							blks[tgt_blk].name,
							NAME_LEN - 1);
						blks[i].succs[blks[i].succ_count -
							      1][NAME_LEN - 1] =
							'\0';
					}
				} else if (ins->op == OP_BRCOND) {
					int tp = findLabel(ins->sarg1);
					int fp = findLabel(ins->sarg2);
					int tb = (tp >= 0) ? findBlkByPC(tp) :
							     -1;
					int fb = (fp >= 0) ? findBlkByPC(fp) :
							     -1;
					if (tb >= 0 &&
					    blks[i].succ_count < MAX_SUCC) {
						std::strncpy(
							blks[i].succs
								[blks[i].succ_count++],
							blks[tb].name,
							NAME_LEN - 1);
						blks[i].succs[blks[i].succ_count -
							      1][NAME_LEN - 1] =
							'\0';
					}
					if (fb >= 0 &&
					    blks[i].succ_count < MAX_SUCC) {
						std::strncpy(
							blks[i].succs
								[blks[i].succ_count++],
							blks[fb].name,
							NAME_LEN - 1);
						blks[i].succs[blks[i].succ_count -
							      1][NAME_LEN - 1] =
							'\0';
					}
				}
			}
		}

		for (int i = 0; i < blk_count; i++) {
			for (int s = 0; s < blks[i].succ_count; s++) {
				const char *succ_name = blks[i].succs[s];
				int sb = findBlkByLabel(succ_name);
				if (sb >= 0 && blks[sb].pred_count < MAX_PRED) {
					std::strncpy(
						blks[sb].preds
							[blks[sb].pred_count++],
						blks[i].name, NAME_LEN - 1);
					blks[sb].preds[blks[sb].pred_count - 1]
						      [NAME_LEN - 1] = '\0';
				}
			}
		}
	}

	bool isValidPred(const BasicBlk *blk, const char *name)
	{
		if (!blk || !name)
			return false;
		for (int i = 0; i < blk->pred_count; i++) {
			if (std::strncmp(blk->preds[i], name, NAME_LEN) == 0)
				return true;
		}
		return false;
	}

	void validatePhi()
	{
		for (int b = 0; b < blk_count; b++) {
			BasicBlk *blk = &blks[b];
			if (b == 0 && blk->phi_count > 0 &&
			    blk->pred_count == 0) {
				std::cerr << "[!] Entry blk '" << blk->name
					  << "' must not contain PHI nodes"
					  << std::endl;
				std::exit(1);
			}
			for (int i = 0; i < blk->phi_count; i++) {
				PhiEntry *pe = &blk->phis[i];
				if (pe->dest < 0 || pe->dest >= MAX_VALUES ||
				    pe->src_from_pred1 < 0 ||
				    pe->src_from_pred1 >= MAX_VALUES ||
				    pe->src_from_pred2 < 0 ||
				    pe->src_from_pred2 >= MAX_VALUES) {
					std::cerr
						<< "[!] PHI in blk '"
						<< blk->name
						<< "' has out-of-range slot indices"
						<< std::endl;
					std::exit(1);
				}
				bool ok1 = isValidPred(blk, pe->pred1);
				bool ok2 = isValidPred(blk, pe->pred2);
				if (!ok1 || !ok2) {
					std::cerr
						<< "[!] Invalid PHI predecessors in blk '"
						<< blk->name << "': ["
						<< pe->pred1 << "], ["
						<< pe->pred2 << "]"
						<< std::endl;
					std::exit(1);
				}
			}
		}
	}

	bool isVisible(BasicBlk *blk, int id)
	{
		if (id < 0 || id >= MAX_VALUES)
			return false;
		return blk->visible[id] != 0;
	}

	void markVisible(BasicBlk *blk, int id)
	{
		if (id >= 0 && id < MAX_VALUES)
			blk->visible[id] = 1;
	}

	void execPhi(BasicBlk *blk, const char *incoming_pred)
	{
		for (int i = 0; i < blk->phi_count; i++) {
			PhiEntry *pe = &blk->phis[i];

			if (pe->dest < 0 || pe->dest >= MAX_VALUES ||
			    pe->src_from_pred1 < 0 ||
			    pe->src_from_pred1 >= MAX_VALUES ||
			    pe->src_from_pred2 < 0 ||
			    pe->src_from_pred2 >= MAX_VALUES) {
				std::cerr << "[!] PHI in blk '" << blk->name
					  << "' has out-of-range slot indices"
					  << std::endl;
				std::abort();
			}

			int chosen = -1;
			if (incoming_pred) {
				if (std::strncmp(incoming_pred, pe->pred1,
						 NAME_LEN) == 0) {
					chosen = pe->src_from_pred1;
				} else if (std::strncmp(incoming_pred,
							pe->pred2,
							NAME_LEN) == 0) {
					chosen = pe->src_from_pred2;
				}
			}

			if (chosen < 0 || chosen >= MAX_VALUES) {
				std::cerr
					<< "[!] PHI in blk '" << blk->name
					<< "' has no incoming value for predecessor '"
					<< (incoming_pred ? incoming_pred :
							    "(null)")
					<< "'" << std::endl;
				std::abort();
			}
			if (values[chosen].type != TYPE_INT) {
				std::cerr
					<< "[!] Only int values are allowed in PHI sources"
					<< std::endl;
				std::abort();
			}

			chkAndMarkDef(pe->dest, "phi");

			std::memset(&values[pe->dest], 0, sizeof(SSAValue));
			values[pe->dest].type = TYPE_INT;
			values[pe->dest].data.int_val =
				values[chosen].data.int_val;
			markVisible(blk, pe->dest);
		}
	}

	void execInst(BasicBlk *blk, const Instruction *ins, int cur_blk)
	{
		switch (ins->op) {
		case OP_CONST:
			if (ins->dest >= 0 && ins->dest < MAX_VALUES) {
				chkAndMarkDef(ins->dest, "const");
				values[ins->dest].type = TYPE_INT;
				values[ins->dest].data.int_val = ins->imm;
				markVisible(blk, ins->dest);
			}
			break;
		case OP_ADD:
			if (ins->dest < 0 || ins->dest >= MAX_VALUES)
				break;
			if (ins->src1 < 0 || ins->src1 >= MAX_VALUES)
				break;
			if (ins->src2 < 0 || ins->src2 >= MAX_VALUES)
				break;
			if (!isVisible(blk, ins->src1) ||
			    !isVisible(blk, ins->src2))
				break;

			chkAndMarkDef(ins->dest, "add");

			if (values[ins->src1].type == TYPE_INT &&
			    values[ins->src2].type == TYPE_INT) {
				values[ins->dest].type = TYPE_INT;
				values[ins->dest].data.int_val =
					values[ins->src1].data.int_val +
					values[ins->src2].data.int_val;
			} else if (values[ins->src1].type == TYPE_PTR &&
				   values[ins->src2].type == TYPE_INT) {
				values[ins->dest].type = TYPE_PTR;
				values[ins->dest].data.ptr_val =
					static_cast<void *>(
						static_cast<char *>(
							values[ins->src1]
								.data.ptr_val) +
						values[ins->src2].data.int_val);
			}
			markVisible(blk, ins->dest);
			break;
		case OP_LOAD:
			if (ins->dest < 0 || ins->dest >= MAX_VALUES)
				break;
			if (ins->src1 < 0 || ins->src1 >= MAX_VALUES)
				break;
			if (!isVisible(blk, ins->src1))
				break;
			if (values[ins->src1].type != TYPE_PTR)
				break;
			{
				void *ptr = values[ins->src1].data.ptr_val;
				if (ptr == nullptr) {
					std::cout << "[-] LOAD err1"
						  << std::endl;
					return;
				}

				uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
				if (!in_exe(p, sizeof(int64_t))) {
					std::cerr << "[!] LOAD err2"
						  << std::endl;
					std::abort();
				}

				chkAndMarkDef(ins->dest, "load");
				values[ins->dest].type = TYPE_INT;
				values[ins->dest].data.int_val =
					*static_cast<int64_t *>(ptr);
				markVisible(blk, ins->dest);
			}
			break;
		case OP_STORE: {
			if (ins->dest < 0 || ins->dest >= MAX_VALUES)
				break;
			if (ins->src1 < 0 || ins->src1 >= MAX_VALUES)
				break;
			if (!isVisible(blk, ins->dest) ||
			    !isVisible(blk, ins->src1))
				break;
			if (values[ins->dest].type != TYPE_PTR ||
			    values[ins->src1].type != TYPE_INT)
				break;

			void *target_ptr = values[ins->dest].data.ptr_val;
			if (target_ptr == nullptr) {
				std::cout << "[-] STORE err1" << std::endl;
				return;
			}

			uintptr_t values_base =
				reinterpret_cast<uintptr_t>(&values[0]);
			uintptr_t values_limit = reinterpret_cast<uintptr_t>(
				&values[MAX_VALUES]);
			uintptr_t target_addr =
				reinterpret_cast<uintptr_t>(target_ptr);

			if (target_addr < values_base ||
			    target_addr > values_limit - sizeof(int64_t)) {
				std::cerr << "[!] STORE err2" << std::endl;
				std::abort();
			}

			size_t offset_in_array = target_addr - values_base;
			size_t slot_index = offset_in_array / sizeof(SSAValue);
			size_t offset_in_slot =
				offset_in_array % sizeof(SSAValue);

			if (offset_in_slot < sizeof(ValueType)) {
				std::cerr << "[!] STORE err3" << std::endl;
				std::abort();
			}

			uintptr_t s = target_addr;
			uintptr_t e = target_addr + sizeof(int64_t);
			uintptr_t rlo =
				reinterpret_cast<uintptr_t>(&values[rand_slot]);
			uintptr_t rhi = rlo + sizeof(SSAValue);

			if (!(e <= rlo || s >= rhi)) {
				std::cerr << "[!] STORE err4" << std::endl;
				std::abort();
			}

			size_t next_slot_offset =
				(slot_index + 1) * sizeof(SSAValue);
			size_t write_end_offset =
				offset_in_array + sizeof(int64_t);

			// [VULN] Off-by-one store to overwrite type field of next slot, '>' should be '>='
			if (write_end_offset >
			    next_slot_offset + sizeof(ValueType)) {
				std::cerr << "[!] STORE err5" << std::endl;
				std::abort();
			}

			*static_cast<int64_t *>(target_ptr) =
				values[ins->src1].data.int_val;
			break;
		}
		case OP_CALL:
			if (cur_blk == 0) {
				std::cerr << "[!] CALL err1" << std::endl;
				std::abort();
			}

			if (ins->dest >= 0 && ins->dest < MAX_VALUES) {
				if (!isVisible(blk, ins->dest))
					break;
				if (values[ins->dest].type == TYPE_FUNC &&
				    values[ins->dest].data.func_ptr) {
					void *func_ptr =
						reinterpret_cast<void *>(
							values[ins->dest]
								.data.func_ptr);
					if (func_ptr == nullptr) {
						std::cout << "[-] CALL err2"
							  << std::endl;
						return;
					}
					uintptr_t fp =
						reinterpret_cast<uintptr_t>(
							func_ptr);
					if (in_exe(fp, 1)) {
						std::cerr << "[!] CALL err3"
							  << std::endl;
						std::abort();
					}
					uint64_t arg = 0;
					if (ins->src1 >= 0 &&
					    ins->src1 < MAX_VALUES &&
					    isVisible(blk, ins->src1)) {
						SSAValue *arg_val =
							&values[ins->src1];
						if (arg_val->type == TYPE_INT)
							arg = static_cast<
								uint64_t>(
								arg_val->data
									.int_val);
						else if (arg_val->type ==
							 TYPE_PTR)
							arg = reinterpret_cast<
								uint64_t>(
								arg_val->data
									.ptr_val);
						else if (arg_val->type ==
							 TYPE_FUNC)
							arg = reinterpret_cast<
								uint64_t>(
								arg_val->data
									.func_ptr);
					}
					uintptr_t ap =
						static_cast<uintptr_t>(arg);
					if (ap != 0) {
						if (in_values(ap, 1) ||
						    in_exe(ap, 1)) {
							std::cerr
								<< "[!] CALL err4"
								<< std::endl;
							std::abort();
						}
					}
					void (*func)(uint64_t) =
						reinterpret_cast<void (*)(
							uint64_t)>(func_ptr);
					func(arg);
				}
			}
			break;
		case OP_PRINT:
			if (ins->dest >= 0 && ins->dest < MAX_VALUES) {
				if (!isVisible(blk, ins->dest)) {
					std::cout << "values[" << ins->dest
						  << "] = (invisible)"
						  << std::endl;
					break;
				}
				std::cout << "values[" << ins->dest << "] = ";
				if (values[ins->dest].type == TYPE_INT) {
					std::printf(
						"0x%lx (TYPE_INT)\n",
						static_cast<unsigned long>(
							values[ins->dest]
								.data.int_val));
				} else if (values[ins->dest].type == TYPE_PTR) {
					std::cout << "(opaque) (TYPE_PTR)"
						  << std::endl;
				} else if (values[ins->dest].type ==
					   TYPE_FUNC) {
					std::cout << "(opaque) (TYPE_FUNC)"
						  << std::endl;
				} else {
					std::cout << "(unknown)" << std::endl;
				}
			}
			break;
		default:
			break;
		}
	}

	void run()
	{
		std::cout << "[*] Building blks..." << std::endl;
		buildBlks();

		if (blk_count == 0) {
			std::cout << "[!] No blks to execute" << std::endl;
			return;
		}

		buildCFG();
		validatePhi();

		std::cout << "[*] Executing program..." << std::endl;
		int cur_blk = 0;
		const char *incoming_pred = nullptr;
		bool halted = false;

		while (!halted && cur_blk >= 0 && cur_blk < blk_count) {
			BasicBlk *blk = &blks[cur_blk];

			execPhi(blk, incoming_pred);
			incoming_pred = nullptr;

			int pc = blk->start_pc;
			bool jumped = false;

			for (; pc <= blk->end_pc && pc < inst_count; pc++) {
				Instruction *ins = &program[pc];

				if (ins->op == OP_LABEL || ins->op == OP_PHI)
					continue;

				if (ins->op == OP_BR) {
					int tgt_pc = findLabel(ins->sarg1);
					if (tgt_pc < 0) {
						std::cout
							<< "[!] Label not found: "
							<< ins->sarg1
							<< std::endl;
						halted = true;
						break;
					}
					int nxt_blk = findBlkByPC(tgt_pc);
					if (nxt_blk < 0) {
						std::cout
							<< "[!] Target blk not found"
							<< std::endl;
						halted = true;
						break;
					}
					incoming_pred = blk->name;
					cur_blk = nxt_blk;
					jumped = true;
					break;
				} else if (ins->op == OP_BRCOND) {
					int cond = 0;
					if (ins->src1 >= 0 &&
					    ins->src1 < MAX_VALUES &&
					    isVisible(blk, ins->src1) &&
					    values[ins->src1].type ==
						    TYPE_INT) {
						cond = (values[ins->src1]
								.data.int_val !=
							0);
					}
					const char *lbl = cond ? ins->sarg1 :
								 ins->sarg2;
					int tgt_pc = findLabel(lbl);
					if (tgt_pc < 0) {
						std::cout
							<< "[!] Label not found: "
							<< lbl << std::endl;
						halted = true;
						break;
					}
					int nxt_blk = findBlkByPC(tgt_pc);
					if (nxt_blk < 0) {
						std::cout
							<< "[!] Target blk not found"
							<< std::endl;
						halted = true;
						break;
					}
					incoming_pred = blk->name;
					cur_blk = nxt_blk;
					jumped = true;
					break;
				} else if (ins->op == OP_RET) {
					halted = true;
					break;
				} else if (ins->op == OP_EXIT) {
					std::exit(0);
				} else {
					execInst(blk, ins, cur_blk);
				}
			}

			if (!halted && !jumped) {
				std::cerr
					<< "[!] Unexpected fall-through at blk '"
					<< blk->name
					<< "'. This suggests blk building or terminator checking failed."
					<< std::endl;
				std::exit(1);
			}
		}

		std::cout << "[*] Program finished\n" << std::endl;
	}

	void addInst(char *line)
	{
		if (inst_count >= MAX_INSTRUCTIONS) {
			std::cout << "Program too large!" << std::endl;
			return;
		}
		Instruction inst;
		std::memset(&inst, 0, sizeof(inst));
		inst.dest = -1;
		inst.src1 = -1;
		inst.src2 = -1;
		char op[32] = { 0 };
		std::sscanf(line, "%31s", op);

		if (std::strcmp(op, "label") == 0) {
			inst.op = OP_LABEL;
			std::sscanf(line, "%*s %31s", inst.sarg1);
			trim(inst.sarg1);
		} else if (std::strcmp(op, "phi") == 0) {
			inst.op = OP_PHI;
			int d = 0, v1 = 0, v2 = 0;
			char p1[NAME_LEN] = { 0 }, p2[NAME_LEN] = { 0 };
			int matched = std::sscanf(
				line,
				"%*s %d [ %d , %31[^]] ] [ %d , %31[^]] ]", &d,
				&v1, p1, &v2, p2);
			if (matched < 5) {
				std::cout
					<< "Bad phi syntax. Expected: phi <d> [<v1>, <pred1>] [<v2>, <pred2>]"
					<< std::endl;
				return;
			}

			if (d < 0 || d >= MAX_VALUES) {
				std::cerr << "[!] Invalid PHI destination " << d
					  << " (must be 0-" << (MAX_VALUES - 1)
					  << ")" << std::endl;
				return;
			}
			if (d == rand_slot) {
				std::cerr << "[!] Cannot use slot " << rand_slot
					  << " as PHI destination (reserved)"
					  << std::endl;
				return;
			}
			if (v1 < 0 || v1 >= MAX_VALUES || v2 < 0 ||
			    v2 >= MAX_VALUES) {
				std::cerr << "[!] Invalid PHI sources"
					  << std::endl;
				return;
			}

			trim(p1);
			trim(p2);
			inst.dest = d;
			inst.src1 = v1;
			inst.src2 = v2;
			std::strncpy(inst.sarg1, p1, NAME_LEN - 1);
			std::strncpy(inst.sarg2, p2, NAME_LEN - 1);
		} else if (std::strcmp(op, "const") == 0) {
			inst.op = OP_CONST;
			int matched = std::sscanf(line, "%*s %d %ld",
						  &inst.dest, &inst.imm);
			if (matched < 2) {
				std::cout << "Bad const syntax" << std::endl;
				return;
			}
			if (inst.dest < 0 || inst.dest >= MAX_VALUES ||
			    inst.dest == rand_slot) {
				std::cerr << "[!] Invalid const destination"
					  << std::endl;
				return;
			}
		} else if (std::strcmp(op, "add") == 0) {
			inst.op = OP_ADD;
			int matched = std::sscanf(line, "%*s %d %d %d",
						  &inst.dest, &inst.src1,
						  &inst.src2);
			if (matched < 3) {
				std::cout << "Bad add syntax" << std::endl;
				return;
			}
			if (inst.dest < 0 || inst.dest >= MAX_VALUES ||
			    inst.src1 < 0 || inst.src1 >= MAX_VALUES ||
			    inst.src2 < 0 || inst.src2 >= MAX_VALUES ||
			    inst.dest == rand_slot) {
				std::cerr << "[!] Invalid add operands"
					  << std::endl;
				return;
			}
		} else if (std::strcmp(op, "load") == 0) {
			inst.op = OP_LOAD;
			int matched = std::sscanf(line, "%*s %d %d", &inst.dest,
						  &inst.src1);
			if (matched < 2 || inst.dest < 0 ||
			    inst.dest >= MAX_VALUES || inst.src1 < 0 ||
			    inst.src1 >= MAX_VALUES || inst.dest == rand_slot) {
				std::cerr << "[!] Invalid load operands"
					  << std::endl;
				return;
			}
		} else if (std::strcmp(op, "store") == 0) {
			inst.op = OP_STORE;
			int matched = std::sscanf(line, "%*s %d %d", &inst.dest,
						  &inst.src1);
			if (matched < 2 || inst.dest < 0 ||
			    inst.dest >= MAX_VALUES || inst.src1 < 0 ||
			    inst.src1 >= MAX_VALUES) {
				std::cerr << "[!] Invalid store operands"
					  << std::endl;
				return;
			}
		} else if (std::strcmp(op, "call") == 0) {
			inst.op = OP_CALL;
			int matched = std::sscanf(line, "%*s %d %d", &inst.dest,
						  &inst.src1);
			if (matched < 1 || inst.dest < 0 ||
			    inst.dest >= MAX_VALUES) {
				std::cerr << "[!] Invalid call operands"
					  << std::endl;
				return;
			}
			if (matched == 1)
				inst.src1 = -1;
		} else if (std::strcmp(op, "print") == 0) {
			inst.op = OP_PRINT;
			int matched = std::sscanf(line, "%*s %d", &inst.dest);
			if (matched < 1 || inst.dest < 0 ||
			    inst.dest >= MAX_VALUES) {
				std::cerr << "[!] Invalid print operand"
					  << std::endl;
				return;
			}
		} else if (std::strcmp(op, "br") == 0) {
			inst.op = OP_BR;
			std::sscanf(line, "%*s %31s", inst.sarg1);
			trim(inst.sarg1);
		} else if (std::strcmp(op, "brcond") == 0) {
			inst.op = OP_BRCOND;
			int matched = std::sscanf(line, "%*s %d %31s %31s",
						  &inst.src1, inst.sarg1,
						  inst.sarg2);
			if (matched < 3 || inst.src1 < 0 ||
			    inst.src1 >= MAX_VALUES) {
				std::cerr << "[!] Invalid brcond operands"
					  << std::endl;
				return;
			}
			trim(inst.sarg1);
			trim(inst.sarg2);
		} else if (std::strcmp(op, "ret") == 0) {
			inst.op = OP_RET;
		} else if (std::strcmp(op, "exit") == 0) {
			inst.op = OP_EXIT;
		} else {
			std::cout << "Unknown instruction: " << op << std::endl;
			return;
		}

		program[inst_count++] = inst;
		std::cout << "[+] Instruction " << (inst_count - 1) << " added"
			  << std::endl;
	}

	void help()
	{
		std::cout
			<< "Instructions:\n"
			<< "  label <name>                            - Define basic blk label\n"
			<< "  phi <d> [<v1>, <pred1>] [<v2>, <pred2>] - Phi node at blk entry\n"
			<< "  const <id> <value>                      - Set value to integer\n"
			<< "  add <d> <s1> <s2>                       - d = s1 + s2\n"
			<< "  load <d> <s>                            - Load from pointer\n"
			<< "  store <d> <s>                           - Store to pointer\n"
			<< "  call <id> [arg]                         - Call function pointer\n"
			<< "  print <id>                              - Print value\n"
			<< "  br <label>                              - Unconditional branch\n"
			<< "  brcond <s> <true_lbl> <false_lbl>       - Conditional branch\n"
			<< "  ret                                     - Return (stop interpreter loop)\n"
			<< "  exit                                    - Exit process\n"
			<< "  run                                     - Build blks and execute\n";
	}

    public:
	SSAInterpreter()
	{
		rand_slot = 0;
		inst_count = 0;
		label_count = 0;
		blk_count = 0;

		std::srand(std::time(nullptr));
		rand_slot = std::rand() % MAX_VALUES;

		exe_lo = reinterpret_cast<uintptr_t>(&__executable_start);
		exe_hi = reinterpret_cast<uintptr_t>(&_end);

		fill_random(values, sizeof(values));
		fill_random(program, sizeof(program));
		inst_count = 0;
		fill_random(labels, sizeof(labels));
		label_count = 0;
		fill_random(blks, sizeof(blks));
		blk_count = 0;

		values[rand_slot].type = TYPE_PTR;
		values[rand_slot].data.ptr_val = &values[0];
		resetDefOnce();
	}

	void setbufs()
	{
		std::setvbuf(stdout, nullptr, _IONBF, 0);
		std::setvbuf(stdin, nullptr, _IONBF, 0);
		std::setvbuf(stderr, nullptr, _IONBF, 0);
	}

	void mainLoop()
	{
		while (true) {
			std::cout << "> " << std::flush;
			if (!std::fgets(input_buffer, sizeof(input_buffer),
					stdin))
				break;
			input_buffer[std::strcspn(input_buffer, "\n")] = 0;

			if (std::strcmp(input_buffer, "run") == 0) {
				run();
				break;
			} else if (std::strcmp(input_buffer, "help") == 0) {
				help();
			} else if (std::strcmp(input_buffer, "exit") == 0) {
				break;
			} else if (std::strlen(input_buffer) > 0) {
				addInst(input_buffer);
			}
		}
	}
};

int main()
{
	SSAInterpreter interpreter;
	interpreter.setbufs();
	interpreter.mainLoop();
	return 0;
}