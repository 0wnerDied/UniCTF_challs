#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

#define MAX_VALUES 32
#define MAX_INSTRUCTIONS 64

typedef enum { TYPE_INT, TYPE_PTR, TYPE_FUNC } ValueType;

typedef struct {
	ValueType type;
	union {
		int64_t int_val;
		void *ptr_val;
		void (*func_ptr)(void);
	} data;
} SSAValue;

typedef struct {
	uint8_t op;
	int dest;
	int src1;
	int src2;
	int64_t imm;
} Instruction;

SSAValue values[MAX_VALUES];
Instruction program[MAX_INSTRUCTIONS];
int inst_count = 0;
char input_buffer[1024];
int rand_slot;

const uint8_t opcode_map[8] = {
	0x3A, // const
	0x7E, // add
	0x91, // phi
	0x52, // load
	0xC4, // store
	0x1B, // call
	0x68, // print
	0xAF // exit
};

const uint8_t xor_table[16] = { 0x5A, 0xA5, 0x3C, 0xC3, 0x69, 0x96, 0x1E, 0xE1,
				0x2D, 0xD2, 0x4B, 0xB4, 0x87, 0x78, 0xF0, 0x0F };

const int shift_table[8] = { 3, 7, 1, 5, 2, 6, 4, 0 };

void setbufs()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void init()
{
	srand(time(NULL));
	rand_slot = rand() % MAX_VALUES;
	if (rand_slot <= MAX_VALUES / 2) {
		rand_slot += MAX_VALUES / 2;
	}
	memset(values, 0, sizeof(values));
	memset(program, 0, sizeof(program));
	values[rand_slot].type = TYPE_PTR;
	values[rand_slot].data.ptr_val = &values[0];
}

void help()
{
	printf("Commands:\n");
	printf("  inst <opcode> [params] - Add instruction\n");
	printf("  run                    - Execute program\n");
	printf("  exit                   - Exit\n");
}

static inline void op_handler_0(Instruction *inst)
{
	if (inst->dest < 0 || inst->dest >= MAX_VALUES)
		return;
	values[inst->dest].type = TYPE_INT;
	values[inst->dest].data.int_val = inst->imm;
}

static inline void op_handler_1(Instruction *inst)
{
	if (inst->dest < 0 || inst->dest >= MAX_VALUES)
		return;
	if (inst->src1 < 0 || inst->src1 >= MAX_VALUES)
		return;
	if (inst->src2 < 0 || inst->src2 >= MAX_VALUES)
		return;
	if (values[inst->src1].type == TYPE_INT &&
	    values[inst->src2].type == TYPE_INT) {
		values[inst->dest].type = TYPE_INT;
		values[inst->dest].data.int_val =
			values[inst->src1].data.int_val +
			values[inst->src2].data.int_val;
	} else if (values[inst->src1].type == TYPE_PTR &&
		   values[inst->src2].type == TYPE_INT) {
		values[inst->dest].type = TYPE_PTR;
		values[inst->dest].data.ptr_val =
			(void *)((char *)values[inst->src1].data.ptr_val +
				 values[inst->src2].data.int_val);
	}
}

static inline void op_handler_2(Instruction *inst)
{
	if (inst->dest < 0 || inst->dest >= MAX_VALUES)
		return;
	if (inst->src1 < 0 || inst->src1 >= MAX_VALUES)
		return;
	if (inst->src2 < 0 || inst->src2 >= MAX_VALUES)
		return;

	int src = (values[inst->src1].type == TYPE_INT &&
		   values[inst->src1].data.int_val != 0) ?
			  inst->src1 :
			  inst->src2;
	memcpy(&values[inst->dest], &values[src], sizeof(SSAValue));
}

static inline void op_handler_3(Instruction *inst)
{
	if (inst->dest < 0 || inst->dest >= MAX_VALUES)
		return;
	if (inst->src1 < 0 || inst->src1 >= MAX_VALUES)
		return;
	if (values[inst->src1].type == TYPE_PTR) {
		void *ptr = values[inst->src1].data.ptr_val;
		if (ptr == NULL) {
			printf("[-] Error\n");
			return;
		}
		values[inst->dest].type = TYPE_INT;
		values[inst->dest].data.int_val = *(int64_t *)ptr;
	}
}

static inline void op_handler_4(Instruction *inst)
{
	if (inst->dest < 0 || inst->dest >= MAX_VALUES)
		return;
	if (inst->src1 < 0 || inst->src1 >= MAX_VALUES)
		return;
	// 允许任意地址写入（漏洞点）
	if (values[inst->dest].type == TYPE_PTR &&
	    values[inst->src1].type == TYPE_INT) {
		void *ptr = values[inst->dest].data.ptr_val;
		if (ptr == NULL) {
			printf("[-] Error\n");
			return;
		}
		// 直接写入 8 字节，可以修改 type 字段
		*(int64_t *)ptr = values[inst->src1].data.int_val;
	}
}

static inline void op_handler_5(Instruction *inst)
{
	if (inst->dest < 0 || inst->dest >= MAX_VALUES)
		return;
	// 严格检查 TYPE_FUNC
	if (values[inst->dest].type == TYPE_FUNC) {
		void *func_ptr = values[inst->dest].data.func_ptr;
		if (func_ptr == NULL) {
			printf("[-] Error\n");
			return;
		}
		uint64_t arg = 0;
		if (inst->src1 >= 0 && inst->src1 < MAX_VALUES) {
			if (values[inst->src1].type == TYPE_INT)
				arg = (uint64_t)values[inst->src1].data.int_val;
			else if (values[inst->src1].type == TYPE_PTR)
				arg = (uint64_t)values[inst->src1].data.ptr_val;
		}
		void (*func)(uint64_t) = (void (*)(uint64_t))func_ptr;
		func(arg);
	}
}

static inline void op_handler_6(Instruction *inst)
{
	if (inst->dest < 0 || inst->dest >= MAX_VALUES)
		return;
	printf("values[%d] = ", inst->dest);
	if (values[inst->dest].type == TYPE_INT)
		printf("0x%lx\n", values[inst->dest].data.int_val);
	else if (values[inst->dest].type == TYPE_PTR)
		printf("%p\n", values[inst->dest].data.ptr_val);
	else if (values[inst->dest].type == TYPE_FUNC)
		printf("%p\n", values[inst->dest].data.func_ptr);
}

static inline void op_handler_7()
{
	exit(0);
}

int decode_opcode(uint8_t encoded_op)
{
	uint32_t state = encoded_op;
	for (int round = 0; round < 3; round++) {
		state ^= xor_table[state & 0xF];
		state = ((state << 3) | (state >> 5)) & 0xFF;
		state += opcode_map[round % 8];
		state &= 0xFF;
	}

	int path[16];
	int path_len = 0;
	for (int i = 0; i < 8; i++) {
		int idx = shift_table[i];
		path[path_len++] = idx;

		if ((state >> i) & 1) {
			path[path_len++] = (idx + 4) % 8;
		}
	}

	int candidates[8] = { -1, -1, -1, -1, -1, -1, -1, -1 };
	int candidate_count = 0;
	int hash_sum = 0;

	for (int i = 0; i < path_len; i++) {
		int idx = path[i] % 8;
		hash_sum = (hash_sum * 31 + opcode_map[idx]) & 0xFFFF;

		if (opcode_map[idx] == encoded_op) {
			candidates[candidate_count++] = idx;
			hash_sum ^= (idx << 4);

			if (candidate_count > 1) {
				int diff = candidates[candidate_count - 1] -
					   candidates[candidate_count - 2];
				hash_sum += diff * diff;
			}
		}

		if (hash_sum > 0x1000) {
			hash_sum = (hash_sum >> 4) ^ (hash_sum & 0xF);
		}
	}

	int result = -1;
	if (candidate_count > 0) {
		int selector = hash_sum % candidate_count;
		result = candidates[selector];

		for (int i = 0; i < candidate_count; i++) {
			if (candidates[i] >= 0 && candidates[i] < 8) {
				if (opcode_map[candidates[i]] == encoded_op) {
					result = candidates[i];
					break;
				}
			}
		}
	}

	if (result >= 0) {
		int verify_hash = 0;
		for (int i = 0; i < 8; i++) {
			verify_hash ^= opcode_map[i] * (result + 1);
		}
		if ((verify_hash & 0xFF) == (hash_sum & 0xFF)) {
			result = result;
		}
	}

	return result;
}

void execInst(Instruction *inst)
{
	int real_op = decode_opcode(inst->op);

	if (real_op < 0 || real_op >= 8) {
		return;
	}

	void (*handlers[])(Instruction *) = { op_handler_0, op_handler_1,
					      op_handler_2, op_handler_3,
					      op_handler_4, op_handler_5,
					      op_handler_6, op_handler_7 };

	handlers[real_op](inst);
}

int validateInstParams(int op, int dest, int src1, int src2)
{
	switch (op) {
	case 0:
	case 6:
		if (dest < 0 || dest >= MAX_VALUES) {
			printf("[-] Invalid parameters\n");
			return 0;
		}
		break;
	case 3:
	case 4:
		if (dest < 0 || dest >= MAX_VALUES) {
			printf("[-] Invalid parameters\n");
			return 0;
		}
		if (src1 < 0 || src1 >= MAX_VALUES) {
			printf("[-] Invalid parameters\n");
			return 0;
		}
		break;
	case 1:
	case 2:
		if (dest < 0 || dest >= MAX_VALUES) {
			printf("[-] Invalid parameters\n");
			return 0;
		}
		if (src1 < 0 || src1 >= MAX_VALUES) {
			printf("[-] Invalid parameters\n");
			return 0;
		}
		if (src2 < 0 || src2 >= MAX_VALUES) {
			printf("[-] Invalid parameters\n");
			return 0;
		}
		break;
	case 5:
		if (dest < 0 || dest >= MAX_VALUES) {
			printf("[-] Invalid parameters\n");
			return 0;
		}
		if (src1 >= MAX_VALUES) {
			printf("[-] Invalid parameters\n");
			return 0;
		}
		break;
	case 7:
		break;
	default:
		printf("[-] Invalid opcode\n");
		return 0;
	}
	return 1;
}

void addInst(char *line)
{
	if (inst_count >= MAX_INSTRUCTIONS) {
		printf("[-] Program too large!\n");
		return;
	}

	Instruction inst = { 0 };
	inst.dest = -1;
	inst.src1 = -1;
	inst.src2 = -1;

	char *params = line;
	while (*params && *params != ' ')
		params++;
	while (*params && *params == ' ')
		params++;

	int opcode;
	int parsed = sscanf(params, "%d", &opcode);

	if (parsed != 1 || opcode < 0 || opcode > 255) {
		printf("[-] Invalid input\n");
		return;
	}

	uint8_t encoded_op = (uint8_t)opcode;
	int real_op = decode_opcode(encoded_op);

	if (real_op < 0) {
		printf("[-] Invalid opcode\n");
		return;
	}

	switch (real_op) {
	case 0:
		if (sscanf(params, "%d %d %ld", &opcode, &inst.dest,
			   &inst.imm) != 3) {
			printf("[-] Invalid parameters\n");
			return;
		}
		break;
	case 1:
	case 2:
		if (sscanf(params, "%d %d %d %d", &opcode, &inst.dest,
			   &inst.src1, &inst.src2) != 4) {
			printf("[-] Invalid parameters\n");
			return;
		}
		break;
	case 3:
	case 4:
	case 5:
		if (sscanf(params, "%d %d %d", &opcode, &inst.dest,
			   &inst.src1) != 3) {
			printf("[-] Invalid parameters\n");
			return;
		}
		break;
	case 6:
		if (sscanf(params, "%d %d", &opcode, &inst.dest) != 2) {
			printf("[-] Invalid parameters\n");
			return;
		}
		break;
	case 7:
		break;
	default:
		printf("[-] Invalid opcode\n");
		return;
	}

	if (!validateInstParams(real_op, inst.dest, inst.src1, inst.src2)) {
		return;
	}

	inst.op = encoded_op;
	program[inst_count++] = inst;
	printf("[+] OK\n");
}

void run()
{
	printf("[*] Running...\n");
	for (int i = 0; i < inst_count; i++) {
		execInst(&program[i]);
	}
	printf("[*] Done\n");
}

int main()
{
	setbufs();
	init();

	while (1) {
		printf("> ");
		if (!fgets(input_buffer, sizeof(input_buffer), stdin)) {
			break;
		}

		input_buffer[strcspn(input_buffer, "\n")] = 0;

		if (strcmp(input_buffer, "run") == 0) {
			run();
			break;
		} else if (strcmp(input_buffer, "help") == 0) {
			help();
		} else if (strcmp(input_buffer, "exit") == 0) {
			break;
		} else if (strcmp(input_buffer, "dbg") == 0) {
			printf("[*] rand_slot = %d\n", rand_slot);
		} else if (strncmp(input_buffer, "inst ", 5) == 0) {
			addInst(input_buffer);
		}
	}

	return 0;
}