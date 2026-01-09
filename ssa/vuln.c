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

static inline void op_handler_7(Instruction *inst __attribute__((unused)))
{
	exit(0);
}

/*
 * 代码混淆，感谢Gemini 3.0 Pro，等价于：
 * int decode_opcode(uint8_t encoded_op) {
 *     for (int i = 0; i < 8; i++) {
 *         if (opcode_map[i] == encoded_op) {
 *             return i;
 *         }
 *     }
 *     return -1;
 * }
 */

/*
 * ============================================================
 * VM 内部状态定义 (伪装)
 * ============================================================
 */
typedef struct {
	uint64_t cpu_ticks;
	uint32_t interrupt_mask;
	uint32_t pipeline_flags;
	void *fault_handler;
} VM_Internal_State;

volatile VM_Internal_State g_vm_core;

/*
 * ============================================================
 * 硬件模拟宏 (MBA 混淆)
 * ============================================================
 */
// 模拟加法: (A ^ B) + 2*(A & B)
#define _HW_ADD(x, y) (((x) ^ (y)) + 2 * ((x) & (y)))
// 模拟减法: A - B = A + (~B + 1)
#define _HW_SUB(x, y) ((x) + (~(y) + 1))
// 模拟异或: (A | B) - (A & B)
#define _HW_XOR(x, y) (((x) | (y)) - ((x) & (y)))
// 符号位提取
#define _SIGN_BIT(x) ((x) >> 31)

int decode_opcode(uint8_t encoded_op)
{
	// 伪装成中断向量表
	static void *interrupt_vector_table[] = {
		&&lbl_sys_reset, // 0: 复位
		&&lbl_irq_check, // 1: 边界检查 (Loop Condition)
		&&lbl_fetch_microcode, // 2: 取指 (Load)
		&&lbl_alu_compare, // 3: 比较 (Compare)
		&&lbl_ctx_commit, // 4: 提交 (Update)
		&&lbl_tick_update, // 5: 步进 (Increment)
		&&lbl_trap_handler, // 6: 虚假分支 (Trap)
		&&lbl_bus_error, // 7: 虚假分支 (Error)
		&&lbl_sys_return // 8: 返回
	};

	volatile int vector_idx = 0; // 对应 i
	volatile int latch_register = -1; // 对应 result

	// 初始跳转：计算 lbl_sys_reset 的索引 (0)
	// 使用 Label 地址差来混淆，让 IDA 无法静态计算
	// 逻辑： (Addr - Addr) & 0xF = 0
	uintptr_t base_offset =
		(uintptr_t) &&
		lbl_sys_reset - (uintptr_t)interrupt_vector_table[0];
	uint32_t dispatch_idx = (uint32_t)base_offset & 0xF;

	goto *interrupt_vector_table[dispatch_idx];

	/* ------------------------------------------------------ */

lbl_sys_reset:
	vector_idx = 0;
	latch_register = -1;

	// 动态计算跳转到 lbl_irq_check (1)
	{
		// 强制建立数据依赖，消除 unused variable 警告
		intptr_t diff = (intptr_t) && lbl_irq_check - (intptr_t) &&
				lbl_sys_reset;

		// 我们需要 dispatch_idx = 1
		// 构造一个恒为 0 的噪声: (diff ^ diff)
		uint32_t noise = (uint32_t)_HW_XOR(diff, diff);

		dispatch_idx = _HW_ADD(noise, 1);
	}
	goto *interrupt_vector_table[dispatch_idx];

	/* ------------------------------------------------------ */

lbl_irq_check:
	// 逻辑修正：严格的边界检查
	// if (vector_idx > 7) break;
	{
		// 使用减法宏: 7 - vector_idx
		// 当 vector_idx = 0..7 时，结果为 7..0 (正数, 符号位 0)
		// 当 vector_idx = 8 时，结果为 -1 (负数, 符号位 -1)
		int rem_cycles = _HW_SUB(7, vector_idx);
		int is_loop_active =
			_SIGN_BIT(rem_cycles); // 0 if active, -1 if done

		// 虚假分支：不透明谓词
		if ((vector_idx | 0) <
		    0) { // vector_idx 从 0 开始增加，不可能小于 0
			dispatch_idx = 7; // lbl_bus_error
			goto *interrupt_vector_table[dispatch_idx];
		}

		// 计算下一跳：
		// Active (0)  -> lbl_fetch_microcode (2)
		// Done (-1)   -> lbl_sys_return (8)
		// 公式: 2 + (is_loop_active & (8 - 2)) = 2 + (is_loop_active & 6)
		dispatch_idx = 2 + (is_loop_active & 6);
	}
	goto *interrupt_vector_table[dispatch_idx];

	/* ------------------------------------------------------ */

lbl_fetch_microcode:
	// 模拟总线读取
	{
		volatile uint8_t bus_data = opcode_map[vector_idx];

		// 比较：diff = encoded_op ^ bus_data
		int signal_diff = _HW_XOR(encoded_op, bus_data);

		// 将 diff 存入临时状态，这里利用 vector_idx 暂存（高位复用技巧）
		// 但为了简单和正确，我们直接跳到 ALU 块处理
		// 实际上我们可以把 diff 藏在 g_vm_core.pipeline_flags 里传递，增加复杂度
		g_vm_core.pipeline_flags = signal_diff;
	}

	dispatch_idx = 3; // lbl_alu_compare
	goto *interrupt_vector_table[dispatch_idx];

	/* ------------------------------------------------------ */

lbl_alu_compare : {
	// 取回 diff
	int diff = g_vm_core.pipeline_flags;

	// 构造匹配掩码：if (diff == 0) mask = -1 else mask = 0
	int zero_detect = ((diff | -diff) >> 31) + 1;
	int hit_mask = -zero_detect;

	// 逻辑修正：只记录第一次匹配 (First Match Priority)
	// 如果 latch_register 已经是 -1 以外的值，说明之前匹配过了，mask 强制置 0
	// latch_register >> 31 在 -1 时是 -1 (0xFF..), 在 >=0 时是 0
	// 我们需要：如果 latch == -1，允许更新；如果 latch >= 0，禁止更新
	int not_found_yet = latch_register >> 31;
	int effective_mask = hit_mask & not_found_yet;

	// 更新逻辑： latch = (latch & ~mask) | (vector_idx & mask)
	// 只有当 effective_mask 为 -1 时，latch 才会变成 vector_idx
	latch_register ^= (latch_register ^ vector_idx) & effective_mask;
}

	dispatch_idx = 4; // lbl_ctx_commit
	goto *interrupt_vector_table[dispatch_idx];

	/* ------------------------------------------------------ */

lbl_ctx_commit:
	// 伪装的状态提交
	g_vm_core.cpu_ticks = _HW_ADD(g_vm_core.cpu_ticks, 1);

	dispatch_idx = 5; // lbl_tick_update
	goto *interrupt_vector_table[dispatch_idx];

	/* ------------------------------------------------------ */

lbl_tick_update:
	// i++
	vector_idx = _HW_ADD(vector_idx, 1);

	dispatch_idx = 1; // 回到 Loop Check
	goto *interrupt_vector_table[dispatch_idx];

	/* ------------------------------------------------------ */

lbl_trap_handler:
	// 虚假分支：栈破坏
	{
		volatile char *stack_junk = (char *)__builtin_alloca(64);
		if (stack_junk)
			stack_junk[0] = 0xCC;
		dispatch_idx = 6; // 死循环
		goto *interrupt_vector_table[dispatch_idx];
	}

lbl_bus_error:
	return -2;

	/* ------------------------------------------------------ */

lbl_sys_return:
	return latch_register;
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