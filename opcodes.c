#include "njvm.h"

extern uint8_t stack_index;
extern uint8_t *stack;

uint32_t njvm_internal_pop(struct njvm_mexec *me) {
    if(stack_index == 0) {
        DPF("\n ---------- UNDERFLOW ---------- \n");
        return 0;
    }

    stack_index -= 4;
    return *((uint32_t *) (stack + stack_index));
}

void njvm_internal_push(struct njvm_mexec *me, uint32_t value) {
    if(stack_index >= 256) {
        DPF("\n ---------- OVERFLOW ---------- \n");
        return;
    }

    stack[stack_index] = value;
    stack_index += 4;
}

void njvm_internal_istore(struct njvm_mexec *me, int i) {
    me->lv_int[i] = njvm_internal_pop(me);
}

void njvm_internal_iload(struct njvm_mexec *me, int i) {
    memcpy(stack + stack_index, &me->lv_int[i], 4);
    /* ((unsigned int *) stack)[stack_index] = me->lv_int[1]; */
    stack_index += 4;
}

// OPCODES IMPLEMENTATION

void njvm_op_00_nop(struct njvm_mexec *me) {

}

void njvm_op_03_iconst_0(struct njvm_mexec *me) {
    njvm_internal_push(me, 0);
}

void njvm_op_04_iconst_1(struct njvm_mexec *me) {
    njvm_internal_push(me, 1);
}

void njvm_op_05_iconst_2(struct njvm_mexec *me) {
    njvm_internal_push(me, 2);
}

void njvm_op_06_iconst_3(struct njvm_mexec *me) {
    njvm_internal_push(me, 3);
}

void njvm_op_07_iconst_4(struct njvm_mexec *me) {
    njvm_internal_push(me, 4);
}

void njvm_op_08_iconst_5(struct njvm_mexec *me) {
    njvm_internal_push(me, 5);
}

void njvm_op_10_bipush(struct njvm_mexec *me) {
    njvm_internal_push(me, me->code[me->eip + 1]);
}

void njvm_op_11_sipush(struct njvm_mexec *me) {
    stack[stack_index + 1] = me->code[me->eip + 1];
    stack[stack_index] = me->code[me->eip + 2];
    stack_index += 4;
}

void njvm_op_3B_istore_0(struct njvm_mexec *me) {
    njvm_internal_istore(me, 0);
}

void njvm_op_3C_istore_1(struct njvm_mexec *me) {
    njvm_internal_istore(me, 1);
}

void njvm_op_3D_istore_2(struct njvm_mexec *me) {
    njvm_internal_istore(me, 2);
}

void njvm_op_3E_istore_3(struct njvm_mexec *me) {
    njvm_internal_istore(me, 3);
}

void njvm_op_1A_iload_0(struct njvm_mexec *me) {
    njvm_internal_iload(me, 0);
}

void njvm_op_1B_iload_1(struct njvm_mexec *me) {
    njvm_internal_iload(me, 1);
}

void njvm_op_1C_iload_2(struct njvm_mexec *me) {
    njvm_internal_iload(me, 2);
}

void njvm_op_1D_iload_3(struct njvm_mexec *me) {
    njvm_internal_iload(me, 3);
}

void njvm_op_60_iadd(struct njvm_mexec *me) {
    int a, b;
    memcpy(&a, stack + stack_index - 4, 4);
    memcpy(&b, stack + stack_index - 8, 4);
    b += a;
    memcpy(stack + stack_index - 8, &b, 4);
    stack_index -= 4;
}

void njvm_op_84_iinc(struct njvm_mexec *me) {
    me->lv_int[me->code[me->eip + 1]] += me->code[me->eip + 2];
}

void njvm_op_A2_if_icmpge(struct njvm_mexec *me) {
    uint16_t branch = htobe16(*((unsigned short *) (me->code + me->eip + 1)));
    if(njvm_internal_pop(me) <= njvm_internal_pop(me)) {
        me->eip += branch - 3;
    }
}

void njvm_op_A7_goto(struct njvm_mexec *me) {
    signed short branch = htobe16(*((short *) (me->code + me->eip + 1)));
    me->eip += branch - 3;
    /* DPF("Gotoing to %d\n", me->eip); */
}

void njvm_op_B2_getstatic(struct njvm_mexec *me) {
    uint16_t index = htobe16(*((unsigned short *) (me->code + me->eip + 1)));
    struct njvm_constpool_fieldref *fref = njvm_constpool_get(me->m->cls, index)->data;
    struct njvm_constpool_nameandtype *nat = njvm_constpool_get(me->m->cls, fref->nat)->data;
    char *field_name = njvm_constpool_get(me->m->cls, nat->name)->data;
    /* printf("field name: %s\n", field_name); */
    struct njvm_field *field = njvm_class_getfield(me->m->cls, field_name);

    if(field != NULL) {
        njvm_internal_push(me, field->value);
    }
    else {
        njvm_internal_push(me, 0); //TODO break somehow
    }
}

void njvm_op_B3_putstatic(struct njvm_mexec *me) {
    uint16_t index = htobe16(*((unsigned short *) (me->code + me->eip + 1)));
    struct njvm_constpool_fieldref *fref = njvm_constpool_get(me->m->cls, index)->data;
    struct njvm_constpool_nameandtype *nat = njvm_constpool_get(me->m->cls, fref->nat)->data;
    char *field_name = njvm_constpool_get(me->m->cls, nat->name)->data;
    /* printf("field name: %s\n", field_name); */
    struct njvm_field *field = njvm_class_getfield(me->m->cls, field_name);
    field->value = njvm_internal_pop(me);
}

void njvm_op_B6_invokevirtual(struct njvm_mexec *me) {
    uint16_t index = htobe16(*((unsigned short *) (me->code + me->eip + 1)));
    struct njvm_constpool_methodref *mref = njvm_constpool_get(me->m->cls, index)->data;
    struct njvm_constpool_nameandtype *nat = njvm_constpool_get(me->m->cls, mref->nat)->data;
    char *method_name = njvm_constpool_get(me->m->cls, nat->name)->data;
    /* printf("method name: %s\n", method_name); */

    if(strcmp(method_name, "println") == 0) {
        int val = njvm_internal_pop(me);
        DPF(" ---   OUTPUT = ");
        printf("%d\n", val);
    }

    int objref = njvm_internal_pop(me);
    struct njvm_method *method = njvm_class_getmethod(me->m->cls, method_name);
    if(method != NULL) {
        njvm_exec_method(&objref, method);
    }
}

void njvm_op_B8_invokestatic(struct njvm_mexec *me) {
    uint16_t index = htobe16(*((unsigned short *) (me->code + me->eip + 1)));
    struct njvm_constpool_methodref *mref = njvm_constpool_get(me->m->cls, index)->data;
    struct njvm_constpool_nameandtype *nat = njvm_constpool_get(me->m->cls, mref->nat)->data;
    char *method_name = njvm_constpool_get(me->m->cls, nat->name)->data;
    struct njvm_method *method = njvm_class_getmethod(me->m->cls, method_name);
    njvm_exec_method(NULL, method);
}

void (*opa[256])(struct njvm_mexec *) = {
    [0 ... 255] = NULL,
    [0x00] = &njvm_op_00_nop,
    [0x03] = &njvm_op_03_iconst_0,
    [0x04] = &njvm_op_04_iconst_1,
    [0x05] = &njvm_op_05_iconst_2,
    [0x06] = &njvm_op_06_iconst_3,
    [0x07] = &njvm_op_07_iconst_4,
    [0x08] = &njvm_op_08_iconst_5,
    [0x10] = &njvm_op_10_bipush,
    [0x11] = &njvm_op_11_sipush,
    [0x1A] = &njvm_op_1A_iload_0,
    [0x1B] = &njvm_op_1B_iload_1,
    [0x1C] = &njvm_op_1C_iload_2,
    [0x1D] = &njvm_op_1D_iload_3,
    [0x3B] = &njvm_op_3B_istore_0,
    [0x3C] = &njvm_op_3C_istore_1,
    [0x3D] = &njvm_op_3D_istore_2,
    [0x3E] = &njvm_op_3E_istore_3,
    [0x60] = &njvm_op_60_iadd,
    [0x84] = &njvm_op_84_iinc,
    [0xA2] = &njvm_op_A2_if_icmpge,
    [0xA7] = &njvm_op_A7_goto,
    [0xB2] = &njvm_op_B2_getstatic,
    [0xB3] = &njvm_op_B3_putstatic,
    [0xB6] = &njvm_op_B6_invokevirtual,
    [0xB8] = &njvm_op_B8_invokestatic,
};

int opa_sizes[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 2, 2, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 16, 8, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 4, 4, 2, 1, 2, 0, 0, 2, 2, 0, 0, 3, 3, 2, 2, 4, 4, 0, 0, 0, 0,
};

char *opa_names[256] = {
    "nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4", "iconst_5", "lconst_0", "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0", "dconst_1", "bipush", "sipush", "ldc", "ldc_w", "ldc2_w", "iload", "lload", "fload", "dload", "aload", "iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1", "lload_2", "lload_3", "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1", "dload_2", "dload_3", "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload", "istore", "lstore", "fstore", "dstore", "astore", "istore_0", "istore_1", "istore_2", "istore_3", "lstore_0", "lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1", "fstore_2", "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3", "astore_0", "astore_1", "astore_2", "astore_3", "iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore", "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap", "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub", "imul", "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv", "irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg", "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land", "ior", "lor", "ixor", "lxor", "iinc", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l", "d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg", "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr", "ret", "tableswitch", "lookupswitch", "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return", "getstatic", "putstatic", "getfield", "putfield", "invokevirtual", "invokespecial", "invokestatic", "invokeinterface", "invokedynamic", "new", "newarray", "anewarray", "arraylength", "athrow", "checkcast", "instanceof", "monitorenter", "monitorexit", "wide", "multianewarray", "ifnull", "ifnonnull", "goto_w", "jsr_w", "breakpoint", "(no name)", "impdep1", "impdep2"
};

