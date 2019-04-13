#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct njvm_mexec {
    unsigned char *stack;
    unsigned char *sp;
    int eip;
    int stack_index;
    unsigned char *code;
    int lv_int[4];
    int lv_long[4];
};

char constant_pool_size[20] = {
    0,
    1, 4, 4, 8,
    8, 2, 2, 4,
    4, 4, 4, 4,
    0, 0,
    3, 4, 4, 2,
    2
};

void njvm_op_nop(struct njvm_mexec *me) {
}

void njvm_op_bipush(struct njvm_mexec *me) {
    me->stack[me->stack_index] = me->code[me->eip + 1];
    me->stack_index += 4;
}

void njvm_op_11_sipush(struct njvm_mexec *me) {
    me->stack[me->stack_index + 1] = me->code[me->eip + 1];
    me->stack[me->stack_index] = me->code[me->eip + 2];
    me->stack_index += 4;
}

void njvm_internal_istore(struct njvm_mexec *me, int i) {
    me->lv_int[i] = *((unsigned int *) me->stack + me->stack_index - 4);
    me->stack_index -= 4;
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

void njvm_op_1B_iload_1(struct njvm_mexec *me) {
    ((unsigned int *) me->stack)[me->stack_index] = me->lv_int[1];
    me->stack_index += 4;
}

void njvm_op_1C_iload_2(struct njvm_mexec *me) {
    /* printf("LVINT2 was: %d\n", me->lv_int[2]); */
    /* ((unsigned int *) me->stack)[me->stack_index] = me->lv_int[2]; */
    memcpy(me->stack + me->stack_index, &me->lv_int[2], 4);
    me->stack_index += 4;
}

void njvm_op_60_iadd(struct njvm_mexec *me) {
    int a, b;
    memcpy(&a, me->stack + me->stack_index - 4, 4);
    memcpy(&b, me->stack + me->stack_index - 8, 4);
    b += a;
    memcpy(me->stack + me->stack_index - 8, &b, 4);
    me->stack_index -= 4;
}

void (*opa[256])(struct njvm_mexec *) = {
    [0 ... 255] = NULL,
    [0] = &njvm_op_nop,
    [0x10] = &njvm_op_bipush,
    [0x11] = &njvm_op_11_sipush,
    [0x1B] = &njvm_op_1B_iload_1,
    [0x1C] = &njvm_op_1C_iload_2,
    [0x3C] = &njvm_op_3C_istore_1,
    [0x3D] = &njvm_op_3D_istore_2,
    [0x3E] = &njvm_op_3E_istore_3,
    [0x60] = &njvm_op_60_iadd,
};

int opa_sizes[256] = {
    [0x00 ... 0x0F] = 0,
    1, 2, 1, 2, 2, 1, 1, 1, 1, 1,
    [0x1A ... 0x35] = 0,
};

char *opa_names[256] = {
    "nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4", "iconst_5", "lconst_0", "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0", "dconst_1", "bipush", "sipush", "ldc", "ldc_w", "ldc2_w", "iload", "lload", "fload", "dload", "aload", "iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1", "lload_2", "lload_3", "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1", "dload_2", "dload_3", "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload", "istore", "lstore", "fstore", "dstore", "astore", "istore_0", "istore_1", "istore_2", "istore_3", "lstore_0", "lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1", "fstore_2", "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3", "astore_0", "astore_1", "astore_2", "astore_3", "iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore", "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap", "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub", "imul", "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv", "irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg", "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land", "ior", "lor", "ixor", "lxor", "iinc", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l", "d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg", "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr", "ret", "tableswitch", "lookupswitch", "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return", "getstatic", "putstatic", "getfield", "putfield", "invokevirtual", "invokespecial", "invokestatic", "invokeinterface", "invokedynamic", "new", "newarray", "anewarray", "arraylength", "athrow", "checkcast", "instanceof", "monitorenter", "monitorexit", "wide", "multianewarray", "ifnull", "ifnonnull", "goto_w", "jsr_w", "breakpoint", "(no name)", "impdep1", "impdep2"
};

void njvm_exec_method(unsigned char *d, size_t size) {
    unsigned char *start = d;
    struct njvm_mexec me;
    me.code = d;
    me.stack = malloc(24);
    me.stack_index = 0;
    me.eip = 0;
    printf("Executing code at pointer: %p\n", d);

    while(me.eip < size) {
        unsigned char opcode = me.code[me.eip];
        if(opa[opcode] != NULL) {
            printf("OP 0x%X: %-10s", opcode, opa_names[opcode]);
            opa[opcode](&me);
        }
        else {
            printf("NI 0x%X: %-10s", opcode, opa_names[opcode]);
        }
        me.eip += opa_sizes[opcode] + 1;

        printf("  Stack(%2d): ", me.stack_index);
        for(int si = 0; si < me.stack_index; si++) {
            if(si > 0 && si % 4 == 0) printf("| ");
            printf("%02X ", me.stack[si]);
        }
        printf("\b\n");
    }

    puts("Execution completed");
}

void njvm_exec_class(unsigned char *d, size_t size) {
    unsigned char *start = d;
    d += 8;
    short cpc = htobe16(*((unsigned short *)d));
    /* printf("CPC=%d\n", cpc); */
    int attr_code_index = -1;
    d += 2;
    for(int i = 1; i <= cpc - 1; i++) {
        char tag = *d;
        /* printf(" [%d] CP Tag: %2d at 0x%X\n", i, tag, d - start); */
        d++;
        /* printf("  Additional size: %d\n", constant_pool_size[tag]); */

        if(tag == 1) {
            short str_len = htobe16(*((unsigned short *)d));
            d += constant_pool_size[tag];
            /* printf("  String len = %d\n", str_len); */
            /* printf("  STRING:          "); */
            if(strncmp("Code", d + 1, str_len) == 0) {
                attr_code_index = i;
            }
            for(int j = 0; j < str_len; j++) {
                d++;
                /* printf("%c", *d); */
            }
            /* printf("\n"); */
            d++;
            /* d += str_len; */
        }
        else {
            d += constant_pool_size[tag];
        }
    }

    // flags
    d += 8 + 2;
    /* printf("--- OFFSET: 0x%X\n", d - start); */
    short method_count = htobe16(*((unsigned short *)d));
    d += 2;
    /* printf("Method count: %d\n", method_count); */

    for(int mi = 0; mi < method_count; mi++) {
        /* printf("--- METHOD: %d\n", mi); */
        d += 6;
        short attr_count = htobe16(*((unsigned short *)d));
        /* printf("Attribute count: %d\n", attr_count); */
        d += 2;
        for(int ai = 0; ai < attr_count; ai++) {
            unsigned char *ad = d;
            /* printf("--- OFFSET: 0x%X\n", ad - start); */
            short name_index = htobe16(*((unsigned short *) ad));
            /* printf(" Name index = %d\n", name_index); */
            ad += 2;
            short attr_len = htobe32(*((unsigned int *) ad));
            /* printf(" Length: 0x%X %d\n", attr_len, attr_len); */
            ad += 4;

            if(mi != 0 && name_index == attr_code_index) { //Code
                ad += 2 + 2;
                short code_len = htobe32(*((unsigned int *) ad));
                ad += 4;
                /* printf("Code len: %d 0x%X\n", code_len, code_len); */
                /* printf("--- CODE OFFSET: 0x%X\n", ad - start); */
                /* printf("\n\n\n\n"); */
                njvm_exec_method(ad, code_len);
                /* printf("\n\n\n\n"); */
            }
            d += attr_len + 6;
        }
    }
}

int main(int argc, char **argv) {
    FILE *fh = fopen(argv[1], "rb");
    fseek(fh, 0, SEEK_END);
    long size = ftell(fh);
    unsigned char *buf = malloc(size);
    rewind(fh);
    fread(buf, 1, size, fh);
    njvm_exec_class(buf, size);
    fclose(fh);
}
