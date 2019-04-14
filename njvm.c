#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "njvm.h"
#include "opcodes.c"

uint8_t *stack;
uint8_t stack_index;

void njvm_exec_method(void *objref, struct njvm_method *m) {
    /* unsigned char *start = d; */
    uint8_t *d = m->code;
    size_t size = m->code_len;
    struct njvm_mexec me;
    me.m = m;
    me.code = d;
    /* me.stack = malloc(24); //TODO change to max stack */
    me.eip = 0;
    me.lv_int = calloc(m->max_locals, sizeof(int));
    memset(me.lv_int, 0, m->max_locals * sizeof(int));
    char *method_name = njvm_constpool_get(m->cls, m->name_index)->data;
    DPF(" --- Executing method: %s\n", method_name);

    //load arguments
    if(strcmp(method_name, "main")) {
    /* DPF("DESCRIPTOR INDEX: %d\n", m->descriptor_index); */
    char *desc = njvm_constpool_get(m->cls, m->descriptor_index)->data;
    char *argptr = strchr(desc, ')') - 1;

    for(int i = 0; *argptr != '('; i++, argptr--) {
        me.lv_int[i] = *((unsigned int *) (stack + stack_index - 4));
        stack_index -= 4;
        /* DPF("Argument %d = %c -> %d\n", i, *argptr, me.lv_int[i]); */
    }
    }

    while(me.eip < size) {
        DPF("%02X ", me.eip);
        unsigned char opcode = me.code[me.eip];
        if(opa[opcode] != NULL) {
            DPF("OP");
        }
        else {
            DPF("NI");
        }
        DPF(" 0x%02X: %-14s", opcode, opa_names[opcode]);
        for(int ai = 0; ai < 2; ai++) {
            if(ai < opa_sizes[opcode]) {
                DPF("%02hhX ", me.code[me.eip + 1 + ai]);
            }
            else {
                DPF("   ");
            }
        }

        DPF("0=%-3d 1=%-3d 2=%-3d 3=%-3d", me.lv_int[0], me.lv_int[1], me.lv_int[2], me.lv_int[3]);
        DPF("S(%2d): ", stack_index);
        for(int si = 0; si < stack_index; si++) {
            if(si > 0 && si % 4 == 0) DPF("| ");
            DPF("%02X ", stack[si]);
        }
        DPF("\b\n");
        if(opa[opcode] != NULL) {
            opa[opcode](&me);
        }
        me.eip += opa_sizes[opcode] + 1;

        if(opcode >= 0xAC && opcode <= 0xB1) {
            break;
        }
    }

    free(me.lv_int);
    DPF(" --- Returned from: %s\n", method_name);
}

struct njvm_class *njvm_class_load(unsigned char *d, size_t size) {
    struct njvm_class *class = malloc(sizeof(struct njvm_class));
    /* unsigned char *start = d; */
    d += 8;
    class->constant_pool_count = htobe16(*((unsigned short *)d));
    class->constant_pool = calloc(class->constant_pool_count, sizeof(struct njvm_constpool_entry));
    /* DPF("CPC=%d\n", cpc); */
    d += 2;
    for(int i = 1; i <= class->constant_pool_count - 1; i++) {
        d += njvm_constpool_load(class, i, d);
    }

    // flags
    d += 8;
    /* DPF("--- OFFSET: 0x%lX\n", d - start); */
    class->field_count = htobe16(*((unsigned short *)d));
    class->fields = calloc(class->field_count, sizeof(struct njvm_field));
    d += 2;
    /* DPF("Field count: %d\n", class->field_count); */
    for(int fi = 0; fi < class->field_count; fi++) {
        struct njvm_field *f = &class->fields[fi];
        f->access_flags = htobe16(*((unsigned short *)d));
        d += 2;
        f->name_index = htobe16(*((unsigned short *)d));
        d += 2;
        f->descriptor_index = htobe16(*((unsigned short *)d));
        d += 2;
        f->attributes_count = htobe16(*((unsigned short *)d));
        d += 2;
        /* DPF("Field: ni=%d, di=%d, ac=%d\n", f->name_index, f->descriptor_index, f->attributes_count); */
    }
    class->method_count = htobe16(*((unsigned short *)d));
    d += 2;
    /* DPF("Method count: %d\n", class->method_count); */
    class->methods = calloc(class->method_count, sizeof(struct njvm_method));

    for(int mi = 0; mi < class->method_count; mi++) {
        struct njvm_method *m = class->methods + mi;
        m->cls = class;
        d += 2;
        m->name_index = htobe16(*((unsigned short *)d));
        /* DPF("--- Method: %s\n", (char *)njvm_constpool_get(class, m->name_index)->data); */
        /* DPF("--- METHOD: %d\n", mi); */
        d += 2;
        m->descriptor_index = htobe16(*((unsigned short *) d));
        d += 2;
        short attr_count = htobe16(*((unsigned short *)d));
        /* DPF("Attribute count: %d\n", attr_count); */
        d += 2;
        for(int ai = 0; ai < attr_count; ai++) {
            unsigned char *ad = d;
            /* DPF("--- OFFSET: 0x%X\n", ad - start); */
            uint16_t name_index = htobe16(*((unsigned short *) ad));
            /* DPF(" Name index = %d\n", m->name_index); */
            ad += 2;
            short attr_len = htobe32(*((unsigned int *) ad));
            /* DPF(" Length: 0x%X %d\n", attr_len, attr_len); */
            ad += 4;

            /* if(mi != 0 && name_index == attr_code_index) { //Code */
            if(njvm_constpool_strcmp(njvm_constpool_get(class, name_index), "Code")) {
                /* DPF("Found code!\n"); */
                ad += 2;
                m->max_locals = htobe16(*((unsigned short *) ad));
                /* DPF("MAX_LOCALS = %d\n", m->max_locals); */
                ad += 2;
                m->code_len = htobe32(*((unsigned int *) ad));
                ad += 4;
                m->code = malloc(m->code_len);
                memcpy(m->code, ad, m->code_len);

                /* DPF("Code len: %d 0x%X\n", code_len, code_len); */
                /* DPF("--- CODE OFFSET: 0x%X\n", ad - start); */
                /* DPF("\n\n\n\n"); */
                /* njvm_exec_method(ad, code_len); */
                /* DPF("\n\n\n\n"); */
            }
            d += attr_len + 6;
        }
    }

    return class;
}

int main(int argc, char **argv) {
    FILE *fh = fopen(argv[1], "rb");
    fseek(fh, 0, SEEK_END);
    long size = ftell(fh);
    unsigned char *buf = malloc(size);
    rewind(fh);
    fread(buf, 1, size, fh);
    stack = malloc(128);
    stack_index = 0;
	struct njvm_class *cls = njvm_class_load(buf, size);

    struct njvm_method *m = njvm_class_getmethod(cls, "main");

    if(m != NULL) {
        njvm_exec_method(NULL, m);
    }
    else {
        DPF("main not found.\n");
    }

    fclose(fh);
}
