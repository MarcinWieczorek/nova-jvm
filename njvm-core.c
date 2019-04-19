#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "njvm.h"
#include "opcodes.c"

uint8_t *stack;
uint8_t stack_index;
int NJVM_RAISED = 0;

void njvm_exec_method(uint32_t st, struct njvm_method *m) {
    /* unsigned char *start = d; */
    uint8_t *d = m->code;
    size_t size = m->code_len;
    struct njvm_mexec me;
    me.m = m;
    me.code = d;
    /* me.stack = malloc(24); //TODO change to max stack */
    me.eip = 0;
    /* DPF("MAX locals: %d\n", m->max_locals); */
    me.lv_int = calloc(m->max_locals, sizeof(int));
    memset(me.lv_int, 0, m->max_locals * sizeof(int));
    char *method_name = njvm_constpool_get(m->cls, m->name_index)->data;
    assert(method_name);
    struct njvm_constpool_classref *cref = njvm_constpool_get(m->cls, m->cls->this_class)->data;
    assert(cref);
    char *class_name = njvm_constpool_get(m->cls, cref->name)->data;
    assert(class_name);
    char *desc = njvm_constpool_get(m->cls, m->descriptor_index)->data;
    assert(desc);
    DPF("\033[0;31m --- Executing method: %s.%s:%s on objref #", class_name, method_name, desc);

    //load arguments
    if(strcmp(method_name, "main")) {
    /* DPF("DESCRIPTOR INDEX: %d\n", m->descriptor_index); */
    char *argptr = strchr(desc, ')') - 1;

    for(int i = st == 0 ? 0 : 1; *argptr != '('; i++, argptr--) {
        me.lv_int[i] = *((unsigned int *) (stack + stack_index - 4));
        stack_index -= 4;
        /* DPF("Argument %d = %c -> %d\n", i, *argptr, me.lv_int[i]); */
    }
    }

    uint32_t objref = 0;
    if(st != 0) {
        objref = *((unsigned int *) (stack + stack_index - 4));
        stack_index -= 4;
        me.lv_int[0] = objref;
    }
    DPF("%d\033[0m\n", objref);

    while(me.eip < size) {
        if(NJVM_RAISED == 1) break;
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

        DPF("0=%-3d 1=%-3d 2=%-3d 3=%-3d",
                m->max_locals > 0 ? me.lv_int[0] : 0,
                m->max_locals > 1 ? me.lv_int[1] : 0,
                m->max_locals > 2 ? me.lv_int[2] : 0,
                m->max_locals > 3 ? me.lv_int[3] : 0);
        DPF(" S(%2d): ", stack_index);
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
    DPF("\033[0;31m --- Returned from: %s.%s:%s\033[0m\n", class_name, method_name, desc);
}

struct njvm_class *njvm_class_load(unsigned char *d, size_t size) {
    if(!(d[0] == 0xCA && d[1] == 0xFE && d[2] == 0xBA && d[3] == 0xBE)) {
        DPF("Invalid class signature\n");
        return NULL;
    }

    struct njvm_class *class = malloc(sizeof(struct njvm_class));
    /* unsigned char *start = d; */
    d += 8;
    class->constant_pool_count = htobe16(*((unsigned short *)d));
    /* DPF("CPC=%d\n", class->constant_pool_count); */
    class->constant_pool = calloc(class->constant_pool_count, sizeof(struct njvm_constpool_entry));
    d += 2;
    for(int i = 1; i <= class->constant_pool_count - 1; i++) {
        d += njvm_constpool_load(class, i, d);
    }

    // flags
    d += 2;
    class->this_class = htobe16(*((unsigned short *)d));
    /* DPF("This class = %d\n", class->this_class); */
    d += 6;
    /* DPF("--- OFFSET: 0x%lX\n", d - start); */
    class->field_count = htobe16(*((unsigned short *)d));
    class->fields = calloc(class->field_count, sizeof(struct njvm_field));
    d += 2;
    /* DPF("Field count: %d\n", class->field_count); */
    for(int fi = 0; fi < class->field_count; fi++) {
        struct njvm_field *f = &class->fields[fi];
        f->cls = class;
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

void njvm_object_free(struct njvm_object *o) {
    free(o->fields);
    free(o);
}

void njvm_field_free(struct njvm_field *field) {
    free(field->attributes);
}

void njvm_method_free(struct njvm_method *method) {
    free(method->code);
}

void njvm_class_free(struct njvm_class *cls) {
    for(int i = 0; i < cls->field_count; i++) {
        njvm_field_free(cls->fields + i);
    }
    free(cls->fields);

    for(int i = 0; i < cls->method_count; i++) {
        njvm_method_free(cls->methods + i);
    }
    free(cls->methods);
    for(int i = 0; i < cls->constant_pool_count; i++) {
        njvm_constpool_free(&cls->constant_pool[i]);
    }
    free(cls->constant_pool);
    free(cls);
}

void njvm_jre_free(struct njvm_jre *jre) {
    for(int i = 0; i < jre->cls_count; i++) {
        njvm_class_free(jre->clss[i]);
    }
    free(jre->clss);

    for(int i = 0; i < 24; i++) {
        if(jre->objects[i] != NULL) {
            njvm_object_free(jre->objects[i]);
        }
    }
}

#include <stdarg.h>
void njvm_raise(char *fmt, ...) {
    NJVM_RAISED = 1;
    printf(" ---!!!--- NJVM EXCEPTION  ---!!!---\n    ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end (args);
    printf("\n ---!!!--- NJVM EXCEPTION  ---!!!---\n");
}

struct njvm_method *njvm_class_getmethod(struct njvm_class *cls, char *name) {
    for(int i = 0; i < cls->method_count; i++) {
        if(njvm_constpool_strcmp(njvm_constpool_get(cls, cls->methods[i].name_index), name)) {
            return cls->methods + i;
        }
    }

    return NULL;
}

struct njvm_field *njvm_class_getfield(struct njvm_class *cls, char *name) {
    for(int i = 0; i < cls->field_count; i++) {
        if(njvm_constpool_strcmp(njvm_constpool_get(cls, cls->fields[i].name_index), name)) {
            return cls->fields + i;
        }
    }

    return NULL;
}

struct njvm_class *njvm_class_getclass(struct njvm_jre *jre, char *name) {
    for(int i = 0; i < jre->cls_count; i++) {
        struct njvm_constpool_classref *cref = njvm_constpool_get(jre->clss[i], jre->clss[i]->this_class)->data;
        if(njvm_constpool_strcmp(njvm_constpool_get(jre->clss[i], cref->name), name)) {
            return jre->clss[i];
        }
    }

    return NULL;
}

struct njvm_object *njvm_class_new(struct njvm_jre *jre, struct njvm_class *cls) {
    assert(jre);
    assert(cls);
    struct njvm_object *obj = malloc(sizeof(*obj));

    if(obj == NULL) {
        DPF("FAILED TO ALLOCATE NEW JAVA OBJECT\n");
        return NULL;
    }

    obj->cls = cls;
    obj->fields = calloc(cls->field_count, sizeof(pair_t));

    for(int i = 0; i < cls->field_count; i++) {
        obj->fields[i].first = &cls->fields[i];
        obj->fields[i].second = 0;
    }

    for(int i = 1; i < 24; i++) {
        if(jre->objects[i] == NULL) {
            obj->ref = i;
            jre->objects[i] = obj;
            DPF("CREATED OBJECT #%d of p = %p\n", i, obj);
            break;
        }
    }

    return obj;
}
