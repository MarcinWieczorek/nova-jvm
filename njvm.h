#pragma once

#define DPF(fmt, ...) \
    do { \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
    } while(0)

#include "constant_pool.h"

struct njvm_class;

struct njvm_method {
    struct njvm_class *cls;
    uint16_t max_locals;
    uint16_t name_index;
    uint16_t descriptor_index;
    uint32_t code_len;
    uint8_t *code;
};

struct njvm_field {
    struct njvm_class *cls;
    uint16_t access_flags;
    uint16_t name_index;
    uint16_t descriptor_index;
    uint16_t attributes_count;
    uint32_t value;
    void *attributes;
};

struct njvm_class {
    uint16_t constant_pool_count;
    struct njvm_constpool_entry *constant_pool;
    uint16_t field_count;
    struct njvm_field *fields;
    uint16_t method_count;
    struct njvm_method *methods;
};

struct njvm_mexec {
    struct njvm_method *m;
    unsigned char *sp;
    int eip;
    unsigned char *code;
    int *lv_int;
    int lv_long[4];
};

void njvm_exec_method(void *, struct njvm_method *);

struct njvm_constpool_entry *njvm_constpool_get(struct njvm_class *cls, int index) {
    return cls->constant_pool + index - 1;
}

int njvm_constpool_load(struct njvm_class *cls, int index, uint8_t *data) {
    struct njvm_constpool_entry *e = njvm_constpool_get(cls, index);
    e->tag = data[0];
    int tag = data[0];
    size_t offset = 1;
    DPF(" [%d] CP Tag: %2d\n", index, tag);
    /* DPF("  Additional size: %d\n", constant_pool_size[tag]); */
    int data_start = 0;
    e->size = -1;

    if(tag == 1) {
        data_start = 3;
        short str_len = htobe16(*((unsigned short *) (data+offset)));
        offset += constant_pool_size[tag];
        // DPF("  String len = %d\n", str_len);
        DPF("  STRING:          ");
        for(int j = 0; j < str_len; j++) {
            offset++;
            DPF("%c", data[offset]);
        }
        DPF("\n");
        offset++;
        e->size = offset - data_start;
        e->data = malloc(e->size);
        memcpy(e->data, data + data_start, e->size);
        /* d += str_len; */
    }
    else if(tag == 10) {
        // DPF("Parsing methodref\n");
        struct njvm_constpool_methodref *mref = malloc(sizeof(struct njvm_constpool_methodref));
        mref->cls = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        mref->nat = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = mref;
    }
    else if(tag == 12) {
        struct njvm_constpool_nameandtype *nat = malloc(sizeof(*nat));
        nat->name = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        nat->type = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = nat;
    }
    else if(tag == 9) {
        struct njvm_constpool_fieldref *fref = malloc(sizeof(*fref));
        fref->cls = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        fref->nat = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = fref;
    }
    else {
        offset += constant_pool_size[tag];
    }

    return offset;
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
