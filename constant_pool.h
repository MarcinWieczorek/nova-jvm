#pragma once
#include "njvm.h"

char constant_pool_size[20] = {
    0,
    1, 4, 4, 8,
    8, 2, 2, 4,
    4, 4, 4, 4,
    0, 0,
    3, 4, 4, 2,
    2
};

struct njvm_constpool_entry {
    uint8_t tag;
    uint32_t size;
    void *data;
};

struct njvm_constpool_methodref {
    int cls;
    int nat;
};

struct njvm_constpool_nameandtype {
    int name;
    int type;
};

struct njvm_constpool_fieldref {
    uint16_t cls;
    uint16_t nat;
};

struct njvm_constpool_classref {
    uint16_t name;
};

int njvm_constpool_strcmp(struct njvm_constpool_entry *e, char *str) {
    // DPF("%s == %s\n", (char *) e->data, str);
    return e->tag == 1 && strncmp(e->data, str, e->size) == 0;
}

