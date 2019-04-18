#pragma once
#include <stdint.h>

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

struct njvm_jre;

int njvm_constpool_strcmp(struct njvm_constpool_entry *, char *str);

void njvm_constpool_free(struct njvm_constpool_entry *);

struct njvm_class;
int njvm_constpool_load(struct njvm_class *cls, uint32_t index, uint8_t *data);

struct njvm_constpool_entry *njvm_constpool_get(struct njvm_class *cls, uint32_t index);

char *njvm_cpget_utf8(struct njvm_jre *, int index);

struct njvm_class *njvm_cpget_class(struct njvm_jre *, uint32_t index);

struct njvm_method *njvm_cpget_method(struct njvm_jre *, uint32_t index);

struct njvm_field *njvm_cpget_field(struct njvm_jre *, uint32_t index);

