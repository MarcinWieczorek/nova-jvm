#pragma once
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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
    void *attributes;
    uint32_t value;
};

struct njvm_jre;

struct njvm_class {
    uint16_t this_class;
    struct njvm_jre *jre;
    uint16_t constant_pool_count;
    struct njvm_constpool_entry *constant_pool;
    uint16_t field_count;
    struct njvm_field *fields;
    uint16_t method_count;
    struct njvm_method *methods;
};


struct njvm_mexec {
    struct njvm_method *m;
    uint8_t *sp;
    uint32_t eip;
    uint8_t *code;
    uint32_t *lv_int;
};

typedef struct {
    void *first;
    uint32_t second;
} pair_t;

struct njvm_object {
    uint32_t ref;
    struct njvm_class *cls;
    pair_t *fields;
};

struct njvm_jre {
    uint32_t cls_count;
    struct njvm_class **clss;
    struct njvm_object *objects[24];
};

void njvm_exec_method(uint32_t, struct njvm_method *);

struct njvm_class *njvm_class_load(unsigned char *, size_t);

void njvm_object_free(struct njvm_object *o);

void njvm_field_free(struct njvm_field *field);

void njvm_method_free(struct njvm_method *method);

void njvm_class_free(struct njvm_class *cls);

void njvm_jre_free(struct njvm_jre *jre);

void njvm_raise(char *, ...);

struct njvm_method *njvm_class_getmethod(struct njvm_class *cls, char *name);

struct njvm_field *njvm_class_getfield(struct njvm_class *cls, char *name);

struct njvm_class *njvm_class_getclass(struct njvm_jre *jre, char *name);

struct njvm_object *njvm_class_new(struct njvm_jre *jre, struct njvm_class *cls);

