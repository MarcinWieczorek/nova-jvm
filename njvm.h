#pragma once
#include <assert.h>

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
    uint32_t lv_long[4];
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

void njvm_object_free(struct njvm_object *o) {

}

void njvm_field_free(struct njvm_field *field) {
    free(field->attributes);
}

void njvm_method_free(struct njvm_method *method) {
    free(method->code);
}

void njvm_class_free(struct njvm_class *cls) {
    free(cls->constant_pool);
    for(int i = 0; i < cls->field_count; i++) {
        njvm_field_free(cls->fields + i);
    }
    free(cls->fields);

    for(int i = 0; i < cls->method_count; i++) {
        njvm_method_free(cls->methods + i);
    }
    free(cls->methods);
}

void njvm_jre_free(struct njvm_jre *jre) {
    for(int i = 0; i < jre->cls_count; i++) {
        njvm_class_free(jre->clss[i]);
    }
}

struct njvm_constpool_entry *njvm_constpool_get(struct njvm_class *cls, uint32_t index) {
    if(index >= cls->constant_pool_count) {
        return NULL;
    }

    return cls->constant_pool + index - 1;
}

int njvm_constpool_load(struct njvm_class *cls, uint32_t index, uint8_t *data) {
    struct njvm_constpool_entry *e = njvm_constpool_get(cls, index);
    e->tag = data[0];
    uint8_t tag = data[0];
    size_t offset = 1;
    DPF(" [%-2d] CP Tag: %-2d - ", index, tag);
    /* DPF("  Additional size: %d\n", constant_pool_size[tag]); */
    uint32_t data_start = 0;
    e->size = -1;

    if(tag == 1) {
        data_start = 3;
        short str_len = htobe16(*((unsigned short *) (data+offset)));
        offset += constant_pool_size[tag];
        // DPF("  String len = %d\n", str_len);
        DPF("utf8: ");
        for(int j = 0; j < str_len; j++) {
            offset++;
            DPF("%c", data[offset]);
        }
        offset++;
        e->size = offset - data_start;
        e->data = malloc(e->size);
        memcpy(e->data, data + data_start, e->size);
        /* d += str_len; */
    }
    else if(tag == 10) { // methodref
        // DPF("Parsing methodref\n");
        struct njvm_constpool_methodref *mref = malloc(sizeof(struct njvm_constpool_methodref));
        mref->cls = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        mref->nat = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = mref;
        DPF("MREF: #%d #%d", mref->cls, mref->nat);
    }
    else if(tag == 12) {
        struct njvm_constpool_nameandtype *nat = malloc(sizeof(*nat));
        nat->name = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        nat->type = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = nat;
        DPF("NAT:  #%d #%d", nat->name, nat->type);
    }
    else if(tag == 9) {
        struct njvm_constpool_fieldref *fref = malloc(sizeof(*fref));
        fref->cls = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        fref->nat = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = fref;
        DPF("FREF: #%d #%d", fref->cls, fref->nat);
    }
    else if(tag == 7) {
        struct njvm_constpool_classref *clsref = malloc(sizeof(*clsref));
        clsref->name = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = clsref;
        DPF("CREF: #%d", clsref->name);
    }
    else {
        offset += constant_pool_size[tag];
    }

    DPF("\n");
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
    struct njvm_object *obj = malloc(sizeof(*obj));
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
