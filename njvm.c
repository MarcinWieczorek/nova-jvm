#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "njvm.h"
#include "zip/src/zip.h"

extern uint8_t *stack, stack_index;
struct njvm_jre jre;

void load_jar(char *path) {
    int first_new_class_index = jre.cls_count;
    struct zip_t *zip = zip_open(path, ZIP_DEFAULT_COMPRESSION_LEVEL, 'r');
    int entries = zip_total_entries(zip);
    bool *to_read = malloc(sizeof(bool) * entries);
    for(int i = 0; i < entries; ++i) {
        zip_entry_openbyindex(zip, i);
        const char *name = zip_entry_name(zip);
        if(zip_entry_isdir(zip)) {
            to_read[i] = false;
            continue;
        }
        if(strcmp(name, "META-INF/MANIFEST.MF") == 0) {
            to_read[i] = false;
            continue;
        }
        to_read[i] = true;
        jre.cls_count++;
    }
    if(jre.clss == NULL) {
        jre.clss = calloc(jre.cls_count, sizeof(struct njvm_class));
    }
    else {
        jre.clss = realloc(jre.clss, jre.cls_count * sizeof(struct njvm_class));
    }
    /* DPF("Total count: %d", jre.cls_count); */
    void *buf = NULL;
    size_t buf_size;
    for(int i = 0; i < 24; i++) {
        jre.objects[i] = NULL;
    }
    int ci = first_new_class_index;
    DPF("------- %d\n", jre.cls_count);
    for(int i = 0; i < entries; ++i) {
        zip_entry_openbyindex(zip, i);
        const char *name = zip_entry_name(zip);
        DPF("Reading class %s\n", name);
        if(to_read[i] == false) {
            continue;
        }
        /* zip_entry_extract(zip, on_extract, &buf); */
        zip_entry_read(zip, &buf, &buf_size);
        struct njvm_class *cls = njvm_class_load(buf, buf_size);
        if(cls == NULL) {
            continue;
        }
        cls->jre = &jre;
        jre.clss[ci] = cls;
        ci++;
        free(buf);
    }
    free(to_read);
    zip_close(zip);
}

int main(int argc, char **argv) {
    stack = malloc(128);
    stack_index = 0;
    jre.cls_count = 0;

    if(argc > 2 && strcmp(argv[1], "jar") == 0) {
        for(int i = 2; i < argc; i++) {
            DPF("Running jar: %s\n", argv[i]);
            load_jar(argv[i]);
        }
    }
    else {
        /* struct njvm_jre jre; */
        jre.cls_count = argc - 1;
        jre.clss = calloc(jre.cls_count, sizeof(struct njvm_class));

        for(int i = 0; i < 24; i++) {
            jre.objects[i] = NULL;
        }

        for(int i = 0; i < jre.cls_count; i++) {
            DPF(" --- Loading Class: %s\n", argv[i + 1]);
            FILE *fh = fopen(argv[i + 1], "rb");
            fseek(fh, 0, SEEK_END);
            long size = ftell(fh);
            unsigned char *buf = malloc(size);
            rewind(fh);
            fread(buf, 1, size, fh);

            struct njvm_class *cls = njvm_class_load(buf, size);
            cls->jre = &jre;
            jre.clss[i] = cls;

            free(buf);
            fclose(fh);
        }
    }

    for(int i = 0; i < jre.cls_count; i++) {
        struct njvm_method *m = njvm_class_getmethod(jre.clss[i], "main");
        if(m != NULL) {
            njvm_exec_method(0, m);
            break;
        }
    }

    njvm_jre_free(&jre);
    free(stack);
    return 0;
}
