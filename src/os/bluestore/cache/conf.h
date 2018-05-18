#ifndef CONF_H
#define CONF_H

#ifdef __cplusplus
extern "C" {
#endif

struct conf_value;
struct conf_item;
struct conf_section;
struct conf;

struct conf *conf_allocate(void);
void conf_free(struct conf *cp);
int conf_read(struct conf *cp, const char *file);
struct conf_section *conf_find_section(struct conf *cp, const char *name);

struct conf_section *conf_first_section(struct conf *cp);
struct conf_section *conf_next_section(struct conf_section *sp);

bool conf_section_match_prefix(const struct conf_section *sp, const char *name_prefix);
const char *conf_section_get_name(const struct conf_section *sp);
int conf_section_get_num(const struct conf_section *sp);
char *conf_section_get_nmval(struct conf_section *sp, const char *key, int idx1, int idx2);
char *conf_section_get_nval(struct conf_section *sp, const char *key, int idx);
char *conf_section_get_val(struct conf_section *sp, const char *key);
int conf_section_get_intval(struct conf_section *sp, const char *key);
bool conf_section_get_boolval(struct conf_section *sp, const char *key, bool default_val);

#ifdef __cplusplus
}
#endif

#endif
