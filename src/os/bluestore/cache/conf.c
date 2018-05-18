#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "conf.h"

struct conf_value {
  struct conf_value *next;
  char *value;
};

struct conf_item {
  struct conf_item *next;
  char *key;
  struct conf_value *val;
};

struct conf_section {
  struct conf_section *next;
  char *name;
  int num;
  struct conf_item *item;
};

struct conf {
  char *file;
  struct conf_section *current_section;
  struct conf_section *section;
};

#define CF_DELIM " \t"

#define LIB_MAX_TMPBUF 1024

struct conf *conf_allocate(void)
{
  return calloc(1, sizeof(struct conf));
}

static void free_conf_value(struct conf_value *vp)
{
  if (vp == NULL) {
    return;
  }

  if (vp->value) {
    free(vp->value);
  }

  free(vp);
}

static void free_all_conf_value(struct conf_value *vp)
{
  struct conf_value *next;

  if (vp == NULL) {
    return;
  }

  while (vp != NULL) {
    next = vp->next;
    free_conf_value(vp);
    vp = next;
  }
}

static void free_conf_item(struct conf_item *ip)
{
  if (ip == NULL) {
    return;
  }

  if (ip->val != NULL) {
    free_all_conf_value(ip->val);
  }

  if (ip->key != NULL) {
    free(ip->key);
  }

  free(ip);
}

static void free_all_conf_item(struct conf_item *ip)
{
  struct conf_item *next;

  if (ip == NULL) {
    return;
  }

  while (ip != NULL) {
    next = ip->next;
    free_conf_item(ip);
    ip = next;
  }
}

static void free_conf_section(struct conf_section *sp)
{
  if (sp == NULL) {
    return;
  }

  if (sp->item) {
    free_all_conf_item(sp->item);
  }

  if (sp->name) {
    free(sp->name);
  }

  free(sp);
}

static void free_all_conf_section(struct conf_section *sp)
{
  struct conf_section *next;

  if (sp == NULL) {
    return;
  }

  while (sp != NULL) {
    next = sp->next;
    free_conf_section(sp);
    sp = next;
  }
}

void conf_free(struct conf *cp)
{
  if (cp == NULL) {
    return;
  }

  if (cp->section != NULL) {
    free_all_conf_section(cp->section);
  }

  if (cp->file != NULL) {
    free(cp->file);
  }

  free(cp);
}

static struct conf_section *allocate_cf_section(void)
{
  return calloc(1, sizeof(struct conf_section));
}

static struct conf_item *allocate_cf_item(void)
{
  return calloc(1, sizeof(struct conf_item));
}

static struct conf_value *allocate_cf_value(void)
{
  return calloc(1, sizeof(struct conf_value));
}

struct conf_section *conf_find_section(struct conf *cp, const char *name)
{
  struct conf_section *sp;

  if (name == NULL || name[0] == '\0') {
    return NULL;
  }

  if (cp == NULL) {
    return NULL;
  }

  for (sp = cp->section; sp != NULL; sp = sp->next) {
    if (sp->name != NULL && sp->name[0] == name[0]
        && strcasecmp(sp->name, name) == 0) {
      return sp;
    }
  }

  return NULL;
}

struct conf_section *conf_first_section(struct conf *cp)
{
  if (cp == NULL) {
    return NULL;
  }

  return cp->section;
}

struct conf_section *conf_next_section(struct conf_section *sp)
{
  if (sp == NULL) {
    return NULL;
  }

  return sp->next;
}

static void append_cf_section(struct conf *cp, struct conf_section *sp)
{
  struct conf_section *last;

  if (cp == NULL) {
    CACHE_ERRORLOG("cp is NULL\n");
    return;
  }

  if (cp->section == NULL) {
    cp->section = sp;
    return;
  }

  for (last = cp->section; last->next != NULL; last = last->next)
    ;
  last->next = sp;
}

static struct conf_item *find_cf_nitem(struct conf_section *sp, const char *key, int idx)
{
  struct conf_item *ip;
  int i;

  if (key == NULL || key[0] == '\0') {
    return NULL;
  }

  i = 0;
  for (ip = sp->item; ip != NULL; ip = ip->next) {
    if (ip->key != NULL && ip->key[0] == key[0]
        && strcasecmp(ip->key, key) == 0) {
      if (i == idx) {
        return ip;
      }
      i++;
    }
  }

  return NULL;
}

static void append_cf_item(struct conf_section *sp, struct conf_item *ip)
{
  struct conf_item *last;

  if (sp == NULL) {
    return;
  }

  if (sp->item == NULL) {
    sp->item = ip;
    return;
  }

  for (last = sp->item; last->next != NULL; last = last->next)
    ;
  last->next = ip;
}

static void append_cf_value(struct conf_item *ip, struct conf_value *vp)
{
  struct conf_value *last;

  if (ip == NULL) {
    return;
  }

  if (ip->val == NULL) {
    ip->val = vp;
    return;
  }

  for (last = ip->val; last->next != NULL; last = last->next)
    ;
  last->next = vp;
}

bool conf_section_match_prefix(const struct conf_section *sp, const char *name_prefix)
{
  return strncasecmp(sp->name, name_prefix, strlen(name_prefix)) == 0;
}

const char *conf_section_get_name(const struct conf_section *sp)
{
  return sp->name;
}

int conf_section_get_num(const struct conf_section *sp)
{
  return sp->num;
}

char *conf_section_get_nmval(struct conf_section *sp, const char *key, int idx1, int idx2)
{
  struct conf_item *ip;
  struct conf_value *vp;
  int i;

  ip = find_cf_nitem(sp, key, idx1);
  if (ip == NULL) {
    return NULL;
  }

  vp = ip->val;
  if (vp == NULL) {
    return NULL;
  }

  for (i = 0; vp != NULL; vp = vp->next, i++) {
    if (i == idx2) {
      return vp->value;
    }
  }

  return NULL;
}

char *conf_section_get_nval(struct conf_section *sp, const char *key, int idx)
{
  struct conf_item *ip;
  struct conf_value *vp;

  ip = find_cf_nitem(sp, key, idx);
  if (ip == NULL) {
    return NULL;
  }

  vp = ip->val;
  if (vp == NULL) {
    return NULL;
  }

  return vp->value;
}

char *conf_section_get_val(struct conf_section *sp, const char *key)
{
  return conf_section_get_nval(sp, key, 0);
}

int conf_section_get_intval(struct conf_section *sp, const char *key)
{
  const char *v;
  int value;

  v = conf_section_get_nval(sp, key, 0);
  if (v == NULL) {
    return -1;
  }

  value = (int)strtol(v, NULL, 10);
  return value;
}

bool conf_section_get_boolval(struct conf_section *sp, const char *key, bool default_val)
{
  const char *v;

  v = conf_section_get_nval(sp, key, 0);
  if (v == NULL) {
    return default_val;
  }

  if (!strcasecmp(v, "Yes") || !strcasecmp(v, "Y") || !strcasecmp(v, "True")) {
    return true;
  }

  if (!strcasecmp(v, "No") || !strcasecmp(v, "N") || !strcasecmp(v, "False")) {
    return false;
  }

  return default_val;
}

static char *str_trim(char *s)
{
  char *p, *q;

  if (s == NULL) {
    return NULL;
  }

  /* remove header */
  p = s;
  while (*p != '\0' && isspace(*p)) {
    p++;
  }

  /* remove tailer */
  q = p + strlen(p);
  while (q - 1 >= p && isspace(*(q - 1))) {
    q--;
    *q = '\0';
  }

  /* if remove header, move */
  if (p != s) {
    q = s;
    while (*p != '\0') {
      *q++ = *p++;
    }
    *q = '\0';
  }

  return s;
}

static char *strsepq(char **stringp, const char *delim)
{
  char *p, *q, *r;
  int quoted = 0, bslash = 0;

  p = *stringp;
  if (p == NULL) {
    return NULL;
  }

  r = q = p;
  while (*q != '\0' && *q != '\n') {
    /* eat quoted characters */
    if (bslash) {
      bslash = 0;
      *r++ = *q++;
      continue;
    } else if (quoted) {
      if (quoted == '"' && *q == '\\') {
        bslash = 1;
        q++;
        continue;
      } else if (*q == quoted) {
        quoted = 0;
        q++;
        continue;
      }
      *r++ = *q++;
      continue;
    } else if (*q == '\\') {
      bslash = 1;
      q++;
      continue;
    } else if (*q == '"' || *q == '\'') {
      quoted = *q;
      q++;
      continue;
    }

    /* separator? */
    if (strchr(delim, *q) == NULL) {
      *r++ = *q++;
      continue;
    }

    /* new string */
    q++;
    break;
  }
  *r = '\0';

  /* skip tailer */
  while (*q != '\0' && strchr(delim, *q) != NULL) {
    q++;
  }
  if (*q != '\0') {
    *stringp = q;
  } else {
    *stringp = NULL;
  }

  return p;
}

static int parse_line(struct conf *cp, char *lp)
{
  struct conf_section *sp;
  struct conf_item *ip;
  struct conf_value *vp;
  char *arg;
  char *key;
  char *val;
  char *p;
  int num;

  arg = str_trim(lp);
  if (arg == NULL) {
    CACHE_ERRORLOG("no section\n");
    return -1;
  }

  if (arg[0] == '[') {
    /* section */
    arg++;
    key = strsepq(&arg, "]");
    if (key == NULL || arg != NULL) {
      CACHE_ERRORLOG("broken section\n");
      return -1;
    }
    /* determine section number */
    for (p = key; *p != '\0' && !isdigit((int) *p); p++)
      ;
    if (*p != '\0') {
      num = (int)strtol(p, NULL, 10);
    } else {
      num = 0;
    }

    sp = conf_find_section(cp, key);
    if (sp == NULL) {
      sp = allocate_cf_section();
      append_cf_section(cp, sp);
    }
    cp->current_section = sp;
    sp->name = strdup(key);
    if (sp->name == NULL) {
      CACHE_ERRORLOG("cannot duplicate %s to sp->name\n", key);
      return -1;
    }

    sp->num = num;
  } else {
    /* parameters */
    sp = cp->current_section;
    if (sp == NULL) {
      CACHE_ERRORLOG("unknown section\n");
      return -1;
    }
    key = strsepq(&arg, CF_DELIM);
    if (key == NULL) {
      CACHE_ERRORLOG("broken key\n");
      return -1;
    }

    ip = allocate_cf_item();
    if (ip == NULL) {
      CACHE_ERRORLOG("cannot allocate cf item\n");
      return -1;
    }
    append_cf_item(sp, ip);
    ip->key = strdup(key);
    if (ip->key == NULL) {
      CACHE_ERRORLOG("cannot make duplicate of %s\n", key);
      return -1;
    }
    ip->val = NULL;
    if (arg != NULL) {
      /* key has value(s) */
      while (arg != NULL) {
        val = strsepq(&arg, CF_DELIM);
        vp = allocate_cf_value();
        if (vp == NULL) {
          CACHE_ERRORLOG("cannot allocate cf value\n");
          return -1;
        }
        append_cf_value(ip, vp);
        vp->value = strdup(val);
        if (vp->value == NULL) {
          CACHE_ERRORLOG("cannot duplicate %s to vp->value\n", val);
          return -1;
        }
      }
    }
  }

  return 0;
}

static char *fgets_line(FILE *fp)
{
  char *dst, *dst2, *p;
  size_t total, len;

  dst = p = malloc(LIB_MAX_TMPBUF);
  if (!dst) {
    return NULL;
  }

  dst[0] = '\0';
  total = 0;

  while (fgets(p, LIB_MAX_TMPBUF, fp) != NULL) {
    len = strlen(p);
    total += len;
    if (len + 1 < LIB_MAX_TMPBUF || dst[total - 1] == '\n') {
      dst2 = realloc(dst, total + 1);
      if (!dst2) {
        free(dst);
        return NULL;
      } else {
        return dst2;
      }
    }

    dst2 = realloc(dst, total + LIB_MAX_TMPBUF);
    if (!dst2) {
      free(dst);
      return NULL;
    } else {
      dst = dst2;
    }

    p = dst + total;
  }

  if (feof(fp) && total != 0) {
    dst2 = realloc(dst, total + 2);
    if (!dst2) {
      free(dst);
      return NULL;
    } else {
      dst = dst2;
    }

    dst[total] = '\n';
    dst[total + 1] = '\0';
    return dst;
  }

  free(dst);

  return NULL;
}

int conf_read(struct conf *cp, const char *file)
{
  FILE *fp;
  char *lp, *p;
  char *lp2, *q;
  int line;
  int n, n2;

  if (file == NULL || file[0] == '\0') {
    return -1;
  }

  fp = fopen(file, "r");
  if (fp == NULL) {
    CACHE_ERRORLOG("open error: %s\n", file);
    return -1;
  }

  cp->file = strdup(file);
  if (cp->file == NULL) {
    CACHE_ERRORLOG("cannot duplicate %s to cp->file\n", file);
    fclose(fp);
    return -1;
  }

  line = 1;
  while ((lp = fgets_line(fp)) != NULL) {
    /* skip spaces */
    for (p = lp; *p != '\0' && isspace((int) *p); p++)
      ;
    /* skip comment, empty line */
    if (p[0] == '#' || p[0] == '\0') {
      goto next_line;
    }

    /* concatenate line end with '\' */
    n = strlen(p);
    while (n > 2 && p[n - 1] == '\n' && p[n - 2] == '\\') {
      n -= 2;
      lp2 = fgets_line(fp);
      if (lp2 == NULL) {
        break;
      }

      line++;
      n2 = strlen(lp2);

      q = malloc(n + n2 + 1);
      if (!q) {
        free(lp2);
        free(lp);
        CACHE_ERRORLOG("malloc failed at line %d of %s\n", line, cp->file);
        fclose(fp);
        return -1;
      }

      memcpy(q, p, n);
      memcpy(q + n, lp2, n2);
      q[n + n2] = '\0';
      free(lp2);
      free(lp);
      p = lp = q;
      n += n2;
    }

    /* parse one line */
    if (parse_line(cp, p) < 0) {
      CACHE_ERRORLOG("parse error at line %d of %s\n", line, cp->file);
    }
next_line:
    line++;
    free(lp);
  }

  fclose(fp);
  return 0;
}

/* get specified cache device of a osd*/
const char *get_osd_dev(const char *cf_name, const char *osd_devid)
{
  struct conf *config = conf_allocate();
  if (!config) {
    CACHE_ERRORLOG("unable to allocate config\n");
    return NULL;
  }

  int ret = conf_read(config, cf_name);
  if (ret < 0) {
    CACHE_ERRORLOG("cannot read specfied config file\n");
    return NULL;
  }

  struct conf_section *sp = NULL;
  const char *secname = "AIO";

  sp = conf_find_section(config, secname);
  if (sp == NULL) {
    CACHE_ERRORLOG("can't find section: %s\n", secname);
    return NULL;
  }

  int i = 0;
  for (; ; i++) {
    static const char *name = NULL;

    char *file = conf_section_get_nmval(sp, "AIO", i, 0);
    if (!file)
      break;

    name = conf_section_get_nmval(sp, "AIO", i, 1);
    if (!name)
      break;

    if (!strncmp(name, osd_devid, strlen(osd_devid)))
      return file;
  }

  return NULL;
}
