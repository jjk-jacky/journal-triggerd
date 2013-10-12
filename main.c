/**
 * journal-triggerd - Copyright (C) 2013 Olivier Brunel
 *
 * main.c
 * Copyright (C) 2013 Olivier Brunel <i.am.jack.mail@gmail.com>
 *
 * This file is part of journal-triggerd.
 *
 * journal-triggerd is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * journal-triggerd is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * journal-triggerd. If not, see http://www.gnu.org/licenses/
 */

#include <config.h>

#include <systemd/sd-journal.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include "macros.h"

#define PACKAGE_TAG         "Runs trigger on journal messages"

#define USEC_PER_SEC        1000000ULL

#define JT_ERROR            g_quark_from_static_string ("JournalTriggerd-Error")
#define JT_ERROR_MISC       0

enum
{
    RC_SUCCESS = 0,
    RC_JOURNAL_OPEN,
    RC_JOURNAL_MOVE,
    RC_JOURNAL_READ,
    RC_JOURNAL_WAIT,
    RC_RULES,
    RC_ARGS,
    RC_OTHER
};

enum
{
    TYPE_MATCH          = '=',
    TYPE_PATTERN        = '?',
    TYPE_LESSER_THAN    = '<',
    TYPE_GREATER_THAN   = '>',
};

enum
{
    LINK_AND = 0,
    LINK_OR
};

enum
{
    COMP_LESSER,
    COMP_GREATER
};

struct key
{
    gchar   *name;
    gchar    type;
    gboolean is_not;
    gchar   *value;
};

struct cond
{
    gchar    type;
    gboolean is_not;
    gchar   *field;
    gpointer data;
};

struct filter
{
    guint ref;
    guint nb;
    struct cond cond[];
};

struct element
{
    /* AND/OR */
    guint link      : 1;
    /* prefixed w/ NOT */
    guint is_not    : 1;
    /* is it a filter, or a (group of filters) ? */
    guint is_filter : 1;
    /* pointer to struct filter, or first struct element in group */
    gpointer data;
    /* next element in the group */
    struct element *next;
};

struct rule
{
    struct element *element;
    gchar *trigger;
};

struct config
{
    sd_journal *journal;
    struct rule *rules;
};

static struct config *config = NULL;

static void
free_filter (struct filter *filter)
{
    guint i;

    if (!filter || --filter->ref > 0)
        return;

    for (i = 0; i < filter->nb; ++i)
    {
        struct cond *c = &filter->cond[i];
        g_free (c->field);
        if (c->type == TYPE_MATCH)
            g_free (c->data);
        else if (c->type == TYPE_PATTERN)
            g_pattern_spec_free (c->data);
    }
    g_free (filter);
}

static void
free_element (struct element *e)
{
    if (!e)
        return;

    for (;;)
    {
        struct element *next;

        next = e->next;
        if (e->data)
        {
            if (e->is_filter)
                free_filter (e->data);
            else
                free_element (e->data);
        }
        g_slice_free (struct element, e);

        if (!next)
            break;
        else
            e = next;
    }
}

static void
free_rule (struct rule *rule)
{
    if (!rule)
        return;

    free_element (rule->element);
    g_free (rule->trigger);
}

static void
free_config (void)
{
    struct rule *rule;

    if (config->journal)
        sd_journal_close (config->journal);
    for (rule = config->rules; rule->element; ++rule)
        free_rule (rule);
    g_free (config->rules);
    g_free (config);
    config = NULL;
}

static void
sig_handler (gint sig)
{
    free_config ();
    exit (RC_SUCCESS);
}

static void
free_ptrarr (GPtrArray *ptrarr)
{
    guint i;

    for (i = 1; i < ptrarr->len; i += 2)
        g_array_free (ptrarr->pdata[i + 1], TRUE);
    g_free (ptrarr->pdata[0]);
    g_ptr_array_unref (ptrarr);
}

static GArray *
get_section (GPtrArray *ptrarr, const gchar *section)
{
    guint i;

    for (i = 1; i < ptrarr->len; i += 2)
        if (streq (ptrarr->pdata[i], section))
            return ptrarr->pdata[i + 1];
    return NULL;
}

static struct key *
get_key (GArray *arr, const gchar *key)
{
    guint i;

    for (i = 0; i < arr->len; ++i)
    {
        struct key *k;

        k = &g_array_index (arr, struct key, i);
        if (streq (k->name, key))
            return k;
    }
    return NULL;
}

static struct filter *
parse_filter (GHashTable **ht, GPtrArray *ptrarr, gchar **filter, GError **error)
{
    struct filter *f;
    GArray *arr;
    gchar *s;
    gchar c = 0;
    guint i;

    for (s = *filter; *s != '\0' && !isblank (*s); ++s)
        ;
    if (*s != '\0')
    {
        c = *s;
        *s = '\0';
    }

    if (*ht)
    {
        f = g_hash_table_lookup (*ht, *filter);
        if (f)
        {
            ++f->ref;
            if (c)
                *s = c;
            *filter = s;
            return f;
        }
    }

    arr = get_section (ptrarr, *filter);
    if (!arr)
    {
        g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                "Filter '%s' not found", *filter);
        if (c)
            *s = c;
        return NULL;
    }

    if (arr->len == 0)
    {
        g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                "Filter '%s' has no conditions set", *filter);
        if (c)
            *s = c;
        return NULL;
    }

    f = g_malloc0 (sizeof (guint) * 2 + sizeof (struct cond) * arr->len);
    f->ref = 1;
    f->nb = arr->len;

    for (i = 0; i < arr->len; ++i)
    {
        struct key *k;
        struct cond *cond = &f->cond[i];

        k = &g_array_index (arr, struct key, i);
        cond->type = k->type;
        cond->is_not = k->is_not;
        cond->field = g_strdup (k->name);
        switch (k->type)
        {
            case TYPE_MATCH:
                cond->data  = g_strdup (k->value);
                break;

            case TYPE_PATTERN:
                cond->data = g_pattern_spec_new (k->value);
                continue;

            case TYPE_LESSER_THAN:
            case TYPE_GREATER_THAN:
                cond->data  = GINT_TO_POINTER (g_ascii_strtoll (k->value, NULL, 10));
                continue;
        }
    }

    if (!*ht)
        *ht = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    g_hash_table_insert (*ht, g_strdup (*filter), f);

    *filter = s;
    if (c)
        *s = c;
    return f;
}

static struct element *
parse_element (GHashTable **ht, GPtrArray *ptrarr, gchar **filter, GError **error)
{
    struct element *first_element = NULL;
    struct element *last_element = NULL;
    struct element *element;
    gchar *f = *filter;

    for (;;)
    {
        element = g_slice_new0 (struct element);
        if (last_element)
        {
            if (strcaseeqn (f, "and", 3) && (f[3] == '(' || isblank (f[3])))
            {
                element->link = LINK_AND;
                f += 3;
            }
            else if (strcaseeqn (f, "or", 2) && (f[2] == '(' || isblank (f[2])))
            {
                element->link = LINK_OR;
                f += 2;
            }
            else
            {
                g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                        "Expected 'AND' or 'OR': %s", f);
                free_element (element);
                goto undo;
            }
        }
        else
            /* first element must be AND */
            element->link = LINK_AND;

        skip_blank (f);
        if (strcaseeqn (f, "not", 3) && (f[3] == '(' || isblank (f[3])))
        {
            element->is_not = TRUE;
            f += 3;
            skip_blank (f);
        }

        if (*f == '(')
        {
            /* remember beginning, as f will move to the end */
            gchar *s = ++f;
            /* parenthesis contained within */
            gint c = 0;

            /* find closing parenthesis */
            for ( ; ; ++f)
            {
                if (*f == '\0')
                {
                    g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                            "Missing closing parenthesis: %s", *filter);
                    free_element (element);
                    goto undo;
                }
                else if (*f == '(')
                    ++c;
                else if (*f == ')')
                {
                    if (c > 0)
                        --c;
                    else
                        break;
                }
            }

            /* parse the string within parenthesis */
            *f = '\0';
            element->data = parse_element (ht, ptrarr, &s, error);
            *f = ')';
            f = s + 1;
        }
        else
        {
            element->is_filter = TRUE;
            element->data = parse_filter (ht, ptrarr, &f, error);
        }

        if (!element->data)
        {
            free_element (element);
            goto undo;
        }

        if (last_element)
            last_element->next = element;
        else
            first_element = element;
        last_element = element;

        if (!f)
            break;
        skip_blank (f);
        if (*f == '\0')
            break;
    }

    *filter = f;
    return first_element;

undo:
    free_element (first_element);
    *filter = f;
    return NULL;
}

static GPtrArray *
load_rule_file (const gchar *file, GError **error)
{
    GPtrArray *ptrarr;
    GArray *arr = NULL;
    gchar *data;
    gchar *e;
    guint ln = 0;
    gboolean in_section = FALSE;

    if (!g_file_get_contents (file, &data, NULL, error))
        return NULL;

    ptrarr = g_ptr_array_new ();
    g_ptr_array_add (ptrarr, data);

    for (;;)
    {
        struct key key;
        gchar *s;

        ++ln;
        e = strchr (data, '\n');
        if (e)
            *e = '\0';

        if (*data == '#' || e == data || *data == '\0')
            goto next;

        if (*data == '[')
        {
            s = strchr (data, ']');
            if (!s)
            {
                g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                        "Syntax error in '%s' line %d: Missing end-of-section",
                        file, ln);
                free_ptrarr (ptrarr);
                return NULL;
            }

            *s = '\0';
            g_ptr_array_add (ptrarr, data + 1);
            in_section = TRUE;

            arr = g_array_new (FALSE, FALSE, sizeof (struct key));
            g_ptr_array_add (ptrarr, arr);

            goto next;
        }
        else if (!in_section)
        {
            g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                    "Syntax error in '%s' line %d: Expected section",
                    file, ln);
            free_ptrarr (ptrarr);
            return NULL;
        }

        s = strchr (data, '=');
        if (!s)
        {
            g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                    "Syntax error in '%s' line %d: Missing '=' after key",
                    file, ln);
            free_ptrarr (ptrarr);
            return NULL;
        }
        else if (s + 1 == e)
        {
            g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                    "Syntax error in '%s' line %d: Missing value",
                    file, ln);
            free_ptrarr (ptrarr);
            return NULL;
        }

        key.value = s;
        switch (s[-1])
        {
            case TYPE_MATCH:
            case TYPE_PATTERN:
            case TYPE_LESSER_THAN:
            case TYPE_GREATER_THAN:
                key.type = *--s;
                break;

            default:
                key.type = TYPE_MATCH;
                break;
        }

        key.is_not = (s[-1] == '!');
        if (key.is_not)
            --s;

        for (--s; isblank (*s); --s)
            ;
        ++s;

        *s = '\0';
        key.name = data;

        s = key.value + 1;
        skip_blank (s);
        key.value = s;

        g_array_append_val (arr, key);

next:
        if (!e)
            break;
        data = e + 1;
    }

    return ptrarr;
}

static struct rule *
load_rules (const gchar *path, GError **error)
{
    GHashTable *ht = NULL;
    GArray *rules;
    GDir *dir;
    const gchar *file;
    gchar *filename;
    gsize len;

    dir = g_dir_open (path, 0, error);
    if (!dir)
        return NULL;

    len = strlen (path);
    filename = g_new (char, len + NAME_MAX + 2);
    memcpy (filename, path, sizeof (gchar) * len);
    if (path[len - 1] != '/')
    {
        filename[len] = '/';
        filename[++len] = '\0';
    }

    rules = g_array_new (TRUE, FALSE, sizeof (struct rule));
    g_array_set_clear_func (rules, (GDestroyNotify) free_rule);

    while ((file = g_dir_read_name (dir)))
    {
        GError *err = NULL;
        GPtrArray *ptrarr;
        GArray *arr;
        gboolean filter_done = FALSE;
        size_t l;
        guint i;

        l = strlen (file);
        if (l < 5 || !streq (file + l - 5, ".rule"))
            continue;

        strcpy (filename + len, file);
        ptrarr = load_rule_file (filename, &err);
        if (!ptrarr)
        {
            fprintf (stderr, "Failed loading rule '%s': %s\n",
                    filename, err->message);
            g_clear_error (&err);
            continue;
        }

        arr = get_section (ptrarr, "Rule");
        if (!arr)
        {
            fprintf (stderr, "Failed loading rule '%s': "
                    "Syntax error: Section 'Rule' missing\n",
                    filename);
            free_ptrarr (ptrarr);
            continue;
        }

        for (i = 0; i < arr->len; ++i)
        {
            struct key *k;

            k = &g_array_index (arr, struct key, i);

            if (streqn (k->name, "filter", 6))
            {
                struct rule rule = { NULL, };
                struct key *key;
                gchar *filter;
                gchar *s;

                filter = k->value;

                if ((k->name)[6] == '\0')
                    s = (gchar *) "trigger";
                else
                    s = g_strdup_printf ("trigger%s", k->name + 6);

                key = get_key (arr, s);
                if (!key)
                {
                    fprintf (stderr, "Failed loading rule '%s': "
                            "Syntax error: no matching '%s' for '%s'\n",
                            filename, s, k->name);
                    if ((k->name)[6] != '\0')
                        g_free (s);
                    break;
                }

                if (key->type != TYPE_MATCH)
                {
                    fprintf (stderr, "Failed loading rule '%s': "
                            "Syntax error: option '%s' with invalid type\n",
                            filename, s);
                    if ((k->name)[6] != '\0')
                        g_free (s);
                    break;
                }

                rule.trigger = g_strdup (key->value);
                if ((k->name)[6] != '\0')
                    g_free (s);
                s = filter = g_strdup (filter);
                rule.element = parse_element (&ht, ptrarr, &s, &err);
                if (!rule.element)
                {
                    fprintf (stderr, "Failed loading rule '%s': %s\n",
                            filename, err->message);
                    g_clear_error (&err);
                    g_free (rule.trigger);
                    g_free (filter);
                    break;
                }
                g_free (filter);

                g_array_append_val (rules, rule);

                if ((k->name)[6] == '\0')
                    filter_done = TRUE;
            }
            else if (streqn (k->name, "trigger", 7))
            {
                if (!filter_done && (k->name)[7] == '\0')
                {
                    struct rule rule = { NULL, };
                    gchar *s;

                    s = k->value;

                    if (!get_section (ptrarr, "Filter"))
                    {
                        fprintf (stderr, "Failed loading rule '%s': "
                                "Missing section 'Filter'\n",
                                filename);
                        break;
                    }

                    rule.trigger = g_strdup (s);
                    s = "Filter";
                    rule.element = parse_element (&ht, ptrarr, &s, &err);
                    if (!rule.element)
                    {
                        fprintf (stderr, "Failed loading rule '%s': %s\n",
                                filename, err->message);
                        g_clear_error (&err);
                        g_free (rule.trigger);
                        break;
                    }

                    g_array_append_val (rules, rule);
                }
            }
            else
            {
                fprintf (stderr, "Failed loading rule '%s': "
                        "Syntax error: Unknown option '%s' in 'Rule'\n",
                        filename, k->name);
                break;
            }
        }

        free_ptrarr (ptrarr);
        if (ht)
            g_hash_table_remove_all (ht);
    }

    if (ht)
        g_hash_table_unref (ht);

    g_free (filename);
    g_dir_close (dir);

    if (rules->len == 0)
    {
        g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                "No (valid) rules found");
        g_array_free (rules, TRUE);
        return NULL;
    }
    return (struct rule *) g_array_free (rules, FALSE);
}

static gint
get_journal_field (const gchar *field, gconstpointer *data, size_t *len)
{
    gint r;
    size_t l;

    r = sd_journal_get_data (config->journal, field, data, len);
    if (r < 0)
        return r;

    /* set data to the begining of the actual value */
    l =strlen (field) + 1; /* +1 for '=' */
    *data += l; /* +1 for '=' */
    *len -= l;
    return 0;
}

static gboolean
is_filter_matching (struct filter *filter, GError **error)
{
    guint i;

    for (i = 0; i < filter->nb; ++i)
    {
        struct cond *cond = &filter->cond[i];
        gboolean match = FALSE;
        const gchar *field;
        size_t len;
        gint r;

        r = get_journal_field (cond->field, (gconstpointer *) &field, &len);
        if (r < 0)
        {
            /* ENOENT == no such field for that entry; it's not an error per-se,
             * so we simply treat this as a non-match */
            if (-r != ENOENT)
                g_set_error (error, JT_ERROR, JT_ERROR_MISC,
                        "Failed to read field '%s': %s",
                        cond->field, strerror (-r));

            return FALSE;
        }

        switch (cond->type)
        {
            case TYPE_MATCH:
                match = (strlen (cond->data) == len
                        && streqn (cond->data, field, len));
                break;

            case TYPE_LESSER_THAN:
            case TYPE_GREATER_THAN:
                {
                    gchar buf[32], *b = buf;

                    if (len >= 32)
                        b = g_new (gchar, len + 1);
                    memcpy (b, field, len);
                    b[len] = '\0';
                    if (cond->type == TYPE_LESSER_THAN)
                        match = g_ascii_strtoll (b, NULL, 10) <= GPOINTER_TO_INT (cond->data);
                    else
                        match = g_ascii_strtoll (b, NULL, 10) >= GPOINTER_TO_INT (cond->data);
                    if (b != buf)
                        g_free (b);
                }
                break;

            case TYPE_PATTERN:
                match = g_pattern_match (cond->data, len, field, NULL);
                break;
        }

        if (cond->is_not)
            match = !match;
        if (!match)
            return FALSE;
    }

    return TRUE;
}

static gboolean
is_matching (struct element *element, GError **error)
{
    GError *err = NULL;
    gboolean match = TRUE;

    for ( ; element; element = element->next)
    {
        if ((match && element->link == LINK_OR)
                || (!match && element->link == LINK_AND))
            break;

        if (element->is_filter)
        {
            match = is_filter_matching (element->data, &err);
        }
        else
            match = is_matching (element->data, &err);

        if (err)
        {
            g_propagate_error (error, err);
            return FALSE;
        }

        if (element->is_not)
            match = !match;
    }
    return match;
}

static gboolean
exec_trigger (const gchar *trigger, GError **error)
{
    GString *str = NULL;
    gchar *s;
    gboolean ret;

    s = strchr (trigger, '$');
    if (s)
        str = g_string_new (NULL);

    for ( ; s; s = strchr (s, '$'))
    {
        gchar field[128];
        const gchar *value;
        size_t len;
        gint i;
        gint r;

        for (i = 1; i <= 128 && s[i] != '\0'; ++i)
        {
            field[i - 1] = s[i];
            if (!((s[i] >= 'A' && s[i] <= 'Z') || s[i] == '_'))
                break;
        }
        field[i - 1] = '\0';

        g_string_append_len (str, trigger, s - trigger);
        r = get_journal_field (field, (gconstpointer *) &value, &len);
        if (r < 0)
        {
            if (-r != ENOENT)
                g_string_append_printf (str, "Failed to get field '%s'", field);
        }
        else
            g_string_append_len (str, value, len);

        s += i;
        trigger = s;
    }

    if (str)
    {
        g_string_append_len (str, trigger, s - trigger);
        ret = g_spawn_command_line_async (str->str, error);
        g_string_free (str, TRUE);
    }
    else
        ret = g_spawn_command_line_async (trigger, error);

    return ret;
}

static gboolean
parse_args (gint argc, gchar *argv[], GError **error)
{
    gboolean version = FALSE;

    GOptionContext *context;
    GOptionEntry entries[] = {
        { "version",    'V', 0, G_OPTION_ARG_NONE,  &version,
            "Show version information", NULL },
        { NULL }
    };

    context = g_option_context_new ("- " PACKAGE_TAG);
    g_option_context_add_main_entries (context, entries, NULL);
    if (!g_option_context_parse (context, &argc, &argv, error))
    {
        g_option_context_free (context);
        return FALSE;
    }
    g_option_context_free (context);

    if (version)
    {
        puts (  "journal-triggerd - " PACKAGE_TAG " - v" PACKAGE_VERSION "\n"
                "Copyright (C) 2013 Olivier Brunel\n"
                "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
                "This is free software: you are free to change and redistribute it.\n"
                "There is NO WARRANTY, to the extent permitted by law."
                );
        exit (RC_SUCCESS);
    }

    return TRUE;
}

gint
main (gint argc, gchar *argv[])
{
    GError *err = NULL;
    struct sigaction act;
    gint rc = RC_SUCCESS;
    gint r;

    memset (&act, 0, sizeof (struct sigaction));
    act.sa_handler = sig_handler;
    r = sigaction (SIGINT, &act, NULL);
    if (r < 0)
    {
        fprintf (stderr, "Failed to install signal handler: %s\n",
                strerror (errno));
        return RC_OTHER;
    }
    r = sigaction (SIGTERM, &act, NULL);
    if (r < 0)
    {
        fprintf (stderr, "Failed to install signal handler: %s\n",
                strerror (errno));
        return RC_OTHER;
    }

    if (argc > 1 && !parse_args (argc, argv, &err))
    {
        fprintf (stderr, "Option parsing failed: %s\n", err->message);
        g_clear_error (&err);
        return RC_ARGS;
    }

    config = g_new0 (struct config, 1);
    config->rules = load_rules (RULES_PATH, &err);
    if (!config->rules)
    {
        g_free (config);
        fprintf (stderr, "Failed to load rules: %s\n", err->message);
        g_clear_error (&err);
        return RC_RULES;
    }

    r = sd_journal_open (&config->journal, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0)
    {
        fprintf (stderr, "Failed to open journal: %s\n",
                strerror (-r));
        return RC_JOURNAL_OPEN;
    }

    r = sd_journal_seek_tail (config->journal);
    if (r < 0)
    {
        fprintf (stderr, "Failed to get to the journal's tail: %s\n",
                strerror (-r));
        rc = RC_JOURNAL_MOVE;
        goto finish;
    }

    r = sd_journal_previous (config->journal);
    if (r < 0)
    {
        fprintf (stderr, "Failed to iterate to journal last entry: %s\n",
                strerror (-r));
        rc = RC_JOURNAL_MOVE;
        goto finish;
    }

    for (;;)
    {
        struct rule *rule;

        r = sd_journal_next (config->journal);
        if (r < 0)
        {
            fprintf (stderr, "Failed to iterate to next journal entry: %s\n",
                    strerror (-r));
            rc = RC_JOURNAL_MOVE;
            break;
        }

        if (r == 0)
        {
            /* end of journal, let's wait for changes */
            r = sd_journal_wait (config->journal, (uint64_t) -1);
            if (r < 0)
            {
                fprintf (stderr, "Failed to wait for journal changes: %s\n",
                        strerror (-r));
                rc = RC_JOURNAL_WAIT;
                break;
            }
            continue;
        }

        for (rule = config->rules; rule->element; ++rule)
        {
            if (is_matching (rule->element, &err))
            {
                if (!exec_trigger (rule->trigger, &err))
                {
                    fprintf (stderr, "Failed to execute trigger '%s': %s\n",
                            rule->trigger,
                            (err) ? err->message : "(no error message)");
                    g_clear_error (&err);
                }
            }
            else if (err)
            {
                fprintf (stderr, "Error occured while processing a rule: %s\n",
                        err->message);
                g_clear_error (&err);
            }
        }
    }

finish:
    free_config ();
    return rc;
}
