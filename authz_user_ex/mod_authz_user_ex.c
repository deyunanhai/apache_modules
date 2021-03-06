/* 
**  mod_authz_user_ex.c -- Apache sample authz_user_ex module
**  [Autogenerated via ``apxs -n authz_user_ex -g'']
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_authz_user_ex.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /authz_user_ex in as follows:
**
**    #   httpd.conf
**    LoadModule authz_user_ex_module modules/mod_authz_user_ex.so
**    <Location /authz_user_ex>
**    SetHandler authz_user_ex
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
**  you immediately can request the URL /authz_user_ex and watch for the
**  output of this module. This can be achieved for instance via:
**
**    $ lynx -mime_header http://localhost/authz_user_ex 
**
**  The output should be similar to the following one:
**
**    HTTP/1.1 200 OK
**    Date: Tue, 31 Mar 1998 14:42:22 GMT
**    Server: Apache/1.3.4 (Unix)
**    Connection: close
**    Content-Type: text/html
**  
**    The sample page from mod_authz_user_ex.c
*/ 

#include "apr_strings.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

typedef struct {
    int authoritative;
} authz_user_config_rec;

static void *create_authz_user_dir_config(apr_pool_t *p, char *d)
{
    authz_user_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const command_rec authz_user_cmds[] =
{
    AP_INIT_FLAG("AuthzUserAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_user_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the 'require user' or 'require valid-user' "
                 "statement is not met. (default: On)."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_user_module;

static int check_user_access(request_rec *r)
{
    authz_user_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &authz_user_module);
    char *user = r->user;
    int m = r->method_number;
    int required_user = 0;
    register int x;
    const char *t, *w;
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;

    /* BUG FIX: tadc, 11-Nov-1995.  If there is no "requires" directive,
     * then any user will do.
     */
    if (!reqs_arr) {
        return DECLINED;
    }
    reqs = (require_line *)reqs_arr->elts;

    for (x = 0; x < reqs_arr->nelts; x++) {

        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) {
            continue;
        }

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);
        if (!strcasecmp(w, "valid-user")) {
            return OK;
        }
        if (!strcasecmp(w, "user")) {
            /* And note that there are applicable requirements
             * which we consider ourselves the owner of.
             */
            required_user = 1;
            while (t[0]) {
                w = ap_getword_conf(r->pool, &t);
                if (!strcmp(user, w)) {
                    return OK;
                }
            }
        }
        if (!strcasecmp(w, "except")) {
            /* And note that there are applicable requirements
             * which we consider ourselves the owner of.
             */
            required_user = 1;
            while (t[0]) {
                w = ap_getword_conf(r->pool, &t);
                if (strcmp(user, w)) {
                    return OK;
                }
            }
        }
    }

    if (!required_user) {
        /* no applicable requirements */
        return DECLINED;
    }

    if (!conf->authoritative) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "access to %s failed, reason: user '%s' does not meet "
                  "'require'ments for user/valid-user to be allowed access",
                  r->uri, user);

    ap_note_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void authz_user_ex_register_hooks(apr_pool_t *p)
{
    ap_hook_auth_checker(check_user_access, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA authz_user_ex_module = {
    STANDARD20_MODULE_STUFF, 
    create_authz_user_dir_config, /* dir config creater */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    authz_user_cmds,              /* command apr_table_t */
    authz_user_ex_register_hooks  /* register hooks                      */
};

