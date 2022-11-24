#include "ed25519/ed25519.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
  ngx_flag_t enable_verification;
  ngx_str_t public_key;
} ngx_discord_interactions_verifier_loc_conf_t;

static void *ngx_discord_interactions_verifier_create_loc_conf(ngx_conf_t *cf);
static char *ngx_discord_interactions_verifier_merge_loc_conf(ngx_conf_t *cf,
                                                              void *parent,
                                                              void *child);
static ngx_int_t ngx_discord_interactions_verifier_init(ngx_conf_t *cf);
static char *ngx_handle_directives(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);

static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name,
                                          size_t len);

static ngx_command_t ngx_discord_interactions_verifier_commands[] = {
    {ngx_string("verify_interactions"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_handle_directives, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},
    ngx_null_command};

static ngx_http_module_t ngx_discord_interactions_verifier_module_ctx = {
    NULL,
    ngx_discord_interactions_verifier_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_discord_interactions_verifier_create_loc_conf,
    ngx_discord_interactions_verifier_merge_loc_conf};

ngx_module_t ngx_discord_interactions_verifier = {
    NGX_MODULE_V1,
    &ngx_discord_interactions_verifier_module_ctx,
    ngx_discord_interactions_verifier_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING};

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t verify(ngx_http_request_t *r, ngx_chain_t *in) {
  ngx_discord_interactions_verifier_loc_conf_t *conf;
  ngx_chain_t *cl;
  u_char *p;

  conf = ngx_http_get_module_loc_conf(r, ngx_discord_interactions_verifier);

  if (!conf->enable_verification) {
    return ngx_http_next_body_filter(r, in);
  }

  static const char *sign = "X-Signature-Ed25519";
  static const char *ts = "X-Signature-Timestamp";

  ngx_table_elt_t *signature_h =
      search_headers_in(r, (unsigned char *)sign, strlen(sign));
  ngx_table_elt_t *timestamp_h =
      search_headers_in(r, (unsigned char *)ts, strlen(ts));

  if (signature_h == NULL || timestamp_h == NULL ||
      signature_h->value.len == 0 || timestamp_h->value.len == 0) {
    r->keepalive = 0;
    return NGX_HTTP_FORBIDDEN;
  }

  char *signature = (char *)signature_h->value.data;
  char *timestamp = (char *)timestamp_h->value.data;
  char *pk = (char *)conf->public_key.data;

  char *msg =
      (char *)malloc(1 + strlen(signature) + r->headers_in.content_length_n);
  strcpy(msg, timestamp);

  for (cl = in; cl; cl = cl->next) {
    for (p = cl->buf->pos; p < cl->buf->last; p++) {
      strncat(msg, (char *)p, 1);
    }
  }

  unsigned char signature_bytes[64];
  unsigned char public_key_bytes[32];

  for (size_t count = 0;
       count < sizeof signature_bytes / sizeof *signature_bytes; count++) {
    sscanf(signature, "%2hhx", &signature_bytes[count]);
    signature += 2;
  }

  for (size_t count = 0;
       count < sizeof public_key_bytes / sizeof *public_key_bytes; count++) {
    sscanf(pk, "%2hhx", &public_key_bytes[count]);
    pk += 2;
  }

  if (ed25519_verify(signature_bytes, (const unsigned char *)msg, strlen(msg),
                     public_key_bytes)) {
    return ngx_http_next_body_filter(r, in);
  } else {
    r->keepalive = 0;
    return NGX_HTTP_FORBIDDEN;
  }
}

static void *ngx_discord_interactions_verifier_create_loc_conf(ngx_conf_t *cf) {
  ngx_discord_interactions_verifier_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool,
                     sizeof(ngx_discord_interactions_verifier_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->enable_verification = NGX_CONF_UNSET;
  return conf;
}

static char *ngx_discord_interactions_verifier_merge_loc_conf(ngx_conf_t *cf,
                                                              void *parent,
                                                              void *child) {
  ngx_discord_interactions_verifier_loc_conf_t *prev = parent;
  ngx_discord_interactions_verifier_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->enable_verification, prev->enable_verification, 0);
  ngx_conf_merge_str_value(conf->public_key, prev->public_key, "");

  return NGX_CONF_OK;
}

static ngx_int_t ngx_discord_interactions_verifier_init(ngx_conf_t *cf) {
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = verify;

  return NGX_OK;
}

static char *ngx_handle_directives(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf) {
  ngx_discord_interactions_verifier_loc_conf_t *arcf = conf;

  ngx_str_t *value;

  if (arcf->public_key.data != NULL) {
    return "is duplicate";
  }
  value = cf->args->elts;

  if (ngx_strcmp(value[1].data, "off") == 0) {
    arcf->public_key.len = 0;
    arcf->public_key.data = (u_char *)"";
    arcf->enable_verification = 0;

    return NGX_CONF_OK;
  }
  arcf->enable_verification = 1;
  arcf->public_key = value[1];

  return NGX_CONF_OK;
}

static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name,
                                          size_t len) {
  ngx_list_part_t *part;
  ngx_table_elt_t *h;
  ngx_uint_t i;

  /*
  Get the first part of the list. There is usual only one part.
  */
  part = &r->headers_in.headers.part;
  h = part->elts;

  /*
  Headers list array may consist of more than one part,
  so loop through all of it
  */
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        /* The last part, search is done. */
        break;
      }

      part = part->next;
      h = part->elts;
      i = 0;
    }

    /*
    Just compare the lengths and then the names case insensitively.
    */
    if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
      /* This header doesn't match. */
      continue;
    }

    /*
    Ta-da, we got one!
    Note, we'v stop the search at the first matched header
    while more then one header may fit.
    */
    return &h[i];
  }

  /*
  No headers was found
  */
  return NULL;
}