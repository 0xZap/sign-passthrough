#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static ngx_int_t ngx_http_sign_module_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_sign_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_sign_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static unsigned char* sign_response(ngx_http_request_t *r, u_char *buf, size_t len, size_t *sig_len);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

typedef struct {
    ngx_str_t private_key_path;
} ngx_http_sign_loc_conf_t;

typedef struct {
    ngx_chain_t *in;
} ngx_http_sign_ctx_t;

static void *ngx_http_sign_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_sign_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sign_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->private_key_path.data = NULL;
    conf->private_key_path.len = 0;

    return conf;
}

static char *ngx_http_sign_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_sign_loc_conf_t *prev = parent;
    ngx_http_sign_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->private_key_path, prev->private_key_path, "");

    return NGX_CONF_OK;
}

static char *ngx_http_sign_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_sign_loc_conf_t *slcf = conf;
    ngx_str_t *value;

    value = cf->args->elts;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "sign_passthrough requires private key path as parameter");
        return NGX_CONF_ERROR;
    }

    slcf->private_key_path = value[1];

    return NGX_CONF_OK;
}


static ngx_http_module_t ngx_http_sign_module_ctx = {
    NULL,                             // preconfiguration
    ngx_http_sign_module_init,        // postconfiguration
    NULL,                             // create main configuration
    NULL,                             // init main configuration
    NULL,                             // create server configuration
    NULL,                             // merge server configuration
    ngx_http_sign_create_loc_conf,    // create location configuration
    ngx_http_sign_merge_loc_conf      // merge location configuration
};

static ngx_command_t ngx_http_sign_commands[] = {
    { ngx_string("sign_passthrough"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_sign_path,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sign_loc_conf_t, private_key_path),
      NULL },
    ngx_null_command
};

ngx_module_t ngx_http_sign_module = {
    NGX_MODULE_V1,
    &ngx_http_sign_module_ctx,   // module context
    ngx_http_sign_commands,      // module directives
    NGX_HTTP_MODULE,             // module type
    NULL,                        // init master
    NULL,                        // init module
    NULL,                        // init process
    NULL,                        // init thread
    NULL,                        // exit thread
    NULL,                        // exit process
    NULL,                        // exit master
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_sign_module_init(ngx_conf_t *cf) {
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "sign_passthrough module: initializing");

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_sign_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_sign_body_filter;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "sign_passthrough module: filter chain setup complete");
    return NGX_OK;
}

static ngx_int_t ngx_http_sign_header_filter(ngx_http_request_t *r) {
    ngx_http_sign_loc_conf_t *slcf;
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);

    if (slcf->private_key_path.len == 0 || r->method == NGX_HTTP_HEAD || r->header_only) {
        return ngx_http_next_header_filter(r);
    }

    ngx_http_sign_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sign_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_sign_module);

    r->filter_need_in_memory = 1;

    return NGX_OK;
}

static ngx_int_t ngx_http_sign_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_sign_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_sign_module);

    if (ctx == NULL || in == NULL || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sign_passthrough module: body filter");

    ngx_chain_t **ll = &ctx->in;
    while (*ll) {
        ll = &(*ll)->next;
    }
    *ll = in;

    ngx_chain_t *cl;
    int last = 0;
    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            last = 1;
            break;
        }
    }

    if (!last) {
        return NGX_OK;
    }

    size_t len = 0;
    for (cl = ctx->in; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            len += cl->buf->last - cl->buf->pos;
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sign_passthrough module: total buffer length=%uz", len);

    if (len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sign_passthrough module: empty buffer, skipping");
        return ngx_http_next_body_filter(r, ctx->in);
    }

    u_char *buf = ngx_pnalloc(r->pool, len);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: failed to allocate buffer");
        return NGX_ERROR;
    }

    u_char *p = buf;
    for (cl = ctx->in; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            size_t n = cl->buf->last - cl->buf->pos;
            p = ngx_cpymem(p, cl->buf->pos, n);
        }
    }

    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) {
        len--;
    }

    size_t sig_len = 0;
    unsigned char *signature = sign_response(r, buf, len, &sig_len);
    if (signature == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: signing failed");
        return NGX_ERROR;
    }

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: failed to add header");
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "X-Signed-Checksum");

    ngx_str_t sig_str;
    sig_str.data = signature;
    sig_str.len = sig_len;

    h->value.len = ngx_base64_encoded_length(sig_str.len);
    h->value.data = ngx_pnalloc(r->pool, h->value.len);
    if (h->value.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: failed to allocate memory for base64");
        return NGX_ERROR;
    }

    ngx_encode_base64(&h->value, &sig_str);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sign_passthrough module: signature header added successfully");

    ngx_int_t rc = ngx_http_next_header_filter(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    return ngx_http_next_body_filter(r, ctx->in);
}

unsigned char* sign_response(ngx_http_request_t *r, u_char *buf, size_t len, size_t *sig_len_out) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "sign_passthrough module: body: %s", buf);

    ngx_http_sign_loc_conf_t *slcf;
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);

    char *key_path = ngx_pcalloc(r->pool, slcf->private_key_path.len + 1);
    if (key_path == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "sign_passthrough module: failed to allocate memory for key path");
        return NULL;
    }

    ngx_memcpy(key_path, slcf->private_key_path.data, slcf->private_key_path.len);
    key_path[slcf->private_key_path.len] = '\0';

    FILE *fp = fopen(key_path, "r");
    if (fp == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
            "sign_passthrough module: failed to open private key file: %s", key_path);
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: failed to read private key");
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: failed to create MD context");
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: DigestSignInit failed");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (EVP_DigestSignUpdate(mdctx, buf, len) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: DigestSignUpdate failed");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: DigestSignFinal (get length) failed");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    unsigned char *sig = ngx_pcalloc(r->pool, sig_len);
    if (!sig) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: failed to allocate memory for signature");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (EVP_DigestSignFinal(mdctx, sig, &sig_len) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sign_passthrough module: DigestSignFinal failed");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    *sig_len_out = sig_len;
    return sig;
}
