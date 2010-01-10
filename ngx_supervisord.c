/*
 * Copyright (c) 2009-2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * All rights reserved.
 *
 * This project was fully funded by megiteam.pl.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY FRiCKLE PIOTR SIKORA AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL FRiCKLE PIOTR
 * SIKORA OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <ngx_supervisord.h>
#include <nginx.h>

#if (NGX_HTTP_UPSTREAM_INIT_BUSY_PATCH_VERSION != 1)
  #error "ngx_supervisord requires NGX_HTTP_UPSTREAM_INIT_BUSY_PATCH v1"
#endif

#define NGX_SUPERVISORD_MONITOR_INTERVAL  10000
#define NGX_SUPERVISORD_QUEUE_INTERVAL      500
#define NGX_SUPERVISORD_LOAD_SKIP             6
#define NGX_SUPERVISORD_ANTISPAM          30000

void       *ngx_supervisord_create_srv_conf(ngx_conf_t *);
void       *ngx_supervisord_create_loc_conf(ngx_conf_t *);
ngx_int_t   ngx_supervisord_preconf(ngx_conf_t *);
char       *ngx_supervisord_conf(ngx_conf_t *, ngx_command_t *, void *);
char       *ngx_supervisord_conf_name(ngx_conf_t *, ngx_command_t *, void *);
char       *ngx_supervisord_conf_inherit_backend_status(ngx_conf_t *,
                ngx_command_t *, void *);
char       *ngx_supervisord_conf_start_handler(ngx_conf_t *, ngx_command_t *,
                void *);
char       *ngx_supervisord_conf_stop_handler(ngx_conf_t *, ngx_command_t *,
                void *);
ngx_int_t   ngx_supervisord_module_init(ngx_cycle_t *);
ngx_int_t   ngx_supervisord_worker_init(ngx_cycle_t *);
void        ngx_supervisord_monitor(ngx_event_t *);
void        ngx_supervisord_queue_monitor(ngx_event_t *);
void        ngx_supervisord_finalize_request(ngx_http_request_t *, ngx_int_t);
const char *ngx_supervisord_get_command(ngx_uint_t);

typedef struct {
    ngx_url_t                      server;
    ngx_str_t                      userpass;	/* user:pass format */
    ngx_str_t                      name;
    ngx_int_t                      is_fake;
} ngx_supervisord_conf_t;

typedef struct {
    ngx_supervisord_conf_t         supervisord;
    ngx_http_upstream_srv_conf_t  *uscf;	/* original uscf */
    ngx_int_t                      inherit_backend_status;
    /* memory */
    ngx_shm_zone_t                *shm;
    ngx_pool_t                    *lpool;	/* local memory pool */
    ngx_slab_pool_t               *shpool;	/* shared memory pool */
    /* backends */
    ngx_uint_t                     nservers;	/* number of servers */
    ngx_uint_t                     aservers;	/* number of active servers */
    ngx_uint_t                    *lservers;	/* local servers list */
    ngx_uint_t                    *shservers;	/* shared servers list */
    ngx_uint_t                    *dservers;	/* local diff between lists */
    /* monitors */
    ngx_supervisord_backend_pt     backend_monitor;
    ngx_supervisord_load_pt        load_monitor;
    ngx_uint_t                     load_skip;
    /* misc */
    ngx_msec_t                    *last_cmd;	/* shared */
    ngx_uint_t                    *total_reqs;	/* shared */
    ngx_uint_t                     total_reported;
    ngx_queue_t                    queue;
    ngx_event_t                    queue_timer;
} ngx_supervisord_srv_conf_t;

typedef struct {
    ngx_http_upstream_srv_conf_t  *upstream;
    ngx_uint_t                     command;
} ngx_supervisord_loc_conf_t;

typedef struct {
    ngx_uint_t                     command;
    ngx_uint_t                     backend;
} ngx_supervisord_ctx_t;

typedef struct {
    ngx_supervisord_srv_conf_t    *supcf;
    ngx_http_request_t            *request;
    ngx_uint_t                     command;
    ngx_uint_t                     backend;
    ngx_supervisord_checker_pt     checker;
} ngx_supervisord_queued_cmd_t;

typedef struct {
    ngx_http_request_t            *request;
    ngx_queue_t                    queue;
} ngx_supervisord_queued_req_t;

static ngx_command_t  ngx_supervisord_module_commands[] = {

    { ngx_string("supervisord"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_supervisord_conf,
      0,
      0,
      NULL },

    { ngx_string("supervisord_name"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_supervisord_conf_name,
      0,
      0,
      NULL },

    { ngx_string("supervisord_inherit_backend_status"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_supervisord_conf_inherit_backend_status,
      0,
      0,
      NULL },

    { ngx_string("supervisord_start"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_supervisord_conf_start_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("supervisord_stop"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_supervisord_conf_stop_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
      ngx_null_command
};

static ngx_http_module_t  ngx_supervisord_module_ctx = {
    ngx_supervisord_preconf,            /* preconfiguration */
    NULL,                               /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    ngx_supervisord_create_srv_conf,    /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_supervisord_create_loc_conf,    /* create location configuration */
    NULL                                /* merge location configuration */
};

/* cheap hack, but sadly we need it */
ngx_module_t  ngx_http_copy_filter_module;

ngx_module_t  ngx_supervisord_module = {
    NGX_MODULE_V1,
    &ngx_supervisord_module_ctx,        /* module context */
    ngx_supervisord_module_commands,    /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    ngx_supervisord_module_init,        /* init module */
    ngx_supervisord_worker_init,        /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * configuration & initialization
 */

ngx_array_t  *ngx_supervisord_upstreams;
ngx_event_t  *ngx_supervisord_timer;

void *
ngx_supervisord_create_srv_conf(ngx_conf_t *cf)
{
    ngx_supervisord_srv_conf_t  *supcf;

    supcf = ngx_pcalloc(cf->pool, sizeof(ngx_supervisord_srv_conf_t));
    if (supcf == NULL) {
        return NGX_CONF_ERROR;
    }

    return supcf;
}

void *
ngx_supervisord_create_loc_conf(ngx_conf_t *cf)
{
    ngx_supervisord_loc_conf_t  *suplcf;

    suplcf = ngx_pcalloc(cf->pool, sizeof(ngx_supervisord_loc_conf_t));
    if (suplcf == NULL) {
        return NGX_CONF_ERROR;
    }

    return suplcf;
}

ngx_int_t
ngx_supervisord_preconf(ngx_conf_t *cf)
{
    ngx_supervisord_upstreams = ngx_array_create(cf->pool, 8,
                                    sizeof(ngx_supervisord_srv_conf_t *));
    if (ngx_supervisord_upstreams == NULL) {
        return NGX_ERROR;
    }

    ngx_supervisord_timer = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
    if (ngx_supervisord_timer == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_supervisord_shm_init(ngx_shm_zone_t *shm, void *data)
{
    ngx_supervisord_srv_conf_t  *supcf, *osupcf;

    if (data) {
        osupcf = data;

        if (osupcf->shservers != NULL) {
            ngx_slab_free(osupcf->shpool, osupcf->shservers);
        }

        if (osupcf->total_reqs != NULL) {
            ngx_slab_free(osupcf->shpool, osupcf->total_reqs);
        }

        if (osupcf->last_cmd != NULL) {
            ngx_slab_free(osupcf->shpool, osupcf->last_cmd);
        }
    }

    supcf = shm->data;
    supcf->shpool = (ngx_slab_pool_t *) shm->shm.addr;

    return NGX_OK;
}

char *
ngx_supervisord_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                      *value = cf->args->elts;
    ngx_http_upstream_srv_conf_t   *uscf;
    ngx_supervisord_srv_conf_t     *supcf;
    ngx_supervisord_srv_conf_t    **supcfp;
    ngx_connection_t               *dummy;

    uscf  = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    supcf = ngx_http_conf_get_module_srv_conf(cf, ngx_supervisord_module);
    supcf->uscf = uscf; /* original uscf */

    supcf->lpool = cf->pool;

    if (supcf->supervisord.server.url.data != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "supervisord already set to \"%V\"",
            &supcf->supervisord.server.url);

        return NGX_CONF_ERROR;
    }

    if (supcf->supervisord.is_fake) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "supervisord already set to \"none\"");

        return NGX_CONF_ERROR;
    }

    if (ngx_strncmp(value[1].data, "none", 4) == 0) {
        supcf->supervisord.is_fake = 1;
    } else {
        supcf->supervisord.server.url = value[1];
        if (ngx_parse_url(cf->pool, &supcf->supervisord.server) != NGX_OK) {
            if (supcf->supervisord.server.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in supervisord \"%V\"",
                    supcf->supervisord.server.err,
                    &supcf->supervisord.server.url);
            }

            return NGX_CONF_ERROR;
        }

        if (cf->args->nelts == 3) {
            supcf->supervisord.userpass = value[2];
        }
    }

    supcf->shm = ngx_shared_memory_add(cf, &uscf->host, 4 * ngx_pagesize,
                                       &ngx_supervisord_module);
    if (supcf->shm == NULL) {
        return NGX_CONF_ERROR;
    }

    supcf->shm->init = ngx_supervisord_shm_init;
    supcf->shm->data = supcf;

    ngx_queue_init(&supcf->queue);

    dummy = ngx_pcalloc(cf->pool, sizeof(ngx_connection_t));
    if (dummy == NULL) {
        return NGX_CONF_ERROR;
    }

    dummy->fd = (ngx_socket_t) -1;
    dummy->data = supcf;

    supcf->queue_timer.log = ngx_cycle->log;
    supcf->queue_timer.data = dummy;
    supcf->queue_timer.handler = ngx_supervisord_queue_monitor;

    supcfp = ngx_array_push(ngx_supervisord_upstreams);
    if (supcfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *supcfp = supcf;

    return NGX_CONF_OK;
}

char *
ngx_supervisord_conf_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                   *value = cf->args->elts;
    ngx_supervisord_srv_conf_t  *supcf;

    supcf = ngx_http_conf_get_module_srv_conf(cf, ngx_supervisord_module);

    if (supcf->supervisord.name.data != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "supervisord_name already set to \"%V\"", &supcf->supervisord.name);

        return NGX_CONF_ERROR;
    }

    supcf->supervisord.name = value[1];

    return NGX_CONF_OK;
}

char *
ngx_supervisord_conf_inherit_backend_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_supervisord_srv_conf_t  *supcf;

    supcf = ngx_http_conf_get_module_srv_conf(cf, ngx_supervisord_module);
    supcf->inherit_backend_status = 1;

    return NGX_CONF_OK;
}

ngx_int_t
ngx_supervisord_module_init(ngx_cycle_t *cycle)
{
    ngx_supervisord_srv_conf_t  **supcfp;
    ngx_http_upstream_server_t   *server;
    ngx_uint_t                    i, n;
    size_t                        size;

    supcfp = ngx_supervisord_upstreams->elts;
    for (i = 0; i < ngx_supervisord_upstreams->nelts; i++) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                       "[supervisord] upstream: %V, initializing",
                       &supcfp[i]->uscf->host);

        supcfp[i]->nservers = supcfp[i]->uscf->servers->nelts;

        size = supcfp[i]->nservers * sizeof(ngx_uint_t);

        supcfp[i]->lservers = ngx_pcalloc(supcfp[i]->lpool, size);
        if (supcfp[i]->lservers == NULL) {
            return NGX_ERROR;
        }

        if (supcfp[i]->inherit_backend_status) {
            server = supcfp[i]->uscf->servers->elts;
            for (n = 0; n < supcfp[i]->nservers; n++) {
                supcfp[i]->lservers[n] = server[n].down;
                if (!server[n].down) {
                    supcfp[i]->aservers++;
                }
            }
        } else {
            for (n = 0; n < supcfp[i]->nservers; n++) {
                supcfp[i]->lservers[n] = NGX_SUPERVISORD_SRV_DOWN;
            }
        }

        if (supcfp[i]->backend_monitor != NULL) {
            for (n = 0; n < supcfp[i]->nservers; n++) {
                supcfp[i]->backend_monitor(supcfp[i]->uscf, n,
                                           supcfp[i]->lservers[n]);
            }
        }

        supcfp[i]->dservers = ngx_pcalloc(supcfp[i]->lpool, size);
        if (supcfp[i]->dservers == NULL) {
            return NGX_ERROR;
        }

        ngx_shmtx_lock(&supcfp[i]->shpool->mutex);

        supcfp[i]->shservers = ngx_slab_alloc_locked(supcfp[i]->shpool, size);
        if (supcfp[i]->shservers == NULL) {
            goto failed;
        }

        for (n = 0; n < supcfp[i]->nservers; n++) {
            supcfp[i]->shservers[n] = supcfp[i]->lservers[n];
        }

        supcfp[i]->total_reqs = ngx_slab_alloc_locked(supcfp[i]->shpool,
                                                      sizeof(ngx_uint_t));
        if (supcfp[i]->total_reqs == NULL) {
            goto failed;
        }

        *supcfp[i]->total_reqs = 0;

        supcfp[i]->last_cmd = ngx_slab_alloc_locked(supcfp[i]->shpool,
                                                    sizeof(ngx_msec_t));
        if (supcfp[i]->last_cmd == NULL) {
            goto failed;
        }

        *supcfp[i]->last_cmd = 0;

        ngx_shmtx_unlock(&supcfp[i]->shpool->mutex);
    }

    return NGX_OK;

failed:
    ngx_shmtx_unlock(&supcfp[i]->shpool->mutex);

    return NGX_ERROR;
}

ngx_int_t
ngx_supervisord_worker_init(ngx_cycle_t *cycle)
{
    ngx_connection_t  *dummy;

#if (nginx_version >= 8028)
    if (ngx_process > NGX_PROCESS_WORKER) {
#else
    /*
     * This is really cheap hack, but it's the only way
     * to distinguish "workers" from "cache manager"
     * and "cache loader" without additional patch.
     *
     * NOTE: "worker_connections" cannot be set to 512!
     */
    if (cycle->connection_n == 512) {
#endif
        /* work only on real worker processes */
        return NGX_OK;
    }

    if (ngx_supervisord_upstreams->nelts == 0) {
        /* nothing to do */
        return NGX_OK;
    }

    dummy = ngx_pcalloc(ngx_supervisord_upstreams->pool,
                        sizeof(ngx_connection_t));
    if (dummy == NULL) {
        return NGX_ERROR;
    }

    dummy->fd = (ngx_socket_t) -1;
    dummy->data = ngx_supervisord_upstreams;

    ngx_supervisord_timer->log = ngx_cycle->log;
    ngx_supervisord_timer->data = dummy;
    ngx_supervisord_timer->handler = ngx_supervisord_monitor;

    ngx_add_timer(ngx_supervisord_timer, NGX_SUPERVISORD_MONITOR_INTERVAL);

    return NGX_OK;
}

/*
 * sync, monitors, etc.
 */

void
ngx_supervisord_sync_servers(ngx_supervisord_srv_conf_t *supcf)
{
    ngx_uint_t  i;

    ngx_shmtx_lock(&supcf->shpool->mutex);

    for (i = 0; i < supcf->nservers; i++) {
        if (supcf->lservers[i] != supcf->shservers[i]) {
            supcf->lservers[i] = supcf->shservers[i];
            supcf->dservers[i] = 1;
        }
    }

    ngx_shmtx_unlock(&supcf->shpool->mutex);

    supcf->aservers = 0;
    for (i = 0; i < supcf->nservers; i++) {
        if (supcf->lservers[i] == NGX_SUPERVISORD_SRV_UP) {
            supcf->aservers++;
        }

        if (supcf->dservers[i]) {
            supcf->dservers[i] = 0;

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                "[supervisord] upstream: %V, backend: %ui, new status: %ui",
                &supcf->uscf->host, i, supcf->lservers[i]);

            if (supcf->backend_monitor != NULL) {
                supcf->backend_monitor(supcf->uscf, i, supcf->lservers[i]);
            }
        }
    }
}

void
ngx_supervisord_sync_load(ngx_supervisord_srv_conf_t *supcf)
{
    ngx_supervisord_load_t  report;
    ngx_uint_t              curr, load;
    ngx_int_t               diff;

    ngx_shmtx_lock(&supcf->shpool->mutex);
    curr = *supcf->total_reqs;
    ngx_shmtx_unlock(&supcf->shpool->mutex);

    diff = curr - supcf->total_reported;
    supcf->total_reported = curr;

    if (diff < 0) {
        /* overflow? */
        return;
    }

    if ((diff == 0) || (supcf->aservers == 0)) {
        load = 0;
    } else {
        /* load = requests per second per active backend */
        load = ((diff * NGX_SUPERVISORD_LOAD_MULTIPLIER)
             / (((NGX_SUPERVISORD_MONITOR_INTERVAL * NGX_SUPERVISORD_LOAD_SKIP)
             / 1000) * supcf->aservers));
    }

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
        "[supervisord] upstream: %V, load: %ui.%02ui, reqs: %i, up: %ui/%ui",
        &supcf->uscf->host,
        load / NGX_SUPERVISORD_LOAD_MULTIPLIER,
        load % NGX_SUPERVISORD_LOAD_MULTIPLIER,
        diff, supcf->aservers, supcf->nservers);

    if (supcf->load_monitor != NULL) {
        report.load = load;
        report.reqs = diff;
        report.aservers = supcf->aservers;
        report.nservers = supcf->nservers;
        report.interval = NGX_SUPERVISORD_MONITOR_INTERVAL
                        * NGX_SUPERVISORD_LOAD_SKIP;

        supcf->load_monitor(supcf->uscf, report);
    }
}

ngx_int_t
ngx_supervisord_resume_requests(ngx_supervisord_srv_conf_t *supcf)
{
    ngx_supervisord_queued_req_t  *qr;
    ngx_http_request_t            *or;
    ngx_queue_t                   *q;
    ngx_int_t                      rc;

    if (ngx_queue_empty(&supcf->queue)) {
        return NGX_OK;
    }

    ngx_supervisord_sync_servers(supcf);

    if (supcf->lservers[0] > NGX_SUPERVISORD_SRV_DOWN) {
        /* retry later, backend status still changing */
        return NGX_BUSY;
    }

    rc = (supcf->lservers[0] == NGX_SUPERVISORD_SRV_UP)
       ? 0 : NGX_HTTP_BAD_GATEWAY;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
        "[supervisord] upstream: %V, resuming queued requests, rc: %i",
        &supcf->uscf->host, rc);

    while (!ngx_queue_empty(&supcf->queue)) {
        q = ngx_queue_head(&supcf->queue);
        qr = ngx_queue_data(q, ngx_supervisord_queued_req_t, queue);
        or = qr->request;
        ngx_queue_remove(q);
        (void) ngx_pfree(supcf->lpool, qr);

        if (rc == 0) {
            /* resume processing */
            ngx_http_upstream_connect(or, or->upstream);
        } else {
            /* remove cleanup, otherwise we end up with double free! */
            if ((or->upstream) && (or->upstream->cleanup)) {
                *or->upstream->cleanup = NULL;
            }

            ngx_http_finalize_request(or, rc);
        }
    }

    return NGX_OK;
}

void
ngx_supervisord_monitor(ngx_event_t *ev)
{
    ngx_connection_t             *dummy = ev->data;
    ngx_array_t                  *upstreams = dummy->data;
    ngx_supervisord_srv_conf_t  **supcfp;
    ngx_uint_t                    i;

    if (ngx_exiting) {
        return;
    }

    supcfp = upstreams->elts;
    for (i = 0; i < upstreams->nelts; i++) {
        ngx_supervisord_sync_servers(supcfp[i]);

        supcfp[i]->load_skip = ++supcfp[i]->load_skip
                             % NGX_SUPERVISORD_LOAD_SKIP;
        if (supcfp[i]->load_skip == 0) {
            ngx_supervisord_sync_load(supcfp[i]);
        }
    }

    ngx_add_timer(ev, NGX_SUPERVISORD_MONITOR_INTERVAL);
}

void
ngx_supervisord_queue_monitor(ngx_event_t *ev)
{
    ngx_connection_t            *dummy = ev->data;
    ngx_supervisord_srv_conf_t  *supcf = dummy->data;

    if (ngx_supervisord_resume_requests(supcf) == NGX_BUSY) {
        ngx_add_timer(ev, NGX_SUPERVISORD_QUEUE_INTERVAL);
    }
}

/*
 * ngx_supervisord API
 */

ngx_http_request_t  *ngx_supervisord_init(ngx_pool_t *,
                         ngx_http_upstream_srv_conf_t *);

ngx_int_t
ngx_supervisord_check_servers(ngx_http_request_t *or)
{
    ngx_http_upstream_srv_conf_t  *uscf;
    ngx_supervisord_srv_conf_t    *supcf;
    ngx_supervisord_queued_req_t  *qr;
    ngx_uint_t                     tr;
    ngx_int_t                      rc;

    if ((or->upstream == NULL) || (or->upstream->conf == NULL)
        || (or->upstream->conf->upstream == NULL))
    {
        goto wrong_params;
    }

    uscf = ngx_http_get_module_srv_conf(or->upstream->conf->upstream,
                                        ngx_http_upstream_module);
    if (uscf == NULL) {
        goto wrong_params;
    }

    supcf = ngx_http_conf_upstream_srv_conf(uscf, ngx_supervisord_module);
    if (supcf == NULL) {
        goto wrong_params;
    }

    if (!supcf->supervisord.is_fake
        && supcf->supervisord.server.url.data == NULL)
    {
        /*
         * allow ngx_supervisord-enabled modules to work
         * even when supervisord is not configured.
         */
        return NGX_OK;
    }

    ngx_supervisord_sync_servers(supcf);

    ngx_shmtx_lock(&supcf->shpool->mutex);
    tr = ++(*supcf->total_reqs);
    ngx_shmtx_unlock(&supcf->shpool->mutex);

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
        "[supervisord] upstream: %V, checking servers, up: %ui/%ui req#: %ui",
        &supcf->uscf->host, supcf->aservers, supcf->nservers, tr);

    if (supcf->aservers > 0 || supcf->supervisord.is_fake) {
        return NGX_OK;
    }

    qr = ngx_pcalloc(supcf->lpool, sizeof(ngx_supervisord_queued_req_t));
    if (qr == NULL) {
        return NGX_ERROR;
    }

    qr->request = or;

    if (supcf->lservers[0] == NGX_SUPERVISORD_SRV_STARTING_UP) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "[supervisord] upstream: %V, no alive backends, queuing request...",
            &supcf->uscf->host);

        /* add timer for first request queued on non-initializing process */
        if (ngx_queue_empty(&supcf->queue)) {
            ngx_add_timer(&supcf->queue_timer, NGX_SUPERVISORD_QUEUE_INTERVAL);
        }

        ngx_queue_insert_tail(&supcf->queue, &qr->queue);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "[supervisord] upstream: %V, no alive backends, starting one...",
            &supcf->uscf->host);

        ngx_queue_insert_tail(&supcf->queue, &qr->queue);

        rc = ngx_supervisord_execute(uscf, NGX_SUPERVISORD_CMD_START, 0, NULL);
        if (rc != NGX_OK) {
            ngx_queue_remove(&qr->queue);

            return rc;
        }
    }

    return NGX_BUSY;

wrong_params:
    ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                  "[supervisord] wrong parameters passed to: %s", __func__);

    return NGX_DECLINED;
}

void
ngx_supervisord_fake_execute(ngx_uint_t cmd, ngx_uint_t backend,
    ngx_http_request_t *r)
{
    ngx_supervisord_srv_conf_t  *supcf;
    ngx_supervisord_ctx_t       *ctx;

    supcf = ngx_http_get_module_srv_conf(r, ngx_supervisord_module);
    ctx = ngx_http_get_module_ctx(r, ngx_supervisord_module);

    ctx->command = cmd;
    ctx->backend = backend;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[supervisord] upstream: %V, backend: %ui, command: %s",
                   &supcf->uscf->host, backend,
                   ngx_supervisord_get_command(cmd));

    ngx_supervisord_finalize_request(r, 0);
}

void
ngx_supervisord_real_execute(ngx_uint_t cmd, ngx_uint_t backend,
    ngx_http_request_t *r)
{
    ngx_supervisord_ctx_t       *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_supervisord_module);
    ctx->command = cmd;
    ctx->backend = backend;

    ngx_http_upstream_init(r);
}

void
ngx_supervisord_cmd_checker(ngx_event_t *ev)
{
    ngx_connection_t              *dummy = ev->data;
    ngx_supervisord_queued_cmd_t  *qcmd = dummy->data;
    ngx_pool_t                    *pool;
    ngx_int_t                      rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                  "[supervisord] upstream: %V, executing checker...",
                  &qcmd->supcf->uscf->host);
    rc = qcmd->checker(qcmd->supcf->uscf, qcmd->backend);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                  "[supervisord] upstream: %V, checker rc: %i",
                  &qcmd->supcf->uscf->host, rc);

    if (rc != NGX_OK) {
        ngx_add_timer(ev, NGX_SUPERVISORD_QUEUE_INTERVAL);
        return;
    }

    if (qcmd->supcf->supervisord.is_fake) {
        ngx_supervisord_fake_execute(qcmd->command, qcmd->backend,
                                     qcmd->request);
    } else {
        ngx_supervisord_real_execute(qcmd->command, qcmd->backend,
                                     qcmd->request);
    }

    pool = qcmd->supcf->lpool;
    (void) ngx_pfree(pool, qcmd);
    (void) ngx_pfree(pool, dummy);
    (void) ngx_pfree(pool, ev);
}

ngx_int_t
ngx_supervisord_execute(ngx_http_upstream_srv_conf_t *uscf,
    ngx_uint_t cmd, ngx_int_t backend, ngx_supervisord_checker_pt checker)
{
    ngx_supervisord_srv_conf_t    *supcf;
    ngx_supervisord_queued_cmd_t  *qcmd;
    ngx_http_request_t            *r;
    ngx_connection_t              *c, *dummy;
    ngx_event_t                   *timer;
    ngx_uint_t                     i;
    ngx_int_t                      rc;

    if (uscf == NULL) {
        goto wrong_params;
    }

    supcf = ngx_http_conf_upstream_srv_conf(uscf, ngx_supervisord_module);
    if (supcf == NULL) {
        goto wrong_params;
    }

    if (!supcf->supervisord.is_fake
        && supcf->supervisord.server.url.data == NULL)
    {
        /*
         * allow ngx_supervisord-enabled modules to work
         * even when supervisord is not configured.
         */
        return NGX_OK;
    }

    if ((backend >= (ngx_int_t) supcf->nservers) || (backend < -1)) {
        goto wrong_params;
    }

    if (cmd > NGX_SUPERVISORD_CMD_STOP) {
        goto wrong_params;
    }

    r = ngx_supervisord_init(supcf->lpool, uscf);
    if (r == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&supcf->shpool->mutex);

    if ((backend == -1)
        && (*supcf->last_cmd + NGX_SUPERVISORD_ANTISPAM > ngx_current_msec))
    {
        /* antispam for "-1" */
        goto already_done;
    }

    switch (cmd) {
    case NGX_SUPERVISORD_CMD_START:
        if (backend == -1) {
            for (i = 0; i < supcf->nservers; i++) {
                if (supcf->shservers[i] == NGX_SUPERVISORD_SRV_STARTING_UP) {
                    /* "-1" allowed only when nothing happens */
                    goto already_done;
                } else if (supcf->shservers[i] == NGX_SUPERVISORD_SRV_DOWN) {
                    backend = i;
                    break;
                }
            }

            if (backend == -1) {
                /* no available backends */
                goto already_done;
            }
        } else if ((supcf->shservers[backend] == NGX_SUPERVISORD_SRV_UP)
            || (supcf->shservers[backend] == NGX_SUPERVISORD_SRV_STARTING_UP))
        {
            /* command already executed on this backend */
            goto already_done;
        }

        supcf->shservers[backend] = NGX_SUPERVISORD_SRV_STARTING_UP;
        *supcf->last_cmd = ngx_current_msec;
        break;
    case NGX_SUPERVISORD_CMD_STOP:
        if (backend == -1) {
            for (i = 0; i < supcf->nservers; i++) {
                if (supcf->shservers[i] == NGX_SUPERVISORD_SRV_SHUTTING_DOWN) {
                    /* "-1" allowed only when nothing happens */
                    goto already_done;
                } else if (supcf->shservers[i] == NGX_SUPERVISORD_SRV_UP) {
                    backend = i;
                    break;
                }
            }

            if (backend == -1) {
                /* no available backends */
                goto already_done;
            }
        } else if ((supcf->shservers[backend] == NGX_SUPERVISORD_SRV_DOWN)
            || (supcf->shservers[backend] == NGX_SUPERVISORD_SRV_SHUTTING_DOWN))
        {
            /* command already executed on this backend */
            goto already_done;
        }

        supcf->shservers[backend] = NGX_SUPERVISORD_SRV_SHUTTING_DOWN;
        *supcf->last_cmd = ngx_current_msec;
        break;
    default:
        ngx_shmtx_unlock(&supcf->shpool->mutex);

        c = r->connection;
        ngx_destroy_pool(r->pool);
        ngx_destroy_pool(c->pool);
        (void) ngx_pfree(supcf->lpool, c);

        goto wrong_params;
    }

    ngx_shmtx_unlock(&supcf->shpool->mutex);

    if (checker != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                      "[supervisord] upstream: %V, executing checker...",
                      &uscf->host);
        rc = checker(uscf, (ngx_uint_t) backend);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                      "[supervisord] upstream: %V, checker rc: %i",
                      &uscf->host, rc);

        if (rc != NGX_OK) {
            qcmd = ngx_pcalloc(supcf->lpool,
                               sizeof(ngx_supervisord_queued_cmd_t));
            if (qcmd == NULL) {
                return NGX_ERROR;
            }

            qcmd->supcf = supcf;
            qcmd->request = r;
            qcmd->command = cmd;
            qcmd->backend = (ngx_uint_t) backend;
            qcmd->checker = checker;

            dummy = ngx_pcalloc(supcf->lpool, sizeof(ngx_connection_t));
            if (dummy == NULL) {
                return NGX_ERROR;
            }

            dummy->fd = (ngx_socket_t) -1;
            dummy->data = qcmd;

            timer = ngx_pcalloc(supcf->lpool, sizeof(ngx_event_t));
            if (timer == NULL) {
                return NGX_ERROR;
            }

            timer->log = ngx_cycle->log;
            timer->data = dummy;
            timer->handler = ngx_supervisord_cmd_checker;

            ngx_add_timer(timer, NGX_SUPERVISORD_QUEUE_INTERVAL);
 
            return NGX_OK;
        }
    }

    if (supcf->supervisord.is_fake) {
        ngx_supervisord_fake_execute(cmd, (ngx_uint_t) backend, r);
    } else {
        ngx_supervisord_real_execute(cmd, (ngx_uint_t) backend, r);
    }

    return NGX_OK;

wrong_params:
    ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                  "[supervisord] wrong parameters passed to: %s", __func__);

    return NGX_DECLINED;

already_done:
    /* same command already in progress or finished */
    ngx_shmtx_unlock(&supcf->shpool->mutex);

    /* internal request? */
    if ((!ngx_queue_empty(&supcf->queue)) && (!supcf->queue_timer.timer_set)) {
        ngx_add_timer(&supcf->queue_timer, NGX_SUPERVISORD_QUEUE_INTERVAL);
    }

    c = r->connection;
    ngx_destroy_pool(r->pool);
    ngx_destroy_pool(c->pool);
    (void) ngx_pfree(supcf->lpool, c);

    return NGX_OK;
}

ngx_int_t
ngx_supervisord_add_backend_monitor(ngx_http_upstream_srv_conf_t *uscf,
    ngx_supervisord_backend_pt monitor)
{
    ngx_supervisord_srv_conf_t  *supcf;
    ngx_uint_t  i;

    if (monitor == NULL) {
        goto wrong_params;
    }

    supcf = ngx_http_conf_upstream_srv_conf(uscf, ngx_supervisord_module);
    if (supcf == NULL) {
        goto wrong_params;
    }
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[supervisord] upstream: %V, adding backend monitor",
                   &uscf->host);

    supcf->backend_monitor = monitor;

    /* nservers > 0 only after module_init */
    for (i = 0; i < supcf->nservers; i++) {
        monitor(uscf, i, supcf->lservers[i]);
    }

    return NGX_OK;

wrong_params:
    ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                  "[supervisord] wrong parameters passed to: %s", __func__);

    return NGX_ERROR;
}

ngx_int_t
ngx_supervisord_add_load_monitor(ngx_http_upstream_srv_conf_t *uscf,
    ngx_supervisord_load_pt monitor)
{
    ngx_supervisord_srv_conf_t  *supcf;

    if (monitor == NULL) {
        goto wrong_params;
    }

    supcf = ngx_http_conf_upstream_srv_conf(uscf, ngx_supervisord_module);
    if (supcf == NULL) {
        goto wrong_params;
    }
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[supervisord] upstream: %V, adding load monitor",
                   &uscf->host);

    supcf->load_monitor = monitor;

    return NGX_OK;

wrong_params:
    ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                  "[supervisord] wrong parameters passed to: %s", __func__);

    return NGX_ERROR;
}

/*
 * nginx <> supervisord communication
 */

typedef struct {
    ngx_uint_t        id;
    const char       *name;
} ngx_supervisord_cmd_t;


static ngx_supervisord_cmd_t  ngx_supervisord_commands[] =
{
    { NGX_SUPERVISORD_CMD_START, "startProcess" },
    { NGX_SUPERVISORD_CMD_STOP,  "stopProcess" },
    { 0, NULL }
};

static char  ngx_supervisord_headers[] =
"POST /RPC2 HTTP/1.0" CRLF
"Accept: text/xml" CRLF
"Content-Type: text/xml" CRLF
"User-Agent: ngx_supervisord" CRLF
"Content-Length: "
;

static char  ngx_supervisord_auth_header[] =
"Authorization: Basic "
;

static char  ngx_supervisord_body_p1[] =
"<?xml version='1.0'?>\n"
"<methodCall>\n"
"<methodName>supervisor."
;

static char  ngx_supervisord_body_p2[] =
"</methodName>\n"
"<params>\n"
"<param>\n"
"<value><string>"
;

static char  ngx_supervisord_body_p3[] =
"</string></value>\n"
"</param>\n"
"</params>\n"
"</methodCall>\n"
;

ngx_int_t
ngx_supervisord_peer_get(ngx_peer_connection_t *pc, void *data)
{
    ngx_url_t  *supervisord = data;
    ngx_int_t   n;

    n = supervisord->naddrs - pc->tries--;

    pc->sockaddr = supervisord->addrs[n].sockaddr;
    pc->socklen  = supervisord->addrs[n].socklen;
    pc->name     = &supervisord->addrs[n].name;

    return NGX_OK;
}

void
ngx_supervisord_peer_free(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    return;
}

ngx_int_t
ngx_supervisord_peer_init(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_supervisord_srv_conf_t  *supcf;

    supcf = ngx_http_get_module_srv_conf(r, ngx_supervisord_module);

    r->upstream->peer.get   = ngx_supervisord_peer_get;
    r->upstream->peer.free  = ngx_supervisord_peer_free;
    r->upstream->peer.tries = supcf->supervisord.server.naddrs;
    r->upstream->peer.data  = &supcf->supervisord.server;

    return NGX_OK;
}

size_t
int_strlen(ngx_uint_t n)
{
    size_t s = 1;

    while (n >= 10) {
        n /= 10;
        s++;
    }

    return s;
}

const char *
ngx_supervisord_get_command(ngx_uint_t id)
{
    ngx_supervisord_cmd_t  *cmd;

    cmd = ngx_supervisord_commands;
    while (cmd->name != NULL) {
        if (cmd->id == id) {
            return cmd->name;
        }

        cmd++;
    }

    return NULL;
}

ngx_int_t
ngx_supervisord_create_request(ngx_http_request_t *r)
{
    ngx_http_upstream_srv_conf_t  *uscf;
    ngx_supervisord_srv_conf_t    *supcf;
    ngx_supervisord_ctx_t         *ctx;
    ngx_str_t                      auth;
    ngx_buf_t                     *b;
    ngx_chain_t                   *cl;
    const char                    *cmd;
    u_char                        *backend;
    size_t                         len, blen;

    supcf = ngx_http_get_module_srv_conf(r, ngx_supervisord_module);
    uscf = supcf->uscf; /* original uscf */
    ctx = ngx_http_get_module_ctx(r, ngx_supervisord_module);

    cmd = ngx_supervisord_get_command(ctx->command);
    if (cmd == NULL) {
        goto failed;
    }

    if (supcf->supervisord.name.data != NULL) {
        len = supcf->supervisord.name.len + int_strlen(ctx->backend) + 1;
    } else {
        len = uscf->host.len + int_strlen(ctx->backend) + 1;
    }

    backend = ngx_palloc(r->pool, len);
    if (backend == NULL) {
        goto failed;
    }

    /* ngx_snprintf *IS NOT* snprintf compatible */
    if (supcf->supervisord.name.data != NULL) {
        (void) ngx_snprintf(backend, len - 1, "%V%i",
                            &supcf->supervisord.name, ctx->backend);
    } else {
        (void) ngx_snprintf(backend, len - 1, "%V%i",
                            &uscf->host, ctx->backend);
    }

    backend[len - 1] = '\0';
    
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[supervisord] upstream: %V, backend: %ui, command: %s",
                   &uscf->host, ctx->backend, cmd);

    /* request body length */
    blen = sizeof(ngx_supervisord_body_p1) - 1
         + sizeof(ngx_supervisord_body_p2) - 1
         + sizeof(ngx_supervisord_body_p3) - 1
         + ngx_strlen(cmd) + ngx_strlen(backend);

    /* request length */
    len = sizeof(ngx_supervisord_headers) - 1
        + int_strlen(blen) + 2 * sizeof(CRLF) + blen;

    /* optional authorization */
    if (supcf->supervisord.userpass.data != NULL) {
        auth.len = ngx_base64_encoded_length(supcf->supervisord.userpass.len);
        auth.data = ngx_palloc(r->pool, auth.len + 2 * sizeof(CRLF));
        if (auth.data == NULL) {
            goto failed;
        }

        ngx_encode_base64(&auth, &supcf->supervisord.userpass);

        auth.data[auth.len++] = CR;
        auth.data[auth.len++] = LF;
        auth.data[auth.len++] = CR;
        auth.data[auth.len++] = LF;

        len += sizeof(ngx_supervisord_auth_header) + auth.len;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        goto failed;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        goto failed;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    b->last = ngx_cpymem(b->last, ngx_supervisord_headers,
                         sizeof(ngx_supervisord_headers) - 1);

    if (supcf->supervisord.userpass.data != NULL) {
        b->last = ngx_sprintf(b->last, "%i" CRLF, blen);
        b->last = ngx_cpymem(b->last, ngx_supervisord_auth_header,
                             sizeof(ngx_supervisord_auth_header) - 1);
        b->last = ngx_cpymem(b->last, auth.data, auth.len);
    } else {
        b->last = ngx_sprintf(b->last, "%i" CRLF CRLF, blen);
    }

    b->last = ngx_cpymem(b->last, ngx_supervisord_body_p1,
                         sizeof(ngx_supervisord_body_p1) - 1);
    b->last = ngx_cpymem(b->last, cmd, ngx_strlen(cmd));
    b->last = ngx_cpymem(b->last, ngx_supervisord_body_p2,
                         sizeof(ngx_supervisord_body_p2) - 1);
    b->last = ngx_cpymem(b->last, backend, ngx_strlen(backend));
    b->last = ngx_cpymem(b->last, ngx_supervisord_body_p3,
                         sizeof(ngx_supervisord_body_p3) - 1);

    b->last_buf = 1;

    /* force nginx to read whole response into memory */
    r->subrequest_in_memory = 1;

    return NGX_OK;

failed:
    r->connection->error = 1;

    return NGX_ERROR;
}

ngx_int_t
ngx_supervisord_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

ngx_int_t
ngx_supervisord_process_header(ngx_http_request_t *r)
{
    return NGX_OK;
}

void
ngx_supervisord_abort_request(ngx_http_request_t *r)
{
    return;
}

ngx_int_t
ngx_supervisord_parse_response(ngx_buf_t *buf, ngx_str_t *host)
{
    char       *str = (char *) buf->start;
    char       *sep;
    ngx_int_t   code;

    /* just in case */
    *buf->last = '\0';

    if (strncmp(str, "HTTP/1.0 401 ", strlen("HTTP/1.0 401 ")) == 0) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                      "[supervisord] upstream: %V, unauthorized connection",
                      host);

        return NGX_ERROR;
    }

    while ((sep = strsep(&str, "<")) != NULL) {
        if (strncmp(sep, "methodResponse", strlen("methodResponse")) == 0) {
            goto valid_reply;
        } 
    }

    return NGX_ERROR;

valid_reply:
    if ((sep = strsep(&str, "<")) == NULL) {
        return NGX_ERROR;
    }

    if (strncmp(sep, "fault", strlen("fault")) == 0) {
        goto fault;
    } else if (strncmp(sep, "params", strlen("params")) == 0) {
        return NGX_OK;
    }

    return NGX_ERROR;

fault:
    while ((sep = strsep(&str, "<")) != NULL) {
        if (strncmp(sep, "int>", strlen("int>")) == 0) {
            code = 0;
            sep += strlen("int>");

            while ((*sep >= '0') && (*sep <= '9')) {
                code *= 10;
                code += *sep++ - '0';
            }

            return code;
        }
    }

    return NGX_OK;
}

void
ngx_supervisord_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_supervisord_srv_conf_t    *supcf;
    ngx_supervisord_ctx_t         *ctx;
    ngx_int_t                      suprc;

    supcf = ngx_http_get_module_srv_conf(r, ngx_supervisord_module);
    ctx = ngx_http_get_module_ctx(r, ngx_supervisord_module);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[supervisord] upstream: %V, finalizing request, rc: %i",
                   &supcf->uscf->host, rc);

    if (supcf->supervisord.is_fake) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[supervisord] upstream: %V, response: %i none",
                       &supcf->uscf->host, rc);
        goto skip_fake;
    }

    if (rc != 0) {
        if (rc == 502) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                "[supervisord] upstream: %V, couldn't connect to supervisord",
                &supcf->uscf->host);
        }

        goto failed;
    }

    /* just in case overwrite last char, it should be '\n' anyway */
    *r->upstream->buffer.last = '\0';

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[supervisord] upstream: %V, response: %s",
                   &supcf->uscf->host, r->upstream->buffer.start);

    rc = ngx_supervisord_parse_response(&r->upstream->buffer,
                                        &supcf->uscf->host);
    suprc = rc;

    if ((rc == 60) && (ctx->command == NGX_SUPERVISORD_CMD_START)) {
        /* already started */
        rc = 0;
    } else if ((rc == 70) && (ctx->command == NGX_SUPERVISORD_CMD_STOP)) {
        /* not running */
        rc = 0;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[supervisord] upstream: %V, response: %i %i",
                   &supcf->uscf->host, rc, suprc);

    if (rc != 0) {
        goto failed;
    }

skip_fake:
    ngx_shmtx_lock(&supcf->shpool->mutex);

    switch (ctx->command) {
    case NGX_SUPERVISORD_CMD_START:
        if (supcf->shservers[ctx->backend] == NGX_SUPERVISORD_SRV_STARTING_UP) {
            supcf->shservers[ctx->backend] = NGX_SUPERVISORD_SRV_UP;
        }
        break;
    case NGX_SUPERVISORD_CMD_STOP:
        if (supcf->shservers[ctx->backend]
             == NGX_SUPERVISORD_SRV_SHUTTING_DOWN)
        {
            supcf->shservers[ctx->backend] = NGX_SUPERVISORD_SRV_DOWN;
        }
        break;
    }

    ngx_shmtx_unlock(&supcf->shpool->mutex);

    if ((ctx->command == NGX_SUPERVISORD_CMD_START) && (ctx->backend == 0)) {
        (void) ngx_supervisord_resume_requests(supcf);
    }

    /* disable further "less-than-important" logging... */
    r->connection->log->log_level = NGX_LOG_EMERG;

    return;

failed:
    ngx_shmtx_lock(&supcf->shpool->mutex);

    switch (ctx->command) {
    case NGX_SUPERVISORD_CMD_START:
        if (supcf->shservers[ctx->backend] == NGX_SUPERVISORD_SRV_STARTING_UP) {
            supcf->shservers[ctx->backend] = NGX_SUPERVISORD_SRV_DOWN;
        }
        break;
    case NGX_SUPERVISORD_CMD_STOP:
        if (supcf->shservers[ctx->backend]
             == NGX_SUPERVISORD_SRV_SHUTTING_DOWN)
        {
            supcf->shservers[ctx->backend] = NGX_SUPERVISORD_SRV_UP;
        }
        break;
    }

    ngx_shmtx_unlock(&supcf->shpool->mutex);

    if (ctx->backend == 0) {
        (void) ngx_supervisord_resume_requests(supcf);
    }

    /* stop nginx from sending special response over "fake connection" */
    r->connection->error = 1;

    /* disable further "less-than-important" logging... */
    r->connection->log->log_level = NGX_LOG_EMERG;
}

ngx_chain_t *
ngx_supervisord_send_chain(ngx_connection_t *c, ngx_chain_t *in,  off_t limit)
{
    return NULL;
}

ngx_http_request_t *
ngx_supervisord_init(ngx_pool_t *pool, ngx_http_upstream_srv_conf_t *ouscf)
{
    ngx_connection_t              *c;
    ngx_http_request_t            *r;
    ngx_log_t                     *log;
    ngx_http_log_ctx_t            *ctx;
    ngx_http_upstream_t           *u;
    ngx_http_upstream_conf_t      *ucf;
    ngx_http_upstream_srv_conf_t  *uscf;

    /* fake incoming connection */
    c = ngx_pcalloc(pool, sizeof(ngx_connection_t));
    if (c == NULL) {
        goto failed_none;
    }

    c->pool = ngx_create_pool(1024, ngx_cycle->log);
    if (c->pool == NULL) {
        goto failed_none;
    }

    log = ngx_pcalloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        goto failed_conn;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_http_log_ctx_t));
    if (ctx == NULL) {
        goto failed_conn;
    }

    /* fake incoming request */
    r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        goto failed_conn;
    }

    r->pool = ngx_create_pool(8192, ngx_cycle->log);
    if (r->pool == NULL) {
        goto failed_conn;
    }

    ctx->connection = c;
    ctx->request = r;
    ctx->current_request = r;

    log->action = "initializing fake request";
    log->data = ctx;
    log->file = ngx_cycle->new_log.file;
    log->log_level = NGX_LOG_DEBUG_CONNECTION
                   | NGX_LOG_DEBUG_ALL;

    c->log = log;
    c->log_error = NGX_ERROR_INFO;
    c->pool->log = log;
    r->pool->log = log;

    c->fd = -1;
    c->data = r;

    c->send_chain = ngx_supervisord_send_chain;

    r->main = r;
    r->connection = c;

#if (nginx_version >= 8011)
    r->count = 1;
#endif

    /* used by ngx_http_upstream_init */
    c->read = ngx_pcalloc(c->pool, sizeof(ngx_event_t));
    if (c->read == NULL) {
        goto failed_conn;
    }

    c->read->log = log;

    c->write = ngx_pcalloc(c->pool, sizeof(ngx_event_t));
    if (c->write == NULL) {
        goto failed_conn;
    }

    c->write->log = log;
    c->write->active = 1;

    /* used by ngx_http_log_request */
    r->main_conf = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->main_conf == NULL) {
        goto failed_req;
    }

    r->main_conf[ngx_http_core_module.ctx_index] =
        ngx_pcalloc(r->pool, sizeof(ngx_http_core_main_conf_t));
    if (r->main_conf[ngx_http_core_module.ctx_index] == NULL) {
        goto failed_req;
    }

    /* use original servers{}'s configuration for this module */
    r->srv_conf = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->srv_conf == NULL) {
        goto failed_req;
    }

    r->srv_conf[ngx_http_upstream_module.ctx_index] =
        ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_srv_conf_t));
    if (r->srv_conf[ngx_http_upstream_module.ctx_index] == NULL) {
        goto failed_req;
    }

    uscf = r->srv_conf[ngx_http_upstream_module.ctx_index];
    uscf->srv_conf = r->srv_conf;

    uscf->peer.init = ngx_supervisord_peer_init;

    r->srv_conf[ngx_supervisord_module.ctx_index] =
        ouscf->srv_conf[ngx_supervisord_module.ctx_index];
    if (r->srv_conf[ngx_supervisord_module.ctx_index] == NULL) {
        goto failed_req;
    }

    /* used by ngx_http_copy_filter */
    r->loc_conf = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->loc_conf == NULL) {
        goto failed_req;
    }

    r->loc_conf[ngx_http_core_module.ctx_index] =
        ngx_pcalloc(r->pool, sizeof(ngx_http_core_loc_conf_t));
    if (r->loc_conf[ngx_http_core_module.ctx_index] == NULL) {
        goto failed_req;
    }

    r->loc_conf[ngx_http_copy_filter_module.ctx_index] =
        ngx_pcalloc(r->pool, sizeof(ngx_int_t) + sizeof(size_t));
    if (r->loc_conf[ngx_http_copy_filter_module.ctx_index] == NULL) {
        goto failed_req;
    }

    /* used by ngx_http_output_filter */
    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        goto failed_req;
    }

    r->ctx[ngx_supervisord_module.ctx_index] =
        ngx_pcalloc(r->pool, sizeof(ngx_supervisord_ctx_t));
    if (r->ctx[ngx_supervisord_module.ctx_index] == NULL) {
        goto failed_req;
    }

    /* used by ngx_http_upstream_init */
    if (ngx_http_upstream_create(r) != NGX_OK) {
        goto failed_req;
    }

    u = r->upstream;

    u->create_request = ngx_supervisord_create_request;
    u->reinit_request = ngx_supervisord_reinit_request;
    u->process_header = ngx_supervisord_process_header;
    u->abort_request = ngx_supervisord_abort_request;
    u->finalize_request = ngx_supervisord_finalize_request;

    u->schema.len = sizeof("supervisord://") - 1;
    u->schema.data = (u_char *) "supervisord://";
    
    u->peer.log = log;
    u->peer.log_error = NGX_ERROR_ERR;

    u->output.tag = (ngx_buf_tag_t) &ngx_supervisord_module;

    /* configure upstream */
    u->conf = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_conf_t));
    if (u->conf == NULL) {
        goto failed_req;
    }

    ucf = u->conf;

    /* must be enough to hold supervisord's response */
    ucf->buffer_size     = 2048;

    ucf->connect_timeout = 5000;
    ucf->read_timeout    = 30000;
    ucf->send_timeout    = 30000;

    ucf->next_upstream = NGX_HTTP_UPSTREAM_FT_ERROR
                       | NGX_HTTP_UPSTREAM_FT_TIMEOUT;

    ucf->upstream = uscf;

    return r;

failed_req:
    ngx_destroy_pool(r->pool);

failed_conn:
    ngx_destroy_pool(c->pool);

failed_none:
    (void) ngx_pfree(pool, c);

    return NULL;
}

/*
 * ngx_supervisord handlers
 */

static char  ngx_supervisord_success_page_top[] =
"<html>" CRLF
"<head><title>Command executed successfully</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>Command executed successfully</h1>" CRLF
;

static char  ngx_supervisord_success_page_tail[] =
CRLF "</center>" CRLF
"<hr><center>" NGINX_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;

u_char *
ngx_strlrchr(u_char *p, u_char *last, u_char c)
{
    while (p <= last) {
        if (*last == c) {
            return last;
        }

        last--;
    }

    return NULL;
}

ngx_int_t
ngx_supervisord_command_handler(ngx_http_request_t *r)
{
    ngx_supervisord_loc_conf_t  *suplcf;
    u_char                      *p, *last;
    ngx_int_t                    backend, rc;
    ngx_chain_t                  out;
    ngx_buf_t                   *b;
    const char                  *cmd;
    size_t                       len;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    suplcf = ngx_http_get_module_loc_conf(r, ngx_supervisord_module);
    if (!suplcf->upstream) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = r->uri.data + r->uri.len - 1;
    p = ngx_strlrchr(r->uri.data, last, '/');
    p++;

    if (ngx_strncmp(p, "any", 3) == 0) {
        backend = -1;
    } else {
        backend = ngx_atoi(p, last - p + 1);
        if (backend == NGX_ERROR) {
            return NGX_HTTP_NOT_FOUND;
        }
    }

    if (backend >= (ngx_int_t) suplcf->upstream->servers->nelts) {
        return NGX_HTTP_NOT_FOUND;
    }

    cmd = ngx_supervisord_get_command(suplcf->command);
    if (cmd == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_supervisord_execute(suplcf->upstream, suplcf->command, backend, NULL);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof(ngx_supervisord_success_page_top) - 1
        + sizeof(ngx_supervisord_success_page_tail) - 1
        + sizeof("<br>Command: ") - 1 + sizeof(CRLF "<br>Backend: ") - 1
        + ngx_strlen(cmd);

    if (backend == -1) {
        len += 3;
    } else {
        len += int_strlen(backend);
    }

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;

    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_cpymem(b->last, ngx_supervisord_success_page_top,
                         sizeof(ngx_supervisord_success_page_top) - 1);
    b->last = ngx_cpymem(b->last, "<br>Command: ", sizeof("<br>Command: ") - 1);
    b->last = ngx_cpymem(b->last, cmd, ngx_strlen(cmd));
    b->last = ngx_cpymem(b->last, CRLF "<br>Backend: ",
                         sizeof(CRLF "<br>Backend: ") - 1);
    if (backend == -1) {
        b->last = ngx_cpymem(b->last, "any", 3);
    } else {
        b->last = ngx_sprintf(b->last, "%i", backend);
    }
    b->last = ngx_cpymem(b->last, ngx_supervisord_success_page_tail,
                         sizeof(ngx_supervisord_success_page_tail) - 1);
    b->last_buf = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
       return rc;
    }

    return ngx_http_output_filter(r, &out);
}

ngx_http_upstream_srv_conf_t *
ngx_supervisord_find_upstream(ngx_conf_t *cf, ngx_str_t value)
{
    ngx_http_upstream_main_conf_t   *umcf;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_uint_t                       i;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == value.len
            && ngx_strncasecmp(uscfp[i]->host.data, value.data, value.len) == 0)
        {
            return uscfp[i];
        }
    }

    return NULL;
}

char *
ngx_supervisord_conf_start_handler(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                   *value = cf->args->elts;
    ngx_supervisord_loc_conf_t  *suplcf = conf;
    ngx_http_core_loc_conf_t    *clcf;

    if (suplcf->upstream) {
        return "is either duplicate or collides with \"supervisord_stop\"";
    }

    suplcf->upstream = ngx_supervisord_find_upstream(cf, value[1]);
    if (suplcf->upstream == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "supervisord_start refers to non-existing upstream \"%V\"",
            &value[1]);

        return NGX_CONF_ERROR;
    }

    suplcf->command = NGX_SUPERVISORD_CMD_START;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_supervisord_command_handler;

    return NGX_CONF_OK;
}

char *
ngx_supervisord_conf_stop_handler(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                   *value = cf->args->elts;
    ngx_supervisord_loc_conf_t  *suplcf = conf;
    ngx_http_core_loc_conf_t    *clcf;

    if (suplcf->upstream) {
        return "is either duplicate or collides with \"supervisord_start\"";
    }

    suplcf->upstream = ngx_supervisord_find_upstream(cf, value[1]);
    if (suplcf->upstream == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "supervisord_stop refers to non-existing upstream \"%V\"",
            &value[1]);

        return NGX_CONF_ERROR;
    }

    suplcf->command = NGX_SUPERVISORD_CMD_STOP;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_supervisord_command_handler;

    return NGX_CONF_OK;
}
