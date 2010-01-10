/*
 * Copyright (c) 2009, FRiCKLE Piotr Sikora <info@frickle.com>
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

#ifndef _NGX_SUPERVISORD_H_
#define _NGX_SUPERVISORD_H_

#include <ngx_core.h>

#define NGX_SUPERVISORD_API_VERSION        2

#define NGX_SUPERVISORD_CMD_START          1
#define NGX_SUPERVISORD_CMD_STOP           2

#define NGX_SUPERVISORD_SRV_UP             0 /* peer.down == 0 */
#define NGX_SUPERVISORD_SRV_DOWN           1 /* peer.down != 0 && == 1 */
#define NGX_SUPERVISORD_SRV_STARTING_UP    2 /* peer.down != 0 */
#define NGX_SUPERVISORD_SRV_SHUTTING_DOWN  3 /* peer.down != 0 */

#define NGX_SUPERVISORD_LOAD_MULTIPLIER  100

/*
 * ngx_supervisord_check_servers:
 * This function should be called at the end of peer.init() instead of
 * returning NGX_OK. It halts processing of the request when all backends
 * are down and resumes it after starting first one:
 *
 * Parameters:
 * r            - incoming request.
 *
 * Return values:
 * NGX_OK       - at least 1 server is active,
 * NGX_BUSY     - no active servers,
 * NGX_DECLINED - wrong parameters,
 * NGX_ERROR    - internal nginx error.
 */
ngx_int_t           ngx_supervisord_check_servers(ngx_http_request_t *r);

/*
 * ngx_supervisord_execute:
 * Try to execute supervisord's command.
 *
 * Parameters:
 * uscf         - upstream{}'s server configuration,
 * cmd          - NGX_SUPERVISORD_CMD_* command,
 * backend      - backend number (from original servers list),
 *                value -1 means "first available".
 * checker      - *OPTIONAL* function, which must return NGX_OK before
 *                ngx_supervisord will try to send command to supervisord.
 *
 * Return values:
 * NGX_OK       - command queued successfully.
 * NGX_DECLINED - wrong parameters,
 * NGX_ERROR    - internal nginx error.
 *
 * IMPORTANT NOTE:
 * Returned NGX_OK *DOES NOT* mean that the command was completed,
 * it means that request was processed successfully by ngx_supervisord.
 */
typedef ngx_int_t (*ngx_supervisord_checker_pt)(
                        ngx_http_upstream_srv_conf_t *uscf,
                        ngx_uint_t backend);

ngx_int_t           ngx_supervisord_execute(
                        ngx_http_upstream_srv_conf_t *uscf,
                        ngx_uint_t cmd,
                        ngx_int_t backend,
                        ngx_supervisord_checker_pt checker);

/*
 * ngx_supervisord_add_backend_monitor:
 * Register callback function, which will be invoked after every change
 * in status of backend server.
 *
 * Parameters:
 * uscf    - upstream{}'s server configuration,
 * cb      - callback function.
 *
 * IMPORTANT NOTE:
 * Callback function shouldn't do more than update status of backend server
 * in its internal list. It *MUST NOT* resume processing of any requests.
 */
typedef void      (*ngx_supervisord_backend_pt)(
                        ngx_http_upstream_srv_conf_t *uscf, 
                        ngx_uint_t backend,
                        ngx_uint_t new_status);

ngx_int_t           ngx_supervisord_add_backend_monitor(
                        ngx_http_upstream_srv_conf_t *uscf,
                        ngx_supervisord_backend_pt cb);

/*
 * ngx_supervisord_add_load_monitor:
 * Register callback function, which will be invoked periodically
 * with informations about current load.
 *
 * Parameters:
 * uscf    - upstream{}'s server configuration,
 * cb      - callback function.
 */
typedef struct {
    ngx_uint_t  load;     /* requests per second per active backend */
    ngx_uint_t  reqs;     /* requests since last load report */
    ngx_msec_t  interval; /* interval between load reports */
    ngx_uint_t  aservers; /* number of currently active upstream servers */
    ngx_uint_t  nservers; /* total number of configured upstream servers */
} ngx_supervisord_load_t;

typedef void      (*ngx_supervisord_load_pt)(
                        ngx_http_upstream_srv_conf_t *uscf,
                        ngx_supervisord_load_t load);

ngx_int_t           ngx_supervisord_add_load_monitor(
                        ngx_http_upstream_srv_conf_t *uscf,
                        ngx_supervisord_load_pt cb);

#endif /* !_NGX_SUPERVISORD_H_ */
