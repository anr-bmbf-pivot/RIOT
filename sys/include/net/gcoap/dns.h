/*
 * Copyright (C) 2021 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup net_gcoap_dns  DNS over CoAP client implementation
 * @ingroup  net_gcoap
 *
 * @brief   A DNS over CoAP client prototype based on gCoAP.
 *
 * DNS over CoAP allows a node to use a CoAP server to resolve DNS request, following
 * [draft-lenders-dns-over-coap](https://datatracker.ietf.org/doc/draft-lenders-dns-over-coap/).
 *
 * The `gcoap_dns` module does not replace the @ref sock_dns_query function when built, and is not
 * used as a back-end to @ref netutils_get_ipv6 automatically. It does, however, provide a drop-in
 * replacement for @ref sock_dns_query in its @ref gcoap_dns_query function.
 *
 * @{
 *
 * @file
 * @brief   `gcoap_dns` definitions
 *
 * @author  Martine Lenders <m.lenders@fu-berlin.de>
 */
#ifndef NET_GCOAP_DNS_H
#define NET_GCOAP_DNS_H

#include <stdint.h>

#include "mutex.h"
#include "net/credman.h"
#include "net/coap.h"
#include "net/gcoap.h"

#if IS_USED(MODULE_GCOAP_DNS_OSCORE)
#include "oscore/helpers.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup    gcoap_dns_config    GCoAP DNS over CoAP client configuration
 * @ingroup     config
 * @{
 */
/**
 * @brief   maximum length of the URI for the DNS server
 */
#ifndef CONFIG_GCOAP_DNS_SERVER_URI_LEN
#define CONFIG_GCOAP_DNS_SERVER_URI_LEN     64U
#endif

/**
 * @brief   maximum number of credentials that can be added with @ref gcoap_dns_cred_add()
 */
#ifndef CONFIG_GCOAP_DNS_CREDS_MAX
#if IS_USED(MODULE_GCOAP_DTLS) || defined(DOXYGEN)
#define CONFIG_GCOAP_DNS_CREDS_MAX          1U
#else
#define CONFIG_GCOAP_DNS_CREDS_MAX          0U
#endif
#endif

/**
 * @brief   size of the buffer used to build a CoAP request
 */
#ifndef CONFIG_GCOAP_DNS_PDU_BUF_SIZE
#define CONFIG_GCOAP_DNS_PDU_BUF_SIZE       128U
#endif

/**
 * @brief   block-size used for requests (both Block2 control and Block1)
 *
 * Should be less than @ref CONFIG_GCOAP_DNS_PDU_BUF_SIZE or
 * @ref CONFIG_GCOAP_PDU_BUF_SIZE and must be a power
 * of 2
 */
#ifndef CONFIG_GCOAP_DNS_BLOCK_SIZE
#define CONFIG_GCOAP_DNS_BLOCK_SIZE         64U
#endif
/** @} */

/**
 * @brief   Forward type declaration of struct gcoap_dns_ctx
 */
typedef struct gcoap_dns_ctx gcoap_dns_ctx_t;

/**
 * @brief   Callback for asynchronous operation
 *
 * @note    Requires module `gcoap_dns_async` to be used.
 *
 * @param[in] The context for the asynchronous DNS query.
 */
typedef void (*gcoap_dns_async_cb_t)(gcoap_dns_ctx_t *ctx);

/**
 * @brief   Context for a DNS query-response-pair.
 */
struct gcoap_dns_ctx {
    union {
        /**
         * @brief   Synchronization mutex for synchronous use
         */
        mutex_t resp_wait;
        /**
         * @brief   Callback for asynchronous use
         */
        gcoap_dns_async_cb_t cb;
    } sync;                 /**< Synchronization primitives */
    /**
     * @brief The CoAP request packet
     *
     * Only needs to have coap_pkt_t::payload and coap_pkt_t::payload_len
     * initialized.
     */
    coap_pkt_t *pkt;
#if IS_USED(MODULE_DNS_CACHE) || defined(DOXYGEN)
    /**
     * @brief   The queried hostname
     *
     * Only required for DNS caching and thus only available with module @ref net_dns_cache
     */
    const char *domain_name;
#endif
    void *dns_buf;          /**< The buffer for the DNS message exchange */
    void *addr_out;         /**< Pointer to the resulting address */
    /**
     * @brief   Status for the DNS message exchange
     *
     * - length of gcoap_dns_ctx_t::addr_out in bytes on success
     * - -EBADMSG, when receiving erroneous response or response containing
     * - -EDESTADDRREQ, if CoAP response was received from an unexpected remote.
     * - -EINVAL, when block-wise transfer can not be completed.
     * - -ENOBUFS, if length of received CoAP body is greater than
     *   @ref CONFIG_DNS_MSG_LEN.
     * - -ENOMSG, if CoAP response did not contain a DNS response.
     * - -ETIMEDOUT, if CoAP request timed out.
     */
    int res;
#if IS_USED(MODULE_GCOAP_DNS_GET) || IS_USED(MODULE_GCOAP_DNS_POST) || IS_USED(MODULE_GCOAP_DNS_ASYNC)
    uint8_t flags;          /**< Flags */
#endif
    uint8_t dns_buf_len;    /**< Length of gcoap_dns_ctx_t::dns_buf */
    int8_t family;          /**< Address family to resolve */
    /**
     * @brief The current block number for block-wise transfer
     *
     * Leave unset on function call.
     */
    uint8_t cur_blk_num;
#if IS_USED(MODULE_GCOAP_DNS_OSCORE)
    oscore_requestid_t oscore_request_id;
#endif
#if IS_USED(MODULE_GCOAP_DNS_ASYNC) || IS_USED(MODULE_GCOAP_DTLS) || defined(DOXYGEN)
    /**
     * @brief   Request tag to rule out potential request reordering attacks
     *
     * @todo    Also use for OSCORE when using block-wise support for OSCORE
     *          was added
     */
    uint16_t req_tag;
#endif
};

int gcoap_dns_query_method(const char *domain_name, void *addr_out, int family, uint8_t method);

/**
 * @brief   Query a domain name via CoAP synchronously
 *
 * @param[in] domain_name   A '\0'-terminated domain name. Must not be NULL.
 * @param[out] addr_out     The resolved address. Must not be NULL.
 * @param[in] family        The desired address family for @p addr_out.
 *                          @ref AF_UNSPEC for any address family (an IPv6
 *                          address will take preference over an IPv4 address).
 *
 * @return  length of @p addr_out in bytes on success
 * @return  -EAFNOSUPPORT, if the hostname of the URI resolves to an unknown address family.
 * @return  -EBADMSG, when receiving erroneous response or response containing
 *          an error code.
 * @return  -ECONNABORTED, if CoAP request cannot be sent.
 * @return  -ECONNREFUSED, if no URI is set for the client (see @ref gcoap_dns_server_uri_set()).
 * @return  -EDESTADDRREQ, if CoAP response was received from an unexpected
 *          remote.
 * @return  -EHOSTUNREACH, if the hostname of the URI template can not be
 *          resolved
 * @return  -EINVAL, if the URI template was not processable.
 * @return  -ENOBUFS, if there was not enough buffer space for the request.
 * @return  -ENOBUFS, if length of received CoAP body is greater than
 *          @ref CONFIG_DNS_MSG_LEN.
 * @return  -ENOENT, if Zone-ID of the URI can not be found locally.
 * @return  -ENOMSG, if CoAP response did not contain a DNS response.
 * @return  -ENOTRECOVERABLE, on gCoAP-internal error.
 * @return  -ENOTSUP, if credential can not be added for to client.
 * @return  -ETIMEDOUT, if CoAP request timed out.
 */
static inline int gcoap_dns_query(const char *domain_name, void *addr_out, int family)
{
    return gcoap_dns_query_method(domain_name, addr_out, family, COAP_METHOD_FETCH);
}


/**
 * @brief   Query a domain name via CoAP asynchronously
 *
 * @note    Only available with module `gcoap_dns_async` compiled in.
 *
 * @param[in] domain_name   A '\0'-terminated domain name. Must not be NULL.
 * @param[out] addr_out     The resolved address. Must not be NULL.
 * @param[in] family        The desired address family for @p addr_out.
 *                          @ref AF_UNSPEC for any address family (an IPv6
 *                          address will take preference over an IPv4 address).
 *
 * @return  length of @p addr_out in bytes on success
 * @return  -EAFNOSUPPORT, if the hostname of the URI resolves to an unknown address family.
 * @return  -EBADMSG, when receiving erroneous response or response containing
 *          an error code.
 * @return  -ECONNABORTED, if CoAP request cannot be sent.
 * @return  -ECONNREFUSED, if no URI is set for the client (see @ref gcoap_dns_server_uri_set()).
 * @return  -EDESTADDRREQ, if CoAP response was received from an unexpected
 *          remote.
 * @return  -EHOSTUNREACH, if the hostname of the URI template can not be
 *          resolved
 * @return  -EINVAL, if the URI template was not processable.
 * @return  -ENOBUFS, if there was not enough buffer space for the request.
 * @return  -ENOBUFS, if length of received CoAP body is greater than
 *          @ref CONFIG_DNS_MSG_LEN.
 * @return  -ENOENT, if Zone-ID of the URI can not be found locally.
 * @return  -ENOMSG, if CoAP response did not contain a DNS response.
 * @return  -ENOTRECOVERABLE, on gCoAP-internal error.
 * @return  -ENOTSUP, if credential can not be added for to client.
 * @return  -ENOTSUP, if module `gcoap_dns_async` is not compiled in.
 * @return  -ETIMEDOUT, if CoAP request timed out.
 */
int gcoap_dns_query_async(const char *domain_name, gcoap_dns_ctx_t *ctx);

/**
 * @brief   Sets and checks a URI for a DoC server
 *
 * @param[in] uri   A URI. May be NULL to remove the URI.
                    Unless the @ref net_sock_dns module is also used, the host
                    component of the URI needs to be an IP literal.
 *
 * @return  length of @p uri on success (0 when URI is removed).
 * @return  -EINVAL, if @p uri is not a valid URI for DNS over CoAP.
 * @return  -ENOBUFS, if the client implementation has not enough buffer space
 *          to process the URI.
 */
int gcoap_dns_server_uri_set(const char *uri);

/**
 * @brief   Checks if the URI for the DoC server is set.
 *
 * @retval true     A URI for the DoC server is set.
 * @retval false    There is no URI set for the DoC server.
 */
bool gcoap_dns_server_uri_is_set(void);

/**
 * @brief   Gets the URI for the DoC server
 *
 * @param[out] uri      The current URI for the DoC server
 * @param[in] uri_len   Maximum length for @p uri
 *
 * @return  Length of the @p uri on return. 0, if no URI is set.
 * @return  -ENOBUFS, if the configured URI is longer than @p uri_len.
 */
ssize_t gcoap_dns_server_uri_get(char *uri, size_t uri_len);

/**
 * @brief   Deletes all added credentials
 *
 * This also removes the credentials from the @ref net_credman and the GCoAP DTLS sock.
 */
void gcoap_dns_cred_reset(void);

/**
 * @brief   Adds a credential for the use with the configured DoC server.
 *
 * @pre creds != NULL.
 *
 * @param[in] creds     A crential. May not be NULL.
 *
 * @return 0 on success
 * @return -ENOTSUP if DTLS is not supported (because `gcoap_dtls` is not compiled in)
 * @return -ENOMEM if @ref CONFIG_GCOAP_DNS_CREDS_MAX is exceeded (duplicates may be added).
 * @return -EBADF if the credential can not be added to @ref net_credman or the GCoAP DTLS sock.
 */
int gcoap_dns_cred_add(credman_credential_t *creds);

/**
 * @brief   Remove a credential for the use with the configured DoC server
 *
 * This also removes the credentials from the @ref net_credman and the GCoAP DTLS sock.
 *
 * @param[in] tag   The tag of the credential.
 * @param[in] type  The type of the credential.
 */
void gcoap_dns_cred_remove(credman_tag_t tag, credman_type_t type);

/**
 * @brief   Deletes the proxy URI.
 */
void gcoap_dns_server_proxy_reset(void);

/**
 * @brief   Sets and checks a proxy URI.
 *
 * @param[in] proxy     A proxy URI. Must contain a `dns` query variable.
 *
 * @return  length of @p proxy on success.
 * @return  -ENOBUFS, if the client implementation has not enough buffer space
 *          to process the proxy URI.
 * @return  -ENOSUP, if module `gcoap_dns_proxied` is not compiled in.
 */
int gcoap_dns_server_proxy_set(const char *proxy);

/**
 * @brief   Checks if a proxy URI is set.
 *
 * @retval true     A proxy URI is set.
 * @retval false    There is no URI set for the DoC server.
 */
bool gcoap_dns_server_proxy_is_set(void);

/**
 * @brief   Gets the proxy URI
 *
 * @param[out] proxy    The current proxy URI
 * @param[in] proxy_len Maximum length for @p proxy
 *
 * @return  Length of the @p proxy on return. 0, if no URI is set.
 * @return  -ENOBUFS, if the configured URI is longer than @p proxy_len.
 */
ssize_t gcoap_dns_server_proxy_get(char *proxy, size_t proxy_len);

int gcoap_dns_oscore_set_secctx(int64_t alg_num,
                                const uint8_t *sender_id, size_t sender_id_len,
                                const uint8_t *recipient_id, size_t recipient_id_len,
                                const uint8_t *common_iv,
                                const uint8_t *sender_key,
                                const uint8_t *recipient_key);

#ifdef __cplusplus
}
#endif

#endif /* NET_GCOAP_DNS_H */
/** @} */
