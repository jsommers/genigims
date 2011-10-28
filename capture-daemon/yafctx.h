/*
 * yafctx.h from yaf source tree
 * part of the GIMS GENI project.
 * 
 * This source code is licensed under the GENI public license.
 * See www.geni.net, or "geni_public_license.txt" that should 
 * have accompanied this software.
 */

#include "config.h"
#ifdef HAVE_YAF

/*
 ** yafctx.h
 ** YAF configuration 
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2008 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell <bht@cert.org>
 ** ------------------------------------------------------------------------
 ** GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.225-7013
 ** ------------------------------------------------------------------------
 */

#ifndef _YAF_CTX_H_
#define _YAF_CTX_H_

#include <yaf/autoinc.h>
#include <yaf/yaftab.h>
#include <yaf/yafrag.h>
#include <yaf/decode.h>
#include <yaf/ring.h>
#include <airframe/airlock.h>

typedef struct yfConfig_st {
    char            *inspec;
    char            *livetype;
    char            outspec[1024];
    gboolean        lockmode;
    gboolean		ipfixNetTrans;
    gboolean        noerror;
    gboolean        dagInterface;
    uint64_t        rotate_ms;
    uint32_t        odid;
    fbConnSpec_t    connspec;
} yfConfig_t;

#define YF_CONFIG_INIT {NULL, NULL, NULL, FALSE, FALSE, FALSE, FALSE, 0, 0, FB_CONNSPEC_INIT}

typedef struct yfContext_st {
    /** Configuration */
    yfConfig_t          *cfg;
    /** Packet source */
    void                *pktsrc;
    /** Packet ring buffer */
    size_t              pbuflen;
    rgaRing_t           *pbufring;
    /** Decoder */
    yfDecodeCtx_t       *dectx;
    /** Flow table */
    yfFlowTab_t         *flowtab;
    /** Fragment table */
    yfFragTab_t         *fragtab;
    /** Output rotation state */
    uint64_t            last_rotate_ms;
    /** Output lock buffer */
    AirLock             lockbuf;
    /** Output IPFIX buffer */
    fBuf_t              *fbuf;
	/** Error description */
	GError				*err;
} yfContext_t;

#define YF_CTX_INIT {NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, AIR_LOCK_INIT, NULL, NULL}

#endif

#endif
