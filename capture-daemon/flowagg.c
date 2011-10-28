/*
 * flowagg.c; part of the GIMS GENI project.
 * Flow aggregation integration with yaf/fixbuf for capture daemon
 * 
 * This source code is licensed under the GENI public license.
 * See www.geni.net, or "geni_public_license.txt" that should 
 * have accompanied this software.
 */

#include "config.h"
#ifdef HAVE_YAF

#include "flowagg.h"
#include <pcap/pcap.h>
#include <fixbuf/public.h>
#include <airframe/airlock.h>


yfContext_t *yafMakeContext(pcap_t *pcap_handle, char *intf)
{
    yfConfig_t *cfg = (yfConfig_t *)malloc(sizeof(yfConfig_t));
    cfg->inspec = intf;
    cfg->livetype = "pcap";
    cfg->outspec[0] = '\0';
    cfg->lockmode = FALSE;
    cfg->ipfixNetTrans = FALSE;
    cfg->noerror = FALSE;
    cfg->dagInterface = FALSE;
    cfg->rotate_ms = 60000;
    cfg->odid = 0; /* observation domain in ipfix output records */
    cfg->connspec.transport = FB_UDP;
    cfg->connspec.host = NULL;
    cfg->connspec.svc = NULL;
    cfg->connspec.ssl_ca_file = NULL;
    cfg->connspec.ssl_cert_file = NULL;
    cfg->connspec.ssl_key_file = NULL;
    cfg->connspec.ssl_key_pass = NULL;
    cfg->connspec.vai = NULL;
    cfg->connspec.vssl_ctx = NULL;


    yfContext_t *ctx = (yfContext_t *)malloc(sizeof(yfContext_t));
    memset(ctx, 0, sizeof(yfContext_t));
    ctx->cfg = cfg;
    ctx->pbuflen = YF_PBUFLEN_NOPAYLOAD; /* hardcoded: no payload usage */
    ctx->pbufring = NULL;  /* no pbuf ring in capture daemon */

              /* decoder */
    ctx->dectx = yfDecodeCtxAlloc(1, /* LINKTYPE_ETHERNET, datalink=1 */
				  YF_TYPE_IPANY,  /* v4, v6, or any? */
				  FALSE /*yaf_opt_gre_mode*/);

              /* the flow table */
    ctx->flowtab = yfFlowTabAlloc(300 * 1000, /* idle flow timeout */
				  1800 *  1000, /* active flow timeout */
				  0, /* maximum number of flows */
				  YF_PBUFLEN_NOPAYLOAD,
				  FALSE, /* uniflow mode: */
				  FALSE, /* yaf_opt_silk_mode */
				  FALSE, /* yaf_opt_applabel_mode */
				  FALSE /* yaf_opt_entropy_mode */);
    
             /* table to handle fragment reassembly */
    ctx->fragtab = yfFragTabAlloc(30000,
				  0 /* yaf_opt_max_frags */,
				  YF_PBUFLEN_NOPAYLOAD);

    ctx->last_rotate_ms = 0;
    ctx->lockbuf.lpath = NULL;
    ctx->lockbuf.lfd = 0;
    ctx->lockbuf.held = FALSE;
    ctx->err = NULL;
    ctx->fbuf = NULL;
    return ctx;
}

int yafAddPacketToFlow(yfContext_t *ctx, 
		       const struct pcap_pkthdr *hdr, 
		       const uint8_t *pkt)
{
    /*
     * most code taken directly from yafcap.c, except
     * we don't bother with the ring buffer.
     */
    static uint8_t rawbuffer[YF_PBUFLEN_NOPAYLOAD];
    yfPBuf_t                    *pbuf = (yfPBuf_t*)&rawbuffer[0];
    yfIPFragInfo_t              fraginfo_buf, 
	*fraginfo = ctx->fragtab ? 
	&fraginfo_buf : NULL;

    /* Decode packet into packet buffer */
    if (!yfDecodeToPBuf(ctx->dectx, 
                        yfDecodeTimeval(&(hdr->ts)),
                        hdr->caplen, pkt, 
                        fraginfo, ctx->pbuflen, pbuf))      
    {
        /* Couldn't decode packet; counted in dectx. Skip. */
        return TRUE;
    }

    /* Handle fragmentation if necessary */
    if (fraginfo && fraginfo->frag) {
        if (!yfDefragPBuf(ctx->fragtab, fraginfo, 
                          ctx->pbuflen, pbuf))
        {
            /* No complete defragmented packet available. Skip. */
            return TRUE;
        }
    }
    
    /*
     * If there's no output buffer/file, create a new one using the filename
     * specified in the yafcontext (this filename is set in the rollover code in 
     * capture-daemon.c).
     */ 
    if (NULL == ctx->fbuf)
    {
        /* start a writer on the file */
        if (!(ctx->fbuf = yfWriterForFile(ctx->cfg->outspec, ctx->cfg->odid, &ctx->err))) {
            return FALSE;
        }
    }

    yfFlowPBuf(ctx->flowtab, ctx->pbuflen, pbuf);

    if (!yfFlowTabFlush(ctx, FALSE, &ctx->err))
    {
        return FALSE;
    }

    return TRUE;
}

void yafFlush(yfContext_t *context)
{
    if (!context->fbuf)
        return;

    yfFlowTabFlush(context, TRUE, &context->err);
    gboolean rv = yfWriterClose(context->fbuf, TRUE, &context->err);
    if (!rv)
    {
        fprintf(stderr, "Error flushing/closing yaf output file: %s\n", context->err->message);
    }
    context->fbuf = NULL;
}

#endif



