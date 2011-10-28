/*
 * flowagg.h; part of the GIMS GENI project.
 * 
 * Header file for flow aggregation integration with yaf/fixbuf
 * in capture-daemon
 *
 * This source code is licensed under the GENI public license.
 * See www.geni.net, or "geni_public_license.txt" that should 
 * have accompanied this software.
 */

#ifndef __FLOWAGG_H__
#define __FLOWAGG_H__

#include "config.h"

#ifdef HAVE_YAF

#include <yaf/yafcore.h>
#include "yafctx.h"

yfContext_t *yafMakeContext(pcap_t *, char *);
int yafAddPacketToFlow(yfContext_t *, const struct pcap_pkthdr *, const uint8_t *);
void yafFlush(yfContext_t *);

#endif

#endif // __FLOWAGG_H__
