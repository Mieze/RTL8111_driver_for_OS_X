//
//  RealtekRTL8111VTD.cpp
//  RealtekRTL8111
//
//  Created by Laura Müller on 26.11.25.
//  Copyright © 2025 Laura Müller. All rights reserved.
//

#include "RealtekRTL8111.hpp"

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif /* MIN */

#define next_page(x) trunc_page(x + PAGE_SIZE)

#pragma mark --- initialisation methods for AppleVTD support ---

bool RTL8111::setupRxMap()
{
    IOMemoryDescriptor *md;
    IOPhysicalAddress pa;
    IOByteCount offset;
    UInt64 word1;
    UInt32 end;
    UInt32 i, n, idx;
    bool result = false;

    /* Alloc ixgbeRxBufferInfo. */
    rxMapMem = IOMallocZero(kRxMapMemSize);
    
    if (!rxMapMem) {
        IOLog("Couldn't alloc rx map.\n");
        goto done;
    }
    rxMapInfo = (rtlRxMapInfo *)rxMapMem;
    
    /* Setup Ranges for IOMemoryDescriptors. */
    for (i = 0; i < kNumRxDesc; i++) {
        rxMapInfo->rxMemRange[i].address = (IOVirtualAddress)mbuf_datastart(rxBufArray[i].mbuf);
        rxMapInfo->rxMemRange[i].length = PAGE_SIZE;
    }

    /* Alloc IOMemoryDescriptors. */
    for (i = 0, idx = 0; i < kNumRxMemDesc; i++, idx += kRxMemBatchSize) {
        md = IOMemoryDescriptor::withOptions(&rxMapInfo->rxMemRange[idx], kRxMemBatchSize, 0, kernel_task, (kIOMemoryTypeVirtual | kIODirectionIn | kIOMemoryAsReference), mapper);
        
        if (!md) {
            IOLog("Couldn't alloc IOMemoryDescriptor.\n");
            goto error_rx_desc;
        }
        if (md->prepare() != kIOReturnSuccess) {
            IOLog("IOMemoryDescriptor::prepare() failed.\n");
            goto error_prep;
        }
        rxMapInfo->rxMemIO[i] = md;
        offset = 0;
        end = idx + kRxMemBatchSize;
        word1 = (kRxBufferSize | DescOwn);

        for (n = idx; n < end; n++) {
            if (n == kRxLastDesc)
                word1 |= RingEnd;
            
            pa = md->getPhysicalSegment(offset, NULL);
            rxBufArray[n].phyAddr = pa;
            
            rxDescArray[i].buf.blen = OSSwapHostToLittleInt64(word1);
            rxDescArray[i].buf.addr = OSSwapHostToLittleInt64(rxBufArray[i].phyAddr);

            offset += PAGE_SIZE;
        }
    }
    result = true;
    
done:
    return result;
            
error_prep:
    md->complete();
    RELEASE(md);

error_rx_desc:
    if (rxMapMem) {
        for (i = 0; i < kNumRxMemDesc; i++) {
            md = rxMapInfo->rxMemIO[i];
                            
            if (md) {
                md->complete();
                md->release();
            }
            rxMapInfo->rxMemIO[i] = NULL;
        }
        IOFree(rxMapMem, kRxMapMemSize);
        rxMapMem = NULL;
    }
    goto done;
}

void RTL8111::freeRxMap()
{
    IOMemoryDescriptor *md;
    UInt32 i;

    if (rxMapMem) {
        for (i = 0; i < kNumRxMemDesc; i++) {
            md = rxMapInfo->rxMemIO[i];
                            
            if (md) {
                md->complete();
                md->release();
            }
            rxMapInfo->rxMemIO[i] = NULL;
        }
        IOFree(rxMapMem, kRxMapMemSize);
        rxMapMem = NULL;
    }
}

bool RTL8111::setupTxMap()
{
    bool result = false;

    txMapMem = IOMallocZero(kTxMapMemSize);
    
    if (!txMapMem) {
        IOLog("Couldn't alloc memory for tx map.\n");
        goto done;
    }
    txMapInfo = (rtlTxMapInfo *)txMapMem;
    
    txMapInfo->txNextMem2Use = 0;
    txMapInfo->txNextMem2Free = 0;
    txMapInfo->txNumFreeMem = kNumTxMemDesc;

    result = true;
    
done:
    return result;
}

void RTL8111::freeTxMap()
{
    UInt32 i;

    if (txMapMem) {
        for (i = 0; i < kNumTxMemDesc; i++) {
            if (txMapInfo->txMemIO[i]) {
                txMapInfo->txMemIO[i]->complete();
                txMapInfo->txMemIO[i]->release();
                txMapInfo->txMemIO[i] = NULL;
            }
        }
        IOFree(txMapMem, kTxMapMemSize);
        txMapMem = NULL;
    }
}

#pragma mark --- interrupt methods for AppleVTD support ---

void RTL8111::interruptOccurredVTD(OSObject *client, IOInterruptEventSource *src, int count)
{
    UInt32 packets;
    UInt16 status;
    
    WriteReg16(IntrMask, 0x0000);
    status = ReadReg16(IntrStatus);
    
    /* hotplug/major error/no more work/shared irq */
    if ((status == 0xFFFF) || !status)
        goto done;
    
    if (status & SYSErr) {
        pciErrorInterrupt();
        goto done;
    }
    if (!polling) {
        /* Rx interrupt */
        if (status & (RxOK | RxDescUnavail | RxFIFOOver)) {
            packets = rxInterruptVTD(netif, kNumRxDesc, NULL, NULL);
            
            if (packets)
                netif->flushInputQueue();
        }
        /* Tx interrupt */
        if (status & (TxOK | TxErr | TxDescUnavail))
            txInterrupt();
    }
    if (status & LinkChg)
        checkLinkStatus();
    
done:
    WriteReg16(IntrStatus, status);
    WriteReg16(IntrMask, intrMask);
}


#pragma mark --- tx methods for AppleVTD support ---

/*
 * Map a tx packet for read DMA access by the NIC.
 * The packet is split up into physical contiguous segments
 * and an IOMemoryDescriptor is used to map all segments for
 * DMA access.
 */
UInt32 RTL8111::txMapPacket(mbuf_t packet,
                            IOPhysicalSegment *vector,
                            UInt32 maxSegs)
{
    IOMemoryDescriptor *md = NULL;
    IOAddressRange *srcRange;
    IOAddressRange *dstRange;
    mbuf_t m;
    IOVirtualAddress d;
    IOByteCount offset;
    UInt64 len, l;
    UInt32 segIndex = 0;
    UInt32 i;
    UInt16 saveMem;
    bool result = false;

    if (packet && vector && maxSegs) {
        srcRange = txMapInfo->txSCRange;
        m = packet;
        
        /*
         * Split up the packet into virtual contiguos segments.
         */
        if (mbuf_next(m) == 0) {
            d = (IOVirtualAddress)mbuf_data(m);
            len = mbuf_len(m);
            
            if ( trunc_page(d) == trunc_page(d + len - 1) ) {
                srcRange[0].address = d;
                srcRange[0].length = len;
                segIndex = 1;
                goto map;
            }
        }
        do {
            d = (IOVirtualAddress)mbuf_data(m);
            
            for (len = mbuf_len(m); len; d += l, len -= l) {
                l = MIN(len, PAGE_SIZE);
                l = MIN(next_page(d), d + l) - d;
                
                if (segIndex < maxSegs) {
                    srcRange[segIndex].address = d;
                    srcRange[segIndex].length = l;
                } else {
                    segIndex = 0;
                    goto done;
                }
                segIndex++;
            }
            m = mbuf_next(m);
        } while (m);
map:
        /*
         * Get IORanges, fill in the virtual segments and grab
         * an IOMemoryDescriptor to map the packet.
         */
        if (txMapInfo->txNumFreeMem > 1) {
            dstRange = &txMapInfo->txMemRange[txNextDescIndex];
            
            for (i = 0; i < segIndex; i++) {
                dstRange[i].address = (srcRange[i].address & ~PAGE_MASK);
                dstRange[i].length = PAGE_SIZE;
                srcRange[i].address &= PAGE_MASK;
            }
            OSAddAtomic16(-1, &txMapInfo->txNumFreeMem);
            saveMem = txMapInfo->txNextMem2Use++;
            txMapInfo->txNextMem2Use &= kTxMemDescMask;
            md = txMapInfo->txMemIO[saveMem];
            
            if (md) {
                result = md->initWithOptions(dstRange, segIndex, 0, kernel_task, (kIOMemoryTypeVirtual | kIODirectionOut | kIOMemoryAsReference), mapper);
            } else {
                md = IOMemoryDescriptor::withAddressRanges(dstRange, segIndex, (kIOMemoryTypeVirtual | kIODirectionOut | kIOMemoryAsReference), kernel_task);
                
                if (!md) {
                    DebugLog("Couldn't alloc IOMemoryDescriptor for tx packet.");
                    goto error_map;
                }
                txMapInfo->txMemIO[saveMem] = md;
                result = true;
            }
            if (!result) {
                DebugLog("Failed to init IOMemoryDescriptor for tx packet.");
                goto error_map;
            }
            if (md->prepare() != kIOReturnSuccess) {
                DebugLog("Failed to prepare() tx packet.");
                goto error_map;
            }
            md->setTag(kIOMemoryActive);
            offset = 0;

            /*
             * Get the physical segments and fill in the vector.
             */
            for (i = 0; i < segIndex; i++) {
                vector[i].location = md->getPhysicalSegment(offset, NULL) + srcRange[i].address;
                vector[i].length = srcRange[i].length;

                //DebugLog("Phy. Segment %u addr: %llx, len: %llu\n", i, vector[i].location, vector[i].length);
                offset += PAGE_SIZE;
            }
        }
    }
    
done:
    return segIndex;

error_map:
    txMapInfo->txNextMem2Use = saveMem;
    OSAddAtomic16(1, &txMapInfo->txNumFreeMem);

    segIndex = 0;
    goto done;
}

/*
 * Unmap a tx packet. Complete the IOMemoryDecriptor and free it
 * for reuse.
 */
void RTL8111::txUnmapPacket()
{
    IOMemoryDescriptor *md = txMapInfo->txMemIO[txMapInfo->txNextMem2Free];
    
    md->complete();
    md->setTag(kIOMemoryInactive);
    
    ++(txMapInfo->txNextMem2Free) &= kTxMemDescMask;
    OSAddAtomic16(1, &txMapInfo->txNumFreeMem);
}

#pragma mark --- rx methods for AppleVTD support ---

/*
 * Unmap a batch of rx buffers, replace them with new ones and map them.
 * @ring        The ring to map for
 * @index       The index of the first buffer in a batch to map.
 * @count       Number of batches to map.
 * @result      The index of the next batch to map.
 */
UInt16 RTL8111::rxMapBuffers(UInt16 index, UInt16 count)
{
    IOPhysicalAddress pa;
    IOMemoryDescriptor *md;
    UInt64 length;
    IOByteCount offset;
    UInt32 batch = count;
    UInt16 end, i;
    bool result;
    
    while (batch--) {
        /*
         * Get the coresponding IOMemoryDescriptor and complete
         * the mapping;
         */
        md = rxMapInfo->rxMemIO[index >> kRxMemBaseShift];
        md->complete();
        
        /*
         * Update IORanges with the addresses of the replaced buffers.
         */
        for (i = index, end = index + kRxMemBatchSize; i < end; i++) {
            if (rxBufArray[i].phyAddr == 0) {
                rxMapInfo->rxMemRange[i].address = (IOVirtualAddress)mbuf_datastart(rxBufArray[i].mbuf);
            }
        }
        /*
         * Prepare IOMemoryDescriptor with updated buffer addresses.
         */
        result = md->initWithOptions(&rxMapInfo->rxMemRange[index], kRxMemBatchSize, 0, kernel_task, kIOMemoryTypeVirtual | kIODirectionIn | kIOMemoryAsReference, mapper);

        if (!result) {
            IOLog("Failed to reinit rx IOMemoryDescriptor.\n");
            goto done;
        }
        if (md->prepare() != kIOReturnSuccess) {
            IOLog("Failed to prepare rx IOMemoryDescriptor.\n");
            goto done;
        }
        /*
         * Get physical addresses of the buffers and update buffer info,
         * as well as the descriptor ring with new addresses.
         */
        length = (kRxBufferSize | DescOwn);
        offset = 0;

        for (i = index, end = index + kRxMemBatchSize; i < end; i++) {
            if (i == kRxLastDesc)
                length |= RingEnd;
            
            pa = md->getPhysicalSegment(offset, NULL);
            rxBufArray[i].phyAddr = pa;
            
            rxDescArray[i].buf.addr = OSSwapHostToLittleInt64(pa);
            rxDescArray[i].buf.blen = OSSwapHostToLittleInt64(length);

            //DebugLog("rxDescArray[%u]: 0x%x %llu\n", i, (unsigned int)length, pa);
            offset += PAGE_SIZE;
        }
        wmb();
        
next_batch:
        /*
         * Update indices after every batch.
         */
        index = (index + kRxMemBatchSize) & kRxDescMask;
        rxMapNextIndex = index;
    }
    
done:
    return index;
}

UInt32 RTL8111::rxInterruptVTD(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context)
{
    RtlDmaDesc *desc = &rxDescArray[rxNextDescIndex];
    mbuf_t bufPkt, newPkt;
    UInt32 goodPkts = 0;
    UInt32 numMap = 0;
    UInt32 descStatus1, descStatus2;
    UInt32 pktSize;
    bool replaced;
    
    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->cmd.opts1)) & DescOwn) && (goodPkts < maxCount)) {
        descStatus2 = OSSwapLittleToHostInt32(desc->cmd.opts2);
        pktSize = (descStatus1 & 0x1fff) - kIOEthernetCRCSize;
        bufPkt = rxBufArray[rxNextDescIndex].mbuf;
        //DebugLog("rxInterrupt(): descStatus1=0x%x, descStatus2=0x%x, pktSize=%u\n", descStatus1, descStatus2, pktSize);
        
        newPkt = rxPool->replaceOrCopyPacket(&bufPkt, pktSize, &replaced);
        
        if (!newPkt) {
            /* Allocation of a new packet failed so that we must leave the original packet in place. */
            DebugLog("replaceOrCopyPacket() failed.\n");
            etherStats->dot3RxExtraEntry.resourceErrors++;
            goto nextDesc;
        }
        
        /* If the packet was replaced we have to update the descriptor's buffer address. */
        if (replaced) {
            if (mbuf_next(bufPkt) != NULL) {
                DebugLog("Failed to get physical address.\n");
                etherStats->dot3RxExtraEntry.resourceErrors++;
                mbuf_freem_list(bufPkt);
                goto nextDesc;
            }
            rxBufArray[rxNextDescIndex].mbuf = bufPkt;
            rxBufArray[rxNextDescIndex].phyAddr = 0;
        }
        /* Set the length of the buffer. */
        mbuf_setlen(newPkt, pktSize);

        if (descStatus1 & LastFrag) {
            if (rxPacketHead) {
                /* This is the last buffer of a jumbo frame. */
                mbuf_setflags_mask(newPkt, 0, MBUF_PKTHDR);
                mbuf_setnext(rxPacketTail, newPkt);
                
                rxPacketSize += pktSize;
                rxPacketTail = newPkt;
            } else {
                /*
                 * We've got a complete packet in one buffer.
                 * It can be enqueued directly.
                 */
                rxPacketHead = newPkt;
                rxPacketSize = pktSize;
            }
            getChecksumResult(newPkt, descStatus1, descStatus2);
            
            /* Also get the VLAN tag if there is any. */
            if (descStatus2 & RxVlanTag)
                setVlanTag(rxPacketHead, OSSwapInt16(descStatus2 & 0xffff));
            
            mbuf_pkthdr_setlen(rxPacketHead, rxPacketSize);
            interface->enqueueInputPacket(rxPacketHead, pollQueue);
            
            rxPacketHead = rxPacketTail = NULL;
            rxPacketSize = 0;
            
            goodPkts++;
        } else {
            if (rxPacketHead) {
                /* We are in the middle of a jumbo frame. */
                mbuf_setflags_mask(newPkt, 0, MBUF_PKTHDR);
                mbuf_setnext(rxPacketTail, newPkt);
                
                rxPacketTail = newPkt;
                rxPacketSize += pktSize;
            } else {
                /* This is the first buffer of a jumbo frame. */
                rxPacketHead = rxPacketTail = newPkt;
                rxPacketSize = pktSize;
            }
        }

    nextDesc:
        /*
         * If a batch has been completed, increment the number of
         * batches, which need to be mapped.
         */
        if ((rxNextDescIndex & kRxMemDescMask) == kRxMemDescMask)
            numMap++;

        /* Get the next descriptor to process. */
        ++rxNextDescIndex &= kRxDescMask;
        desc = &rxDescArray[rxNextDescIndex];
    }
    if (numMap) {
        //DebugLog("rxMapNextIndex: %u, numMap: %u\n", rxMapNextIndex, numMap);
        rxMapBuffers(rxMapNextIndex, numMap);
    }
    return goodPkts;
}
