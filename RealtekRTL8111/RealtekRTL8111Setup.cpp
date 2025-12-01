//
//  RealtekRTL8111Setup.cpp
//  RealtekRTL8111
//
//  Created by Laura Müller on 26.01.25.
//  Copyright © 2025 Laura Müller. All rights reserved.
//

#include "RealtekRTL8111.hpp"

#pragma mark --- data structure initialization methods ---

static const char *onName = "enabled";
static const char *offName = "disabled";

void RTL8111::getParams()
{
    OSDictionary *params;
    OSIterator *iterator;
    OSBoolean *enableEEE;
    OSBoolean *tso4;
    OSBoolean *tso6;
    OSBoolean *csoV6;
    OSBoolean *noASPM;
    OSString *versionString;
    OSString *fbAddr;

    if (version_major >= Tahoe) {
        params = serviceMatching("AppleVTD");
        
        if (params) {
            iterator = IOService::getMatchingServices(params);
            
            if (iterator) {
                IOMapper *mp = OSDynamicCast(IOMapper, iterator->getNextObject());
                
                if (mp) {
                    IOLog("AppleVTD is enabled.");
                    useAppleVTD = true;
                }
                iterator->release();
            }
            params->release();
        }
    }
    versionString = OSDynamicCast(OSString, getProperty(kDriverVersionName));

    params = OSDynamicCast(OSDictionary, getProperty(kParamName));
    
    if (params) {
        noASPM = OSDynamicCast(OSBoolean, params->getObject(kDisableASPMName));
        disableASPM = (noASPM != NULL) ? noASPM->getValue() : false;
        
        DebugLog("PCIe ASPM support %s.\n", disableASPM ? offName : onName);
        
        enableEEE = OSDynamicCast(OSBoolean, params->getObject(kEnableEeeName));
        
        if (enableEEE != NULL)
            linuxData.eee_enabled = (enableEEE->getValue()) ? 1 : 0;
        else
            linuxData.eee_enabled = 0;
        
        IOLog("EEE support %s.\n", linuxData.eee_enabled ? onName : offName);
        
        tso4 = OSDynamicCast(OSBoolean, params->getObject(kEnableTSO4Name));
        enableTSO4 = (tso4 != NULL) ? tso4->getValue() : false;
        
        IOLog("TCP/IPv4 segmentation offload %s.\n", enableTSO4 ? onName : offName);
        
        tso6 = OSDynamicCast(OSBoolean, params->getObject(kEnableTSO6Name));
        enableTSO6 = (tso6 != NULL) ? tso6->getValue() : false;
        
        IOLog("TCP/IPv6 segmentation offload %s.\n", enableTSO6 ? onName : offName);
        
        csoV6 = OSDynamicCast(OSBoolean, params->getObject(kEnableCSO6Name));
        enableCSO6 = (csoV6 != NULL) ? csoV6->getValue() : false;
        
        IOLog("TCP/IPv6 checksum offload %s.\n", enableCSO6 ? onName : offName);
                
        fbAddr = OSDynamicCast(OSString, params->getObject(kFallbackName));
        
        if (fbAddr) {
            const char *s = fbAddr->getCStringNoCopy();
            UInt8 *addr = fallBackMacAddr.bytes;
            
            if (fbAddr->getLength()) {
                sscanf(s, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
                
                IOLog("Fallback MAC: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
                      fallBackMacAddr.bytes[0], fallBackMacAddr.bytes[1],
                      fallBackMacAddr.bytes[2], fallBackMacAddr.bytes[3],
                      fallBackMacAddr.bytes[4], fallBackMacAddr.bytes[5]);
            }
        }
    } else {
        disableASPM = true;
        linuxData.eee_enabled = 1;
        enableTSO4 = true;
        enableTSO6 = true;
        intrMitigateValue = 0x5f51;
    }
    if (versionString)
        IOLog("Version %s using interrupt mitigate value 0x%x. Please don't support tonymacx86.com!\n", versionString->getCStringNoCopy(), intrMitigateValue);
    else
        IOLog("Using interrupt mitigate value 0x%x. Please don't support tonymacx86.com!\n", intrMitigateValue);
}

static IOMediumType mediumTypeArray[MEDIUM_INDEX_COUNT] = {
    kIOMediumEthernetAuto,
    (kIOMediumEthernet10BaseT | IFM_HDX),
    (kIOMediumEthernet10BaseT | IFM_FDX),
    (kIOMediumEthernet100BaseTX | IFM_HDX),
    (kIOMediumEthernet100BaseTX | IFM_FDX),
    (kIOMediumEthernet100BaseTX | IFM_FDX | IFM_FLOW),
    (kIOMediumEthernet1000BaseT | IFM_FDX),
    (kIOMediumEthernet1000BaseT | IFM_FDX | IFM_FLOW),
    (kIOMediumEthernet100BaseTX | IFM_FDX | IFM_EEE),
    (kIOMediumEthernet100BaseTX | IFM_FDX | IFM_FLOW | IFM_EEE),
    (kIOMediumEthernet1000BaseT | IFM_FDX | IFM_EEE),
    (kIOMediumEthernet1000BaseT | IFM_FDX | IFM_FLOW | IFM_EEE)
};

static UInt32 mediumSpeedArray[MEDIUM_INDEX_COUNT] = {
    0,
    10 * MBit,
    10 * MBit,
    100 * MBit,
    100 * MBit,
    100 * MBit,
    1000 * MBit,
    1000 * MBit,
    100 * MBit,
    100 * MBit,
    1000 * MBit,
    1000 * MBit
};

bool RTL8111::setupMediumDict()
{
    IONetworkMedium *medium;
    UInt32 i, n;
    bool result = false;

    n = eeeCap ? MEDIUM_INDEX_COUNT : MEDIUM_INDEX_COUNT - 4;
    mediumDict = OSDictionary::withCapacity(n + 1);

    if (mediumDict) {
        for (i = MEDIUM_INDEX_AUTO; i < n; i++) {
            medium = IONetworkMedium::medium(mediumTypeArray[i], mediumSpeedArray[i], 0, i);
            
            if (!medium)
                goto error1;

            result = IONetworkMedium::addMedium(mediumDict, medium);
            medium->release();

            if (!result)
                goto error1;

            mediumTable[i] = medium;
        }
    }
    result = publishMediumDictionary(mediumDict);
    
    if (!result)
        goto error1;

done:
    return result;
    
error1:
    IOLog("Error creating medium dictionary.\n");
    mediumDict->release();
    
    for (i = MEDIUM_INDEX_AUTO; i < MEDIUM_INDEX_COUNT; i++)
        mediumTable[i] = NULL;

    goto done;
}

bool RTL8111::initEventSources(IOService *provider)
{
    int msiIndex = -1;
    int intrIndex = 0;
    int intrType = 0;
    bool result = false;
    
    txQueue = reinterpret_cast<IOBasicOutputQueue *>(getOutputQueue());
    
    if (txQueue == NULL) {
        IOLog("Failed to get output queue.\n");
        goto done;
    }
    txQueue->retain();
    
    while (pciDevice->getInterruptType(intrIndex, &intrType) == kIOReturnSuccess) {
        if (intrType & kIOInterruptTypePCIMessaged){
            msiIndex = intrIndex;
            break;
        }
        intrIndex++;
    }
    if (msiIndex != -1) {
        DebugLog("MSI interrupt index: %d\n", msiIndex);
        
        if (useAppleVTD) {
            interruptSource = IOInterruptEventSource::interruptEventSource(this, OSMemberFunctionCast(IOInterruptEventSource::Action, this, &RTL8111::interruptOccurredVTD), provider, msiIndex);
        } else {
            interruptSource = IOInterruptEventSource::interruptEventSource(this, OSMemberFunctionCast(IOInterruptEventSource::Action, this, &RTL8111::interruptOccurredPoll), provider, msiIndex);
        }
    }
    if (!interruptSource) {
        IOLog("Error: MSI index was not found or MSI interrupt could not be enabled.\n");
        goto error1;
    }
    workLoop->addEventSource(interruptSource);
    
    if (revisionC)
        timerSource = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &RTL8111::timerActionRTL8111C));
    else
        timerSource = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &RTL8111::timerActionRTL8111B));
    
    if (!timerSource) {
        IOLog("Failed to create IOTimerEventSource.\n");
        goto error2;
    }
    workLoop->addEventSource(timerSource);

    result = true;
    
done:
    return result;
    
error2:
    workLoop->removeEventSource(interruptSource);
    RELEASE(interruptSource);

error1:
    IOLog("Error initializing event sources.\n");
    txQueue->release();
    txQueue = NULL;
    goto done;
}

bool RTL8111::setupRxResources()
{
    IOPhysicalAddress64 pa = 0;
    IODMACommand::Segment64 seg;
    mbuf_t m;
    UInt64 offset = 0;
    UInt64 word1;
    UInt32 numSegs = 1;
    UInt32 i;
    bool result = false;
    
    /* Alloc rx mbuf_t array. */
    rxBufArrayMem = IOMallocZero(kRxBufArraySize);
    
    if (!rxBufArrayMem) {
        IOLog("Couldn't alloc receive buffer array.\n");
        goto done;
    }
    rxBufArray = (rtlRxBufferInfo *)rxBufArrayMem;

    /* Create receiver descriptor array. */
    rxBufDesc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, (kIODirectionInOut | kIOMemoryPhysicallyContiguous | kIOMemoryHostPhysicallyContiguous | kIOMapInhibitCache), kRxDescSize, 0xFFFFFFFFFFFFFF00ULL);
    
    if (!rxBufDesc) {
        IOLog("Couldn't alloc rxBufDesc.\n");
        goto error_buff;
    }
    if (rxBufDesc->prepare() != kIOReturnSuccess) {
        IOLog("rxBufDesc->prepare() failed.\n");
        goto error_prep;
    }
    rxDescArray = (RtlDmaDesc *)rxBufDesc->getBytesNoCopy();

    rxDescDmaCmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1, mapper, NULL);
    
    if (!rxDescDmaCmd) {
        IOLog("Couldn't alloc rxDescDmaCmd.\n");
        goto error_dma;
    }
    
    if (rxDescDmaCmd->setMemoryDescriptor(rxBufDesc) != kIOReturnSuccess) {
        IOLog("setMemoryDescriptor() failed.\n");
        goto error_set_desc;
    }
    
    if (rxDescDmaCmd->gen64IOVMSegments(&offset, &seg, &numSegs) != kIOReturnSuccess) {
        IOLog("gen64IOVMSegments() failed.\n");
        goto error_rx_buf;
    }
    /* And the rx ring's physical address too. */
    rxPhyAddr = seg.fIOVMAddr;
    
    /* Initialize rxDescArray. */
    bzero(rxDescArray, kRxDescSize);
    rxDescArray[kRxLastDesc].cmd.opts1 = OSSwapHostToLittleInt32(RingEnd);

    for (i = 0; i < kNumRxDesc; i++) {
        rxBufArray[i].mbuf = NULL;
    }
    rxNextDescIndex = 0;
    rxMapNextIndex = 0;
    
    rxPool = RealtekRxPool::withCapacity(kRxPoolMbufCap, kRxPoolClstCap);

    if (!rxPool) {
        IOLog("Couldn't alloc receive buffer pool.\n");
        goto error_rx_buf;
    }

    /* Alloc receive buffers. */
    for (i = 0; i < kNumRxDesc; i++) {
        m = rxPool->getPacket(kRxBufferSize);
        
        if (!m) {
            IOLog("Couldn't get receive buffer from pool.\n");
            goto error_buf;
        }
        rxBufArray[i].mbuf = m;

        if (!useAppleVTD) {
            word1 = (kRxBufferSize | DescOwn);

            if (i == kRxLastDesc)
                word1 |= RingEnd;

            pa = mbuf_data_to_physical(mbuf_datastart(m));
            rxBufArray[i].phyAddr = pa;

            rxDescArray[i].buf.blen = OSSwapHostToLittleInt64(word1);
            rxDescArray[i].buf.addr = OSSwapHostToLittleInt64(pa);
        }
    }
    if (useAppleVTD)
        result = setupRxMap();
    else
        result = true;

done:
    return result;
    
error_buf:
    for (i = 0; i < kNumRxDesc; i++) {
        if (rxBufArray[i].mbuf) {
            mbuf_freem_list(rxBufArray[i].mbuf);
            rxBufArray[i].mbuf = NULL;
            rxBufArray[i].phyAddr = 0;
        }
    }
    RELEASE(rxPool);

error_rx_buf:
    rxDescDmaCmd->clearMemoryDescriptor();

error_set_desc:
    RELEASE(rxDescDmaCmd);

error_dma:
    rxBufDesc->complete();
    
error_prep:
    RELEASE(rxBufDesc);

error_buff:
    IOFree(rxBufArrayMem, kRxBufArraySize);
    rxBufArrayMem = NULL;
    rxBufArray = NULL;

    goto done;
}

bool RTL8111::setupTxResources()
{
    IODMACommand::Segment64 seg;
    UInt64 offset = 0;
    UInt32 numSegs = 1;
    UInt32 i;
    bool result = false;
    
    /* Alloc tx mbuf_t array. */
    txBufArrayMem = IOMallocZero(kTxBufArraySize);
    
    if (!txBufArrayMem) {
        IOLog("Couldn't alloc transmit buffer array.\n");
        goto done;
    }
    txMbufArray = (mbuf_t *)txBufArrayMem;
    
    /* Create transmitter descriptor array. */
    txBufDesc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, (kIODirectionInOut | kIOMemoryPhysicallyContiguous | kIOMemoryHostPhysicallyContiguous | kIOMapInhibitCache), kTxDescSize, 0xFFFFFFFFFFFFFF00ULL);
                
    if (!txBufDesc) {
        IOLog("Couldn't alloc txBufDesc.\n");
        goto error_buff;
    }
    if (txBufDesc->prepare() != kIOReturnSuccess) {
        IOLog("txBufDesc->prepare() failed.\n");
        goto error_prep;
    }
    txDescArray = (RtlDmaDesc *)txBufDesc->getBytesNoCopy();
    
    txDescDmaCmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1, mapper, NULL);
    
    if (!txDescDmaCmd) {
        IOLog("Couldn't alloc txDescDmaCmd.\n");
        goto error_dma;
    }
    
    if (txDescDmaCmd->setMemoryDescriptor(txBufDesc) != kIOReturnSuccess) {
        IOLog("setMemoryDescriptor() failed.\n");
        goto error_set_desc;
    }
    
    if (txDescDmaCmd->gen64IOVMSegments(&offset, &seg, &numSegs) != kIOReturnSuccess) {
        IOLog("gen64IOVMSegments() failed.\n");
        goto error_segm;
    }
    /* Now get tx ring's physical address. */
    txPhyAddr = seg.fIOVMAddr;
    
    /* Initialize txDescArray. */
    bzero(txDescArray, kTxDescSize);
    txDescArray[kTxLastDesc].cmd.opts1 = OSSwapHostToLittleInt32(RingEnd);
    
    for (i = 0; i < kNumTxDesc; i++) {
        txMbufArray[i] = NULL;
    }
    txNextDescIndex = txDirtyDescIndex = 0;
    txNumFreeDesc = kNumTxDesc;
    
    if (useAppleVTD) {
        result = setupTxMap();
        
        if (!result)
            goto error_segm;
    } else {
        txMbufCursor = IOMbufNaturalMemoryCursor::withSpecification(0x4000, kMaxSegs);
        
        if (!txMbufCursor) {
            IOLog("Couldn't create txMbufCursor.\n");
            goto error_segm;
        }
        result = true;
    }
    
done:
    return result;
        
error_segm:
    txDescDmaCmd->clearMemoryDescriptor();

error_set_desc:
    RELEASE(txDescDmaCmd);
    
error_dma:
    txBufDesc->complete();

error_prep:
    RELEASE(txBufDesc);
    
error_buff:
    IOFree(txBufArrayMem, kTxBufArraySize);
    txBufArrayMem = NULL;
    txMbufArray = NULL;
    
    goto done;
}

bool RTL8111::setupStatResources()
{
    IODMACommand::Segment64 seg;
    UInt64 offset = 0;
    UInt32 numSegs = 1;
    bool result = false;

    /* Create statistics dump buffer. */
    statBufDesc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, (kIODirectionIn | kIOMemoryPhysicallyContiguous | kIOMemoryHostPhysicallyContiguous | kIOMapInhibitCache), sizeof(RtlStatData), 0xFFFFFFFFFFFFFF00ULL);
    
    if (!statBufDesc) {
        IOLog("Couldn't alloc statBufDesc.\n");
        goto done;
    }
    
    if (statBufDesc->prepare() != kIOReturnSuccess) {
        IOLog("statBufDesc->prepare() failed.\n");
        goto error_prep;
    }
    statData = (RtlStatData *)statBufDesc->getBytesNoCopy();
    
    statDescDmaCmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1);
    
    if (!statDescDmaCmd) {
        IOLog("Couldn't alloc statDescDmaCmd.\n");
        goto error_dma;
    }
    
    if (statDescDmaCmd->setMemoryDescriptor(statBufDesc) != kIOReturnSuccess) {
        IOLog("setMemoryDescriptor() failed.\n");
        goto error_set_desc;
    }
    
    if (statDescDmaCmd->gen64IOVMSegments(&offset, &seg, &numSegs) != kIOReturnSuccess) {
        IOLog("gen64IOVMSegments() failed.\n");
        goto error_segm;
    }
    /* And the rx ring's physical address too. */
    statPhyAddr = seg.fIOVMAddr;
    
    /* Initialize statData. */
    bzero(statData, sizeof(RtlStatData));

    result = true;
    
done:
    return result;

error_segm:
    statDescDmaCmd->clearMemoryDescriptor();

error_set_desc:
    RELEASE(statDescDmaCmd);
    
error_dma:
    statBufDesc->complete();

error_prep:
    RELEASE(statBufDesc);
    goto done;
}

void RTL8111::freeRxResources()
{
    UInt32 i;
    
    if (useAppleVTD)
        freeRxMap();

    if (rxDescDmaCmd) {
        rxDescDmaCmd->complete();
        rxDescDmaCmd->clearMemoryDescriptor();
        rxDescDmaCmd->release();
        rxDescDmaCmd = NULL;
    }
    if (rxBufDesc) {
        rxBufDesc->complete();
        rxBufDesc->release();
        rxBufDesc = NULL;
        rxPhyAddr = (IOPhysicalAddress64)NULL;
    }
    RELEASE(rxPool);
    
    for (i = 0; i < kNumRxDesc; i++) {
        if (rxBufArray[i].mbuf) {
            mbuf_freem_list(rxBufArray[i].mbuf);
            rxBufArray[i].mbuf = NULL;
        }
    }
    if (rxBufArrayMem) {
        IOFree(rxBufArrayMem, kRxBufArraySize);
        rxBufArrayMem = NULL;
        rxBufArray = NULL;
    }
}

void RTL8111::freeTxResources()
{
    if (useAppleVTD)
        freeTxMap();
    else
        RELEASE(txMbufCursor);

    if (txDescDmaCmd) {
        txDescDmaCmd->complete();
        txDescDmaCmd->clearMemoryDescriptor();
        txDescDmaCmd->release();
        txDescDmaCmd = NULL;
    }
    if (txBufDesc) {
        txBufDesc->complete();
        txBufDesc->release();
        txBufDesc = NULL;
        txPhyAddr = (IOPhysicalAddress64)NULL;
    }
    if (txBufArrayMem) {
        IOFree(txBufArrayMem, kTxBufArraySize);
        txBufArrayMem = NULL;
        txMbufArray = NULL;
    }
}

void RTL8111::freeStatResources()
{
    if (statDescDmaCmd) {
        statDescDmaCmd->complete();
        statDescDmaCmd->clearMemoryDescriptor();
        statDescDmaCmd->release();
        statDescDmaCmd = NULL;
    }
    if (statBufDesc) {
        statBufDesc->complete();
        statBufDesc->release();
        statBufDesc = NULL;
        statPhyAddr = (IOPhysicalAddress64)NULL;
    }
}

void RTL8111::clearDescriptors()
{
    IOMemoryDescriptor *md;
    mbuf_t m;
    UInt64 word1;
    UInt32 lastIndex = kTxLastDesc;
    UInt32 i;
    
    DebugLog("clearDescriptors() ===>\n");
    
    if (useAppleVTD && txMapInfo) {
        for (i = 0; i < kNumTxMemDesc; i++) {
            md = txMapInfo->txMemIO[i];
            
            if (md && (md->getTag() == kIOMemoryActive)) {
                md->complete();
                md->setTag(kIOMemoryInactive);
            }
        }
        txMapInfo->txNextMem2Use = txMapInfo->txNextMem2Free = 0;
        txMapInfo->txNumFreeMem = kNumTxMemDesc;
    }
    for (i = 0; i < kNumTxDesc; i++) {
        txDescArray[i].cmd.opts1 = OSSwapHostToLittleInt32((i != lastIndex) ? 0 : RingEnd);
        m = txMbufArray[i];
        
        if (m) {
            mbuf_freem_list(m);
            txMbufArray[i] = NULL;
        }
    }
    txDirtyDescIndex = txNextDescIndex = 0;
    txNumFreeDesc = kNumTxDesc;
    
    if (useAppleVTD)
        rxMapBuffers(0, kNumRxMemDesc);

    for (i = 0; i < kNumRxDesc; i++) {
        word1 = (kRxBufferSize | DescOwn);
        
        if (i == kRxLastDesc)
            word1 |= RingEnd;
        
        rxDescArray[i].buf.blen = OSSwapHostToLittleInt64(word1);
        rxDescArray[i].buf.addr = OSSwapHostToLittleInt64(rxBufArray[i].phyAddr);
    }
    rxNextDescIndex = 0;
    rxMapNextIndex = 0;
    deadlockWarn = 0;
    
    /* Free packet fragments which haven't been upstreamed yet.  */
    discardPacketFragment();
    
    DebugLog("clearDescriptors() <===\n");
}

void RTL8111::discardPacketFragment()
{
    /*
     * In case there is a packet fragment which hasn't been enqueued yet
     * we have to free it in order to prevent a memory leak.
     */
    if (rxPacketHead)
        mbuf_freem_list(rxPacketHead);
    
    rxPacketHead = rxPacketTail = NULL;
    rxPacketSize = 0;
}
