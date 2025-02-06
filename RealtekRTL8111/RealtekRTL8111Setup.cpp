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
    OSNumber *intrMit;
    OSBoolean *enableEEE;
    OSBoolean *poll;
    OSBoolean *tso4;
    OSBoolean *tso6;
    OSBoolean *csoV6;
    OSBoolean *noASPM;
    OSString *versionString;
    OSString *fbAddr;

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
        
        poll = OSDynamicCast(OSBoolean, params->getObject(kEnableRxPollName));
        rxPoll = (poll != NULL) ? poll->getValue() : false;
        
        IOLog("RxPoll support %s.\n", rxPoll ? onName : offName);

        tso4 = OSDynamicCast(OSBoolean, params->getObject(kEnableTSO4Name));
        enableTSO4 = (tso4 != NULL) ? tso4->getValue() : false;
        
        IOLog("TCP/IPv4 segmentation offload %s.\n", enableTSO4 ? onName : offName);
        
        tso6 = OSDynamicCast(OSBoolean, params->getObject(kEnableTSO6Name));
        enableTSO6 = (tso6 != NULL) ? tso6->getValue() : false;
        
        IOLog("TCP/IPv6 segmentation offload %s.\n", enableTSO6 ? onName : offName);
        
        csoV6 = OSDynamicCast(OSBoolean, params->getObject(kEnableCSO6Name));
        enableCSO6 = (csoV6 != NULL) ? csoV6->getValue() : false;
        
        IOLog("TCP/IPv6 checksum offload %s.\n", enableCSO6 ? onName : offName);
        
        intrMit = OSDynamicCast(OSNumber, params->getObject(kIntrMitigateName));
        
        if (intrMit && !rxPoll)
            intrMitigateValue = intrMit->unsigned16BitValue();
        
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
        rxPoll = true;
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
    IOReturn intrResult;
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
    
    while ((intrResult = pciDevice->getInterruptType(intrIndex, &intrType)) == kIOReturnSuccess) {
        if (intrType & kIOInterruptTypePCIMessaged){
            msiIndex = intrIndex;
            break;
        }
        intrIndex++;
    }
    if (msiIndex != -1) {
        DebugLog("MSI interrupt index: %d\n", msiIndex);
        
        if (rxPoll) {
            interruptSource = IOInterruptEventSource::interruptEventSource(this, OSMemberFunctionCast(IOInterruptEventSource::Action, this, &RTL8111::interruptOccurredPoll), provider, msiIndex);
        } else {
            interruptSource = IOInterruptEventSource::interruptEventSource(this, OSMemberFunctionCast(IOInterruptEventSource::Action, this, &RTL8111::interruptOccurred), provider, msiIndex);
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
    IOPhysicalSegment rxSegment;
    IODMACommand::Segment64 seg;
    mbuf_t spareMbuf[kRxNumSpareMbufs];
    mbuf_t m;
    UInt64 offset = 0;
    UInt32 numSegs = 1;
    UInt32 i;
    UInt32 opts1;
    bool result = false;
    
    /* Alloc rx mbuf_t array. */
    rxBufArrayMem = IOMallocZero(kRxBufArraySize);
    
    if (!rxBufArrayMem) {
        IOLog("Couldn't alloc receive buffer array.\n");
        goto done;
    }
    rxMbufArray = (mbuf_t *)rxBufArrayMem;

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
        goto error_segm;
    }
    /* And the rx ring's physical address too. */
    rxPhyAddr = seg.fIOVMAddr;
    
    /* Initialize rxDescArray. */
    bzero(rxDescArray, kRxDescSize);
    rxDescArray[kRxLastDesc].opts1 = OSSwapHostToLittleInt32(RingEnd);

    for (i = 0; i < kNumRxDesc; i++) {
        rxMbufArray[i] = NULL;
    }
    rxNextDescIndex = 0;
    
    rxMbufCursor = IOMbufNaturalMemoryCursor::withSpecification(PAGE_SIZE, 1);
    
    if (!rxMbufCursor) {
        IOLog("Couldn't create rxMbufCursor.\n");
        goto error_segm;
    }

    /* Alloc receive buffers. */
    for (i = 0; i < kNumRxDesc; i++) {
        m = allocatePacket(kRxBufferPktSize);
        
        if (!m) {
            IOLog("Couldn't alloc receive buffer.\n");
            goto error_buf;
        }
        rxMbufArray[i] = m;
        
        if (rxMbufCursor->getPhysicalSegments(m, &rxSegment, 1) != 1) {
            IOLog("getPhysicalSegments() for receive buffer failed.\n");
            goto error_buf;
        }
        opts1 = (UInt32)rxSegment.length;
        opts1 |= (i == kRxLastDesc) ? (RingEnd | DescOwn) : DescOwn;
        rxDescArray[i].opts1 = OSSwapHostToLittleInt32(opts1);
        rxDescArray[i].opts2 = 0;
        rxDescArray[i].addr = OSSwapHostToLittleInt64(rxSegment.location);
    }

    /* Allocate some spare mbufs and free them in order to increase the buffer pool.
     * This seems to avoid the replaceOrCopyPacket() errors under heavy load.
     */
    for (i = 0; i < kRxNumSpareMbufs; i++)
        spareMbuf[i] = allocatePacket(kRxBufferPktSize);

    for (i = 0; i < kRxNumSpareMbufs; i++) {
        if (spareMbuf[i])
            freePacket(spareMbuf[i]);
    }
    result = true;
    
done:
    return result;
    
error_buf:
    for (i = 0; i < kNumRxDesc; i++) {
        if (rxMbufArray[i]) {
            freePacket(rxMbufArray[i]);
            rxMbufArray[i] = NULL;
        }
    }
    RELEASE(rxMbufCursor);

error_segm:
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
    rxMbufArray = NULL;

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
    txDescArray[kTxLastDesc].opts1 = OSSwapHostToLittleInt32(RingEnd);
    
    for (i = 0; i < kNumTxDesc; i++) {
        txMbufArray[i] = NULL;
    }
    txNextDescIndex = txDirtyDescIndex = 0;
    txNumFreeDesc = kNumTxDesc;
    txMbufCursor = IOMbufNaturalMemoryCursor::withSpecification(0x4000, kMaxSegs);
    
    if (!txMbufCursor) {
        IOLog("Couldn't create txMbufCursor.\n");
        goto error_segm;
    }
    result = true;
    
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
        
    if (rxBufDesc) {
        rxBufDesc->complete();
        rxBufDesc->release();
        rxBufDesc = NULL;
        rxPhyAddr = (IOPhysicalAddress64)NULL;
    }
    RELEASE(rxMbufCursor);
    
    for (i = 0; i < kNumRxDesc; i++) {
        if (rxMbufArray[i]) {
            freePacket(rxMbufArray[i]);
            rxMbufArray[i] = NULL;
        }
    }
    if (rxDescDmaCmd) {
        rxDescDmaCmd->clearMemoryDescriptor();
        rxDescDmaCmd->release();
        rxDescDmaCmd = NULL;
    }
    if (rxBufArrayMem) {
        IOFree(txBufArrayMem, kRxBufArraySize);
        rxBufArrayMem = NULL;
        rxMbufArray = NULL;
    }
}

void RTL8111::freeTxResources()
{
    if (txBufDesc) {
        txBufDesc->complete();
        txBufDesc->release();
        txBufDesc = NULL;
        txPhyAddr = (IOPhysicalAddress64)NULL;
    }
    if (txDescDmaCmd) {
        txDescDmaCmd->clearMemoryDescriptor();
        txDescDmaCmd->release();
        txDescDmaCmd = NULL;
    }
    if (txBufArrayMem) {
        IOFree(txBufArrayMem, kTxBufArraySize);
        txBufArrayMem = NULL;
        txMbufArray = NULL;
    }
    RELEASE(txMbufCursor);
}

void RTL8111::freeStatResources()
{
    if (statBufDesc) {
        statBufDesc->complete();
        statBufDesc->release();
        statBufDesc = NULL;
        statPhyAddr = (IOPhysicalAddress64)NULL;
    }
    if (statDescDmaCmd) {
        statDescDmaCmd->clearMemoryDescriptor();
        statDescDmaCmd->release();
        statDescDmaCmd = NULL;
    }
}


void RTL8111::clearDescriptors()
{
    mbuf_t m;
    UInt32 lastIndex = kTxLastDesc;
    UInt32 opts1;
    UInt32 i;
    
    DebugLog("clearDescriptors() ===>\n");
    
    for (i = 0; i < kNumTxDesc; i++) {
        txDescArray[i].opts1 = OSSwapHostToLittleInt32((i != lastIndex) ? 0 : RingEnd);
        m = txMbufArray[i];
        
        if (m) {
            freePacket(m);
            txMbufArray[i] = NULL;
        }
    }
    txDirtyDescIndex = txNextDescIndex = 0;
    txNumFreeDesc = kNumTxDesc;
        
    for (i = 0; i < kNumRxDesc; i++) {
        opts1 = (UInt32)kRxBufferPktSize;
        opts1 |= (i == kRxLastDesc) ? (RingEnd | DescOwn) : DescOwn;
        rxDescArray[i].opts1 = OSSwapHostToLittleInt32(opts1);
        rxDescArray[i].opts2 = 0;
    }
    rxNextDescIndex = 0;
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
        freePacket(rxPacketHead);
    
    rxPacketHead = rxPacketTail = NULL;
    rxPacketSize = 0;
}
