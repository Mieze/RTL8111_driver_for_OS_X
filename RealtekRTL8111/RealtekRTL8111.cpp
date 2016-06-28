/* RealtekRTL8111.c -- RTL8111 driver class implementation.
 *
 * Copyright (c) 2013 Laura Müller <laura-mueller@uni-duesseldorf.de>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * Driver for Realtek RTL8111x PCIe ethernet controllers.
 *
 * This driver is based on Realtek's r8168 Linux driver (8.041.0).
 */


#include "RealtekRTL8111.h"

#pragma mark --- function prototypes ---

static inline UInt32 adjustIPv6Header(mbuf_t m);

static inline u32 ether_crc(int length, unsigned char *data);

#pragma mark --- public methods ---

OSDefineMetaClassAndStructors(RTL8111, super)

/* IOService (or its superclass) methods. */

bool RTL8111::init(OSDictionary *properties)
{
    bool result;
    
    result = super::init(properties);
    
    if (result) {
        workLoop = NULL;
        commandGate = NULL;
        pciDevice = NULL;
        mediumDict = NULL;
        txQueue = NULL;
        interruptSource = NULL;
        timerSource = NULL;
        netif = NULL;
        netStats = NULL;
        etherStats = NULL;
        baseMap = NULL;
        baseAddr = NULL;
        rxMbufCursor = NULL;
        txNext2FreeMbuf = NULL;
        txMbufCursor = NULL;
        statBufDesc = NULL;
        statPhyAddr = NULL;
        statData = NULL;
        isEnabled = false;
        promiscusMode = false;
        multicastMode = false;
        linkUp = false;
        
#ifdef __PRIVATE_SPI__
        rxPoll = false;
        polling = false;
#else
        stalled = false;
#endif /* __PRIVATE_SPI__ */
        
        mtu = ETH_DATA_LEN;
        powerState = 0;
        speed = SPEED_1000;
        duplex = DUPLEX_FULL;
        autoneg = AUTONEG_ENABLE;
        flowCtl = kFlowControlOff;
        eeeAdv = 0;
        eeeCap = 0;
        linuxData.aspm = 0;
        pciDeviceData.vendor = 0;
        pciDeviceData.device = 0;
        pciDeviceData.subsystem_vendor = 0;
        pciDeviceData.subsystem_device = 0;
        linuxData.pci_dev = &pciDeviceData;
        intrMitigateValue = 0x5f51;
        lastIntrTime = 0;
        wolCapable = false;
        wolActive = false;
        enableTSO4 = false;
        enableCSO6 = false;
        disableASPM = false;
    }
    
done:
    return result;
}

void RTL8111::free()
{
    UInt32 i;
    
    DebugLog("free() ===>\n");
    
    if (workLoop) {
        if (interruptSource) {
            workLoop->removeEventSource(interruptSource);
            RELEASE(interruptSource);
        }
        if (timerSource) {
            workLoop->removeEventSource(timerSource);
            RELEASE(timerSource);
        }
        workLoop->release();
        workLoop = NULL;
    }
    RELEASE(commandGate);
    RELEASE(txQueue);
    RELEASE(mediumDict);
    
    for (i = MEDIUM_INDEX_AUTO; i < MEDIUM_INDEX_COUNT; i++)
        mediumTable[i] = NULL;
    
    RELEASE(baseMap);
    baseAddr = NULL;
    linuxData.mmio_addr = NULL;
    
    RELEASE(pciDevice);
    freeDMADescriptors();
    
    DebugLog("free() <===\n");
    
    super::free();
}

static const char *onName = "enabled";
static const char *offName = "disabled";

bool RTL8111::start(IOService *provider)
{
    bool result;
    
    result = super::start(provider);
    
    if (!result) {
        IOLog("Ethernet [RealtekRTL8111]: IOEthernetController::start failed.\n");
        goto done;
    }
    multicastMode = false;
    promiscusMode = false;
    multicastFilter = 0;

    pciDevice = OSDynamicCast(IOPCIDevice, provider);
    
    if (!pciDevice) {
        IOLog("Ethernet [RealtekRTL8111]: No provider.\n");
        goto done;
    }
    pciDevice->retain();
    
    if (!pciDevice->open(this)) {
        IOLog("Ethernet [RealtekRTL8111]: Failed to open provider.\n");
        goto error1;
    }
    getParams();
    
    if (!initPCIConfigSpace(pciDevice)) {
        goto error2;
    }

    if (!initRTL8111()) {
        goto error2;
    }
    
    if (gotPropMacAddr) {
        if (setHardwareAddress(&propMacAddr) != kIOReturnSuccess) {
            IOLog("Ethernet [RealtekRTL8111]: Failed to set custom MAC address.\n");
            goto error2;
        }
    }
    
    if (!setupMediumDict()) {
        IOLog("Ethernet [RealtekRTL8111]: Failed to setup medium dictionary.\n");
        goto error2;
    }
    commandGate = getCommandGate();
    
    if (!commandGate) {
        IOLog("Ethernet [RealtekRTL8111]: getCommandGate() failed.\n");
        goto error3;
    }
    commandGate->retain();
    
    if (!initEventSources(provider)) {
        IOLog("Ethernet [RealtekRTL8111]: initEventSources() failed.\n");
        goto error3;
    }
    
    result = attachInterface(reinterpret_cast<IONetworkInterface**>(&netif));

    if (!result) {
        IOLog("Ethernet [RealtekRTL8111]: attachInterface() failed.\n");
        goto error3;
    }
    pciDevice->close(this);
    result = true;
    
done:
    return result;

error3:
    RELEASE(commandGate);
        
error2:
    pciDevice->close(this);
    
error1:
    pciDevice->release();
    pciDevice = NULL;
    goto done;
}

void RTL8111::stop(IOService *provider)
{
    UInt32 i;
    
    if (netif) {
        detachInterface(netif);
        netif = NULL;
    }
    if (workLoop) {
        if (interruptSource) {
            workLoop->removeEventSource(interruptSource);
            RELEASE(interruptSource);
        }
        if (timerSource) {
            workLoop->removeEventSource(timerSource);
            RELEASE(timerSource);
        }
        workLoop->release();
        workLoop = NULL;
    }
    RELEASE(commandGate);
    RELEASE(txQueue);
    RELEASE(mediumDict);
    
    for (i = MEDIUM_INDEX_AUTO; i < MEDIUM_INDEX_COUNT; i++)
        mediumTable[i] = NULL;

    freeDMADescriptors();
    RELEASE(baseMap);
    baseAddr = NULL;
    linuxData.mmio_addr = NULL;

    RELEASE(pciDevice);
    
    super::stop(provider);
}

/* Power Management Support */
static IOPMPowerState powerStateArray[kPowerStateCount] =
{
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

IOReturn RTL8111::registerWithPolicyMaker(IOService *policyMaker)
{    
    DebugLog("registerWithPolicyMaker() ===>\n");
    
    powerState = kPowerStateOn;
    
    DebugLog("registerWithPolicyMaker() <===\n");

    return policyMaker->registerPowerDriver(this, powerStateArray, kPowerStateCount);
}

IOReturn RTL8111::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)
{
    IOReturn result = IOPMAckImplied;
    
    DebugLog("setPowerState() ===>\n");
        
    if (powerStateOrdinal == powerState) {
        DebugLog("Ethernet [RealtekRTL8111]: Already in power state %lu.\n", powerStateOrdinal);
        goto done;
    }
    DebugLog("Ethernet [RealtekRTL8111]: switching to power state %lu.\n", powerStateOrdinal);
    
    if (powerStateOrdinal == kPowerStateOff)
        commandGate->runAction(setPowerStateSleepAction);
    else
        commandGate->runAction(setPowerStateWakeAction);

    powerState = powerStateOrdinal;
    
done:
    DebugLog("setPowerState() <===\n");

    return result;
}

void RTL8111::systemWillShutdown(IOOptionBits specifier)
{
    DebugLog("systemWillShutdown() ===>\n");
    
    if ((kIOMessageSystemWillPowerOff | kIOMessageSystemWillRestart) & specifier) {
        disable(netif);
        
        /* Restore the original MAC address. */
        rtl8168_rar_set(&linuxData, (UInt8 *)&origMacAddr.bytes);
    }
    
    DebugLog("systemWillShutdown() <===\n");

    /* Must call super shutdown or system will stall. */
    super::systemWillShutdown(specifier);
}

/* IONetworkController methods. */
IOReturn RTL8111::enable(IONetworkInterface *netif)
{
    const IONetworkMedium *selectedMedium;
    IOReturn result = kIOReturnError;
    
    DebugLog("enable() ===>\n");

    if (isEnabled) {
        DebugLog("Ethernet [RealtekRTL8111]: Interface already enabled.\n");
        result = kIOReturnSuccess;
        goto done;
    }
    if (!pciDevice || pciDevice->isOpen()) {
        IOLog("Ethernet [RealtekRTL8111]: Unable to open PCI device.\n");
        goto done;
    }
    pciDevice->open(this);
    
    if (!setupDMADescriptors()) {
        IOLog("Ethernet [RealtekRTL8111]: Error allocating DMA descriptors.\n");
        goto done;
    }
    selectedMedium = getSelectedMedium();
    
    if (!selectedMedium) {
        DebugLog("Ethernet [RealtekRTL8111]: No medium selected. Falling back to autonegotiation.\n");
        selectedMedium = mediumTable[MEDIUM_INDEX_AUTO];
    }
    selectMedium(selectedMedium);
    enableRTL8111();
    
    /* We have to enable the interrupt because we are using a msi interrupt. */
    interruptSource->enable();

    txDescDoneCount = txDescDoneLast = 0;
    deadlockWarn = 0;
    needsUpdate = false;
    isEnabled = true;
    
#ifdef __PRIVATE_SPI__
    polling = false;
#else
    txQueue->setCapacity(kTransmitQueueCapacity);
    stalled = false;
#endif /* __PRIVATE_SPI__ */

    if (!revisionC)
        timerSource->setTimeoutMS(kTimeoutMS);
    
    result = kIOReturnSuccess;
    
    DebugLog("enable() <===\n");

done:
    return result;
}

IOReturn RTL8111::disable(IONetworkInterface *netif)
{
    IOReturn result = kIOReturnSuccess;
    
    DebugLog("disable() ===>\n");
    
    if (!isEnabled)
        goto done;
    
#ifdef __PRIVATE_SPI__
    netif->stopOutputThread();
    netif->flushOutputQueue();
    
    polling = false;
#else
    txQueue->stop();
    txQueue->flush();
    txQueue->setCapacity(0);
    stalled = false;
#endif /* __PRIVATE_SPI__ */

    isEnabled = false;

    timerSource->cancelTimeout();
    needsUpdate = false;
    txDescDoneCount = txDescDoneLast = 0;

    /* Disable interrupt as we are using msi. */
    interruptSource->disable();

    disableRTL8111();
    
    txClearDescriptors();
    
    if (pciDevice && pciDevice->isOpen())
        pciDevice->close(this);
    
    freeDMADescriptors();
    
    DebugLog("disable() <===\n");
    
done:
    return result;
}

#ifdef __PRIVATE_SPI__

IOReturn RTL8111::outputStart(IONetworkInterface *interface, IOOptionBits options )
{
    IOPhysicalSegment txSegments[kMaxSegs];
    mbuf_t m;
    RtlDmaDesc *desc, *firstDesc;
    IOReturn result = kIOReturnNoResources;
    UInt32 cmd;
    UInt32 opts2;
    mbuf_tso_request_flags_t tsoFlags;
    mbuf_csum_request_flags_t checksums;
    UInt32 mssValue;
    UInt32 opts1;
    UInt32 vlanTag;
    UInt32 numSegs;
    UInt32 lastSeg;
    UInt32 index;
    UInt32 i;
    
    //DebugLog("outputStart() ===>\n");
    
    if (!(isEnabled && linkUp)) {
        DebugLog("Ethernet [RealtekRTL8111]: Interface down. Dropping packets.\n");
        goto done;
    }
    while ((txNumFreeDesc > (kMaxSegs + 3)) && (interface->dequeueOutputPackets(1, &m, NULL, NULL, NULL) == kIOReturnSuccess)) {
        cmd = 0;
        opts2 = 0;

        if (mbuf_get_tso_requested(m, &tsoFlags, &mssValue)) {
            DebugLog("Ethernet [RealtekRTL8111]: mbuf_get_tso_requested() failed. Dropping packet.\n");
            freePacket(m);
            continue;
        }
        if (tsoFlags & (MBUF_TSO_IPV4 | MBUF_TSO_IPV6)) {
            if (tsoFlags & MBUF_TSO_IPV4) {
                getTso4Command(&cmd, &opts2, mssValue, tsoFlags);
            } else {
                /* The pseudoheader checksum has to be adjusted first. */
                adjustIPv6Header(m);
                getTso6Command(&cmd, &opts2, mssValue, tsoFlags);
            }
        } else {
            /* We use mssValue as a dummy here because it isn't needed anymore. */
            mbuf_get_csum_requested(m, &checksums, &mssValue);
            getChecksumCommand(&cmd, &opts2, checksums);
        }
        /* Finally get the physical segments. */
        numSegs = txMbufCursor->getPhysicalSegmentsWithCoalesce(m, &txSegments[0], kMaxSegs);

        /* Alloc required number of descriptors. As the descriptor which has been freed last must be
         * considered to be still in use we never fill the ring completely but leave at least one
         * unused.
         */
        if (!numSegs) {
            DebugLog("Ethernet [RealtekRTL8111]: getPhysicalSegmentsWithCoalesce() failed. Dropping packet.\n");
            freePacket(m);
            continue;
        }
        OSAddAtomic(-numSegs, &txNumFreeDesc);
        index = txNextDescIndex;
        txNextDescIndex = (txNextDescIndex + numSegs) & kTxDescMask;
        firstDesc = &txDescArray[index];
        lastSeg = numSegs - 1;
        
        /* Next fill in the VLAN tag. */
        opts2 |= (getVlanTagDemand(m, &vlanTag)) ? (OSSwapInt16(vlanTag) | TxVlanTag) : 0;
        
        /* And finally fill in the descriptors. */
        for (i = 0; i < numSegs; i++) {
            desc = &txDescArray[index];
            opts1 = (((UInt32)txSegments[i].length) | cmd);
            opts1 |= (i == 0) ? FirstFrag : DescOwn;
            
            if (i == lastSeg) {
                opts1 |= LastFrag;
                txMbufArray[index] = m;
            } else {
                txMbufArray[index] = NULL;
            }
            if (index == kTxLastDesc)
                opts1 |= RingEnd;
            
            desc->addr = OSSwapHostToLittleInt64(txSegments[i].location);
            desc->opts2 = OSSwapHostToLittleInt32(opts2);
            desc->opts1 = OSSwapHostToLittleInt32(opts1);
            
            //DebugLog("opts1=0x%x, opts2=0x%x, addr=0x%llx, len=0x%llx\n", opts1, opts2, txSegments[i].location, txSegments[i].length);
            ++index &= kTxDescMask;
        }
        firstDesc->opts1 |= DescOwn;
    }
    /* Set the polling bit. */
    WriteReg8(TxPoll, NPQ);

    result = (txNumFreeDesc > (kMaxSegs + 3)) ? kIOReturnSuccess : kIOReturnNoResources;
    
done:
    //DebugLog("outputStart() <===\n");
    
    return result;
}

#else

UInt32 RTL8111::outputPacket(mbuf_t m, void *param)
{
    IOPhysicalSegment txSegments[kMaxSegs];
    RtlDmaDesc *desc, *firstDesc;
    UInt32 result = kIOReturnOutputDropped;
    UInt32 cmd = 0;
    UInt32 opts2 = 0;
    mbuf_tso_request_flags_t tsoFlags;
    mbuf_csum_request_flags_t checksums;
    UInt32 mssValue;
    UInt32 opts1;
    UInt32 vlanTag;
    UInt32 numSegs;
    UInt32 lastSeg;
    UInt32 index;
    UInt32 i;
    
    //DebugLog("outputPacket() ===>\n");
    
    if (!(isEnabled && linkUp)) {
        DebugLog("Ethernet [RealtekRTL8111]: Interface down. Dropping packet.\n");
        goto error;
    }
    numSegs = txMbufCursor->getPhysicalSegmentsWithCoalesce(m, &txSegments[0], kMaxSegs);
    
    if (!numSegs) {
        DebugLog("Ethernet [RealtekRTL8111]: getPhysicalSegmentsWithCoalesce() failed. Dropping packet.\n");
        etherStats->dot3TxExtraEntry.resourceErrors++;
        goto error;
    }
    if (mbuf_get_tso_requested(m, &tsoFlags, &mssValue)) {
        DebugLog("Ethernet [RealtekRTL8111]: mbuf_get_tso_requested() failed. Dropping packet.\n");
        goto error;
    }
    if (tsoFlags & (MBUF_TSO_IPV4 | MBUF_TSO_IPV6)) {
        if (tsoFlags & MBUF_TSO_IPV4) {
            getTso4Command(&cmd, &opts2, mssValue, tsoFlags);
        } else {
            /* The pseudoheader checksum has to be adjusted first. */
            adjustIPv6Header(m);
            getTso6Command(&cmd, &opts2, mssValue, tsoFlags);
        }
    } else {
        /* We use mssValue as a dummy here because it isn't needed anymore. */
        mbuf_get_csum_requested(m, &checksums, &mssValue);
        getChecksumCommand(&cmd, &opts2, checksums);
    }
    /* Alloc required number of descriptors. As the descriptor which has been freed last must be
     * considered to be still in use we never fill the ring completely but leave at least one
     * unused.
     */
    if ((txNumFreeDesc <= numSegs)) {
        DebugLog("Ethernet [RealtekRTL8111]: Not enough descriptors. Stalling.\n");
        result = kIOReturnOutputStall;
        stalled = true;
        goto done;
    }
    OSAddAtomic(-numSegs, &txNumFreeDesc);
    index = txNextDescIndex;
    txNextDescIndex = (txNextDescIndex + numSegs) & kTxDescMask;
    firstDesc = &txDescArray[index];
    lastSeg = numSegs - 1;
    
    /* Next fill in the VLAN tag. */
    opts2 |= (getVlanTagDemand(m, &vlanTag)) ? (OSSwapInt16(vlanTag) | TxVlanTag) : 0;
    
    /* And finally fill in the descriptors. */
    for (i = 0; i < numSegs; i++) {
        desc = &txDescArray[index];
        opts1 = (((UInt32)txSegments[i].length) | cmd);
        opts1 |= (i == 0) ? FirstFrag : DescOwn;
        
        if (i == lastSeg) {
            opts1 |= LastFrag;
            txMbufArray[index] = m;
        } else {
            txMbufArray[index] = NULL;
        }
        if (index == kTxLastDesc)
            opts1 |= RingEnd;
        
        desc->addr = OSSwapHostToLittleInt64(txSegments[i].location);
        desc->opts2 = OSSwapHostToLittleInt32(opts2);
        desc->opts1 = OSSwapHostToLittleInt32(opts1);
        
        //DebugLog("opts1=0x%x, opts2=0x%x, addr=0x%llx, len=0x%llx\n", opts1, opts2, txSegments[i].location, txSegments[i].length);
        ++index &= kTxDescMask;
    }
    firstDesc->opts1 |= DescOwn;

    /* Set the polling bit. */
    WriteReg8(TxPoll, NPQ);
    
    result = kIOReturnOutputSuccess;

done:
    //DebugLog("outputPacket() <===\n");
    
    return result;
        
error:
    freePacket(m);
    goto done;
}

#endif /* __PRIVATE_SPI__ */

void RTL8111::getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const
{
    DebugLog("getPacketBufferConstraints() ===>\n");

	constraints->alignStart = kIOPacketBufferAlign8;
	constraints->alignLength = kIOPacketBufferAlign8;
    
    DebugLog("getPacketBufferConstraints() <===\n");
}

IOOutputQueue* RTL8111::createOutputQueue()
{
    DebugLog("createOutputQueue() ===>\n");
    
    DebugLog("createOutputQueue() <===\n");

    return IOBasicOutputQueue::withTarget(this);
}

const OSString* RTL8111::newVendorString() const
{
    DebugLog("newVendorString() ===>\n");
    
    DebugLog("newVendorString() <===\n");

    return OSString::withCString("Realtek");
}

const OSString* RTL8111::newModelString() const
{
    DebugLog("newModelString() ===>\n");
    DebugLog("newModelString() <===\n");
    
    return OSString::withCString(rtl_chip_info[linuxData.chipset].name);
}

bool RTL8111::configureInterface(IONetworkInterface *interface)
{
    char modelName[kNameLenght];
    IONetworkData *data;
    
#ifdef __PRIVATE_SPI__
    IOReturn error;
#endif /* __PRIVATE_SPI__ */

    bool result;

    DebugLog("configureInterface() ===>\n");

    result = super::configureInterface(interface);
    
    if (!result)
        goto done;
	
    /* Get the generic network statistics structure. */
    data = interface->getParameter(kIONetworkStatsKey);
    
    if (data) {
        netStats = (IONetworkStats *)data->getBuffer();
        
        if (!netStats) {
            IOLog("Ethernet [RealtekRTL8111]: Error getting IONetworkStats\n.");
            result = false;
            goto done;
        }
    }
    /* Get the Ethernet statistics structure. */    
    data = interface->getParameter(kIOEthernetStatsKey);
    
    if (data) {
        etherStats = (IOEthernetStats *)data->getBuffer();
        
        if (!etherStats) {
            IOLog("Ethernet [RealtekRTL8111]: Error getting IOEthernetStats\n.");
            result = false;
            goto done;
        }
    }
#ifdef __PRIVATE_SPI__
    error = interface->configureOutputPullModel(512, 0, 0, IONetworkInterface::kOutputPacketSchedulingModelNormal);
    
    if (error != kIOReturnSuccess) {
        IOLog("Ethernet [RealtekRTL8111]: configureOutputPullModel() failed\n.");
        result = false;
        goto done;
    }
    if (rxPoll) {
        error = interface->configureInputPacketPolling(kNumRxDesc, kIONetworkWorkLoopSynchronous);
        
        if (error != kIOReturnSuccess) {
            IOLog("Ethernet [RealtekRTL8111]: configureInputPacketPolling() failed\n.");
            result = false;
            goto done;
        }
    }
#endif /* __PRIVATE_SPI__ */

    snprintf(modelName, kNameLenght, "Realtek %s PCI Express Gigabit Ethernet", rtl_chip_info[linuxData.chipset].name);
    setProperty("model", modelName);
    
    DebugLog("configureInterface() <===\n");

done:
    return result;
}

bool RTL8111::createWorkLoop()
{
    DebugLog("createWorkLoop() ===>\n");
    
    workLoop = IOWorkLoop::workLoop();
    
    DebugLog("createWorkLoop() <===\n");

    return workLoop ? true : false;
}

IOWorkLoop* RTL8111::getWorkLoop() const
{
    DebugLog("getWorkLoop() ===>\n");
    
    DebugLog("getWorkLoop() <===\n");

    return workLoop;
}

/* Methods inherited from IOEthernetController. */
IOReturn RTL8111::getHardwareAddress(IOEthernetAddress *addr)
{
    IOReturn result = kIOReturnError;
    
    DebugLog("getHardwareAddress() ===>\n");
    
    if (addr) {
        if (gotPropMacAddr)
            bcopy(&propMacAddr.bytes, addr->bytes, kIOEthernetAddressSize);
        else
            bcopy(&currMacAddr.bytes, addr->bytes, kIOEthernetAddressSize);
        
        result = kIOReturnSuccess;
    }
    
    DebugLog("getHardwareAddress() <===\n");

    return result;
}

IOReturn RTL8111::setPromiscuousMode(bool active)
{
    UInt32 *filterAddr = (UInt32 *)&multicastFilter;
    UInt32 mcFilter[2];
    UInt32 rxMode;

    DebugLog("setPromiscuousMode() ===>\n");
    
    if (active) {
        DebugLog("Ethernet [RealtekRTL8111]: Promiscuous mode enabled.\n");
        rxMode = (AcceptBroadcast | AcceptMulticast | AcceptMyPhys | AcceptAllPhys);
        mcFilter[1] = mcFilter[0] = 0xffffffff;
    } else {
        DebugLog("Ethernet [RealtekRTL8111]: Promiscuous mode disabled.\n");
        rxMode = (AcceptBroadcast | AcceptMulticast | AcceptMyPhys);
        mcFilter[0] = *filterAddr++;
        mcFilter[1] = *filterAddr;
    }
    promiscusMode = active;
    rxMode |= rxConfigReg | (ReadReg32(RxConfig) & rxConfigMask);
    WriteReg32(RxConfig, rxMode);
    WriteReg32(MAR0, mcFilter[0]);
    WriteReg32(MAR1, mcFilter[1]);

    DebugLog("setPromiscuousMode() <===\n");

    return kIOReturnSuccess;
}

IOReturn RTL8111::setMulticastMode(bool active)
{    
    UInt32 *filterAddr = (UInt32 *)&multicastFilter;
    UInt32 mcFilter[2];
    UInt32 rxMode;

    DebugLog("setMulticastMode() ===>\n");
    
    if (active) {
        rxMode = (AcceptBroadcast | AcceptMulticast | AcceptMyPhys);
        mcFilter[0] = *filterAddr++;
        mcFilter[1] = *filterAddr;
    } else{
        rxMode = (AcceptBroadcast | AcceptMyPhys);
        mcFilter[1] = mcFilter[0] = 0;
    }
    multicastMode = active;
    rxMode |= rxConfigReg | (ReadReg32(RxConfig) & rxConfigMask);
    WriteReg32(RxConfig, rxMode);
    WriteReg32(MAR0, mcFilter[0]);
    WriteReg32(MAR1, mcFilter[1]);
    
    DebugLog("setMulticastMode() <===\n");
    
    return kIOReturnSuccess;
}

IOReturn RTL8111::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
    UInt32 *filterAddr = (UInt32 *)&multicastFilter;
    UInt64 filter = 0;
    UInt32 i, bitNumber;
    
    DebugLog("setMulticastList() ===>\n");
    
    /* Chipset 17 doesn't include a multicast filter. */
    if ((count <= kMCFilterLimit) && (linuxData.mcfg != CFG_METHOD_18)) {
        for (i = 0; i < count; i++, addrs++) {
            bitNumber = ether_crc(6, reinterpret_cast<unsigned char *>(addrs)) >> 26;
            filter |= (1 << (bitNumber & 0x3f));
        }
        multicastFilter = OSSwapInt64(filter);
    } else {
        multicastFilter = 0xffffffffffffffff;
    }
    WriteReg32(MAR0, *filterAddr++);
    WriteReg32(MAR1, *filterAddr);

    DebugLog("setMulticastList() <===\n");

    return kIOReturnSuccess;
}

IOReturn RTL8111::getChecksumSupport(UInt32 *checksumMask, UInt32 checksumFamily, bool isOutput)
{
    IOReturn result = kIOReturnUnsupported;

    DebugLog("getChecksumSupport() ===>\n");

    if ((checksumFamily == kChecksumFamilyTCPIP) && checksumMask) {
        if (isOutput) {
            if (revisionC)
                *checksumMask = (enableCSO6) ? (kChecksumTCP | kChecksumUDP | kChecksumIP | kChecksumTCPIPv6 | kChecksumUDPIPv6) : (kChecksumTCP | kChecksumUDP | kChecksumIP);
            else
                *checksumMask = (kChecksumTCP | kChecksumUDP | kChecksumIP);
        } else {
            *checksumMask = (revisionC) ? (kChecksumTCP | kChecksumUDP | kChecksumIP | kChecksumTCPIPv6 | kChecksumUDPIPv6) : (kChecksumTCP | kChecksumUDP | kChecksumIP);
        }
        result = kIOReturnSuccess;
    }
    DebugLog("getChecksumSupport() <===\n");

    return result;
}

UInt32 RTL8111::getFeatures() const
{
    UInt32 features = (kIONetworkFeatureMultiPages | kIONetworkFeatureHardwareVlan);
    
    DebugLog("getFeatures() ===>\n");
    
    if (enableTSO4)
        features |= kIONetworkFeatureTSOIPv4;
    
    if (enableTSO6 && revisionC)
        features |= kIONetworkFeatureTSOIPv6;
    
    DebugLog("getFeatures() <===\n");
    
    return features;
}

IOReturn RTL8111::setWakeOnMagicPacket(bool active)
{
    IOReturn result = kIOReturnUnsupported;

    DebugLog("setWakeOnMagicPacket() ===>\n");

    if (wolCapable) {
        linuxData.wol_enabled = active ? WOL_ENABLED : WOL_DISABLED;
        wolActive = active;
        result = kIOReturnSuccess;
    }
    
    DebugLog("setWakeOnMagicPacket() <===\n");

    return result;
}

IOReturn RTL8111::getPacketFilters(const OSSymbol *group, UInt32 *filters) const
{
    IOReturn result = kIOReturnSuccess;

    DebugLog("getPacketFilters() ===>\n");

    if ((group == gIOEthernetWakeOnLANFilterGroup) && wolCapable) {
        *filters = kIOEthernetWakeOnMagicPacket;
        DebugLog("Ethernet [RealtekRTL8111]: kIOEthernetWakeOnMagicPacket added to filters.\n");
    } else {
        result = super::getPacketFilters(group, filters);
    }
    
    DebugLog("getPacketFilters() <===\n");

    return result;
}

IOReturn RTL8111::setHardwareAddress(const IOEthernetAddress *addr)
{
    IOReturn result = kIOReturnError;
    
    DebugLog("setHardwareAddress() ===>\n");
    
    if (addr) {
        bcopy(addr->bytes, &currMacAddr.bytes, kIOEthernetAddressSize);
        rtl8168_rar_set(&linuxData, (UInt8 *)&currMacAddr.bytes);
        result = kIOReturnSuccess;
    }
    
    DebugLog("setHardwareAddress() <===\n");
    
    return result;
}

IOReturn RTL8111::selectMedium(const IONetworkMedium *medium)
{
    IOReturn result = kIOReturnSuccess;
    
    DebugLog("selectMedium() ===>\n");
    
    if (medium) {
        flowCtl = kFlowControlOff;
        eeeAdv = 0;
        
        switch (medium->getIndex()) {
            case MEDIUM_INDEX_AUTO:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                eeeAdv = eeeCap;
                break;
                
            case MEDIUM_INDEX_10HD:
                autoneg = AUTONEG_DISABLE;
                speed = SPEED_10;
                duplex = DUPLEX_HALF;
                break;
                
            case MEDIUM_INDEX_10FD:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_10;
                duplex = DUPLEX_FULL;
                break;
                
            case MEDIUM_INDEX_100HD:
                autoneg = AUTONEG_DISABLE;
                speed = SPEED_100;
                duplex = DUPLEX_HALF;
                break;
                
            case MEDIUM_INDEX_100FD:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_100;
                duplex = DUPLEX_FULL;
                break;
                
            case MEDIUM_INDEX_100FDFC:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_100;
                duplex = DUPLEX_FULL;
                flowCtl = kFlowControlOn;
                break;
                
            case MEDIUM_INDEX_1000FD:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                break;
                
            case MEDIUM_INDEX_1000FDFC:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                flowCtl = kFlowControlOn;
                break;
                
            case MEDIUM_INDEX_100FDEEE:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_100;
                duplex = DUPLEX_FULL;
                eeeAdv = eeeCap;
                break;
                
            case MEDIUM_INDEX_100FDFCEEE:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_100;
                duplex = DUPLEX_FULL;
                flowCtl = kFlowControlOn;
                eeeAdv = eeeCap;
                break;
                
            case MEDIUM_INDEX_1000FDEEE:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                eeeAdv = eeeCap;
                break;
                
            case MEDIUM_INDEX_1000FDFCEEE:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                flowCtl = kFlowControlOn;
                eeeAdv = eeeCap;
                break;
        }
        setPhyMedium();
        setCurrentMedium(medium);
    }
    
    DebugLog("selectMedium() <===\n");
    
done:
    return result;
}

#pragma mark --- data structure initialization methods ---

void RTL8111::getParams()
{
    OSNumber *intrMit;
    OSBoolean *enableEEE;

#ifdef __PRIVATE_SPI__
    OSBoolean *poll;
#endif /* __PRIVATE_SPI__ */

    OSBoolean *tso4;
    OSBoolean *tso6;
    OSBoolean *csoV6;
    OSBoolean *noASPM;
    OSString *versionString;
    OSString *hardwareAddress;
    
    noASPM = OSDynamicCast(OSBoolean, getProperty(kDisableASPMName));
    disableASPM = (noASPM) ? noASPM->getValue() : false;
    
    DebugLog("Ethernet [RealtekRTL8111]: PCIe ASPM support %s.\n", disableASPM ? offName : onName);
    
    enableEEE = OSDynamicCast(OSBoolean, getProperty(kEnableEeeName));
    
    if (enableEEE)
        linuxData.eeeEnable = (enableEEE->getValue()) ? 1 : 0;
    else
        linuxData.eeeEnable = 0;
    
    IOLog("Ethernet [RealtekRTL8111]: EEE support %s.\n", linuxData.eeeEnable ? onName : offName);
    
#ifdef __PRIVATE_SPI__
    poll = OSDynamicCast(OSBoolean, getProperty(kEnableRxPollName));
    rxPoll = (poll) ? poll->getValue() : false;
    
    IOLog("Ethernet [RealtekRTL8111]: RxPoll support %s.\n", rxPoll ? onName : offName);
#endif /* __PRIVATE_SPI__ */

    tso4 = OSDynamicCast(OSBoolean, getProperty(kEnableTSO4Name));
    enableTSO4 = (tso4) ? tso4->getValue() : false;
    
    IOLog("Ethernet [RealtekRTL8111]: TCP/IPv4 segmentation offload %s.\n", enableTSO4 ? onName : offName);
    
    tso6 = OSDynamicCast(OSBoolean, getProperty(kEnableTSO6Name));
    enableTSO6 = (tso6) ? tso6->getValue() : false;
    
    IOLog("Ethernet [RealtekRTL8111]: TCP/IPv6 segmentation offload %s.\n", enableTSO6 ? onName : offName);
    
    csoV6 = OSDynamicCast(OSBoolean, getProperty(kEnableCSO6Name));
    enableCSO6 = (csoV6) ? csoV6->getValue() : false;
    
    IOLog("Ethernet [RealtekRTL8111]: TCP/IPv6 checksum offload %s.\n", enableCSO6 ? onName : offName);
    
    intrMit = OSDynamicCast(OSNumber, getProperty(kIntrMitigateName));
    
    if (intrMit)
        intrMitigateValue = intrMit->unsigned16BitValue();
    
    hardwareAddress = OSDynamicCast(OSString, getProperty(kHardwareAddress));
    
    int numBytes = 0;
    if (hardwareAddress && hardwareAddress->getLength() == 12)
        numBytes = sscanf(hardwareAddress->getCStringNoCopy(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
               &propMacAddr.bytes[0], &propMacAddr.bytes[1],
               &propMacAddr.bytes[2], &propMacAddr.bytes[3],
               &propMacAddr.bytes[4], &propMacAddr.bytes[5]);
    
    gotPropMacAddr = (6 == numBytes) ? true: false;
    
    if (gotPropMacAddr)
        IOLog("Ethernet [RealtekRTL8111]: Got custom MAC address %02x:%02x:%02x:%02x:%02x:%02x.\n",
          propMacAddr.bytes[0], propMacAddr.bytes[1],
          propMacAddr.bytes[2], propMacAddr.bytes[3],
          propMacAddr.bytes[4], propMacAddr.bytes[5]);
    
    versionString = OSDynamicCast(OSString, getProperty(kDriverVersionName));
    
    if (versionString)
        IOLog("Ethernet [RealtekRTL8111]: Version %s using interrupt mitigate value 0x%x. Please don't support tonymacx86.com!\n", versionString->getCStringNoCopy(), intrMitigateValue);
    else
        IOLog("Ethernet [RealtekRTL8111]: Using interrupt mitigate value 0x%x. Please don't support tonymacx86.com!\n", intrMitigateValue);
}

static IOMediumType mediumTypeArray[MEDIUM_INDEX_COUNT] = {
    kIOMediumEthernetAuto,
    (kIOMediumEthernet10BaseT | kIOMediumOptionHalfDuplex),
    (kIOMediumEthernet10BaseT | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionHalfDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionEEE),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl | kIOMediumOptionEEE),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionEEE),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl | kIOMediumOptionEEE)
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
    IOLog("Ethernet [RealtekRTL8111]: Error creating medium dictionary.\n");
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
        IOLog("Ethernet [RealtekRTL8111]: Failed to get output queue.\n");
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
        DebugLog("Ethernet [RealtekRTL8111]: MSI interrupt index: %d\n", msiIndex);
        
        interruptSource = IOInterruptEventSource::interruptEventSource(this, OSMemberFunctionCast(IOInterruptEventSource::Action, this, &RTL8111::interruptOccurred), provider, msiIndex);
    }
    if (!interruptSource) {
        IOLog("Ethernet [RealtekRTL8111]: Error: MSI index was not found or MSI interrupt could not be enabled.\n");
        goto error1;
    }
    workLoop->addEventSource(interruptSource);
    
    if (revisionC)
        timerSource = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &RTL8111::timerActionRTL8111C));
    else
        timerSource = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &RTL8111::timerActionRTL8111B));
    
    if (!timerSource) {
        IOLog("Ethernet [RealtekRTL8111]: Failed to create IOTimerEventSource.\n");
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
    IOLog("Ethernet [RealtekRTL8111]: Error initializing event sources.\n");
    txQueue->release();
    txQueue = NULL;
    goto done;
}

bool RTL8111::setupDMADescriptors()
{
    IOPhysicalSegment rxSegment;
    mbuf_t spareMbuf[kRxNumSpareMbufs];
    mbuf_t m;
    UInt32 i;
    UInt32 opts1;
    bool result = false;
    
    /* Create transmitter descriptor array. */
    txBufDesc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, (kIODirectionInOut | kIOMemoryPhysicallyContiguous | kIOMapInhibitCache), kTxDescSize, 0xFFFFFFFFFFFFFF00ULL);
            
    if (!txBufDesc) {
        IOLog("Ethernet [RealtekRTL8111]: Couldn't alloc txBufDesc.\n");
        goto done;
    }
    if (txBufDesc->prepare() != kIOReturnSuccess) {
        IOLog("Ethernet [RealtekRTL8111]: txBufDesc->prepare() failed.\n");
        goto error1;
    }
    txDescArray = (RtlDmaDesc *)txBufDesc->getBytesNoCopy();
    txPhyAddr = OSSwapHostToLittleInt64(txBufDesc->getPhysicalAddress());
    
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
        IOLog("Ethernet [RealtekRTL8111]: Couldn't create txMbufCursor.\n");
        goto error2;
    }
    
    /* Create receiver descriptor array. */
    rxBufDesc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, (kIODirectionInOut | kIOMemoryPhysicallyContiguous | kIOMapInhibitCache), kRxDescSize, 0xFFFFFFFFFFFFFF00ULL);
    
    if (!rxBufDesc) {
        IOLog("Ethernet [RealtekRTL8111]: Couldn't alloc rxBufDesc.\n");
        goto error3;
    }
    
    if (rxBufDesc->prepare() != kIOReturnSuccess) {
        IOLog("Ethernet [RealtekRTL8111]: rxBufDesc->prepare() failed.\n");
        goto error4;
    }
    rxDescArray = (RtlDmaDesc *)rxBufDesc->getBytesNoCopy();
    rxPhyAddr = OSSwapHostToLittleInt64(rxBufDesc->getPhysicalAddress());
    
    /* Initialize rxDescArray. */
    bzero(rxDescArray, kRxDescSize);
    rxDescArray[kRxLastDesc].opts1 = OSSwapHostToLittleInt32(RingEnd);

    for (i = 0; i < kNumRxDesc; i++) {
        rxMbufArray[i] = NULL;
    }
    rxNextDescIndex = 0;
    
    rxMbufCursor = IOMbufNaturalMemoryCursor::withSpecification(PAGE_SIZE, 1);
    
    if (!rxMbufCursor) {
        IOLog("Ethernet [RealtekRTL8111]: Couldn't create rxMbufCursor.\n");
        goto error5;
    }
    /* Alloc receive buffers. */
    for (i = 0; i < kNumRxDesc; i++) {
        m = allocatePacket(kRxBufferPktSize);
        
        if (!m) {
            IOLog("Ethernet [RealtekRTL8111]: Couldn't alloc receive buffer.\n");
            goto error6;
        }
        rxMbufArray[i] = m;
        
        if (rxMbufCursor->getPhysicalSegments(m, &rxSegment, 1) != 1) {
            IOLog("Ethernet [RealtekRTL8111]: getPhysicalSegments() for receive buffer failed.\n");
            goto error6;
        }
        opts1 = (UInt32)rxSegment.length;
        opts1 |= (i == kRxLastDesc) ? (RingEnd | DescOwn) : DescOwn;
        rxDescArray[i].opts1 = OSSwapHostToLittleInt32(opts1);
        rxDescArray[i].opts2 = 0;
        rxDescArray[i].addr = OSSwapHostToLittleInt64(rxSegment.location);
    }
    /* Create statistics dump buffer. */
    statBufDesc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, (kIODirectionIn | kIOMemoryPhysicallyContiguous | kIOMapInhibitCache), sizeof(RtlStatData), 0xFFFFFFFFFFFFFF00ULL);
    
    if (!statBufDesc) {
        IOLog("Ethernet [RealtekRTL8111]: Couldn't alloc statBufDesc.\n");
        goto error6;
    }
    
    if (statBufDesc->prepare() != kIOReturnSuccess) {
        IOLog("Ethernet [RealtekRTL8111]: statBufDesc->prepare() failed.\n");
        goto error7;
    }
    statData = (RtlStatData *)statBufDesc->getBytesNoCopy();
    statPhyAddr = OSSwapHostToLittleInt64(statBufDesc->getPhysicalAddress());
    
    /* Initialize statData. */
    bzero(statData, sizeof(RtlStatData));

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

error7:
    statBufDesc->release();
    statBufDesc = NULL;
    
error6:
    for (i = 0; i < kNumRxDesc; i++) {
        if (rxMbufArray[i]) {
            freePacket(rxMbufArray[i]);
            rxMbufArray[i] = NULL;
        }
    }
    RELEASE(rxMbufCursor);

error5:
    rxBufDesc->complete();
    
error4:
    rxBufDesc->release();
    rxBufDesc = NULL;

error3:
    RELEASE(txMbufCursor);
    
error2:
    txBufDesc->complete();

error1:
    txBufDesc->release();
    txBufDesc = NULL;
    goto done;
}

void RTL8111::freeDMADescriptors()
{
    UInt32 i;
    
    if (txBufDesc) {
        txBufDesc->complete();
        txBufDesc->release();
        txBufDesc = NULL;
        txPhyAddr = NULL;
    }
    RELEASE(txMbufCursor);
    
    if (rxBufDesc) {
        rxBufDesc->complete();
        rxBufDesc->release();
        rxBufDesc = NULL;
        rxPhyAddr = NULL;
    }
    RELEASE(rxMbufCursor);
    
    for (i = 0; i < kNumRxDesc; i++) {
        if (rxMbufArray[i]) {
            freePacket(rxMbufArray[i]);
            rxMbufArray[i] = NULL;
        }
    }
    if (statBufDesc) {
        statBufDesc->complete();
        statBufDesc->release();
        statBufDesc = NULL;
        statPhyAddr = NULL;
        statData = NULL;
    }
}

void RTL8111::txClearDescriptors()
{
    mbuf_t m;
    UInt32 lastIndex = kTxLastDesc;
    UInt32 i;
    
    DebugLog("txClearDescriptors() ===>\n");
    
    if (txNext2FreeMbuf) {
        freePacket(txNext2FreeMbuf);
        txNext2FreeMbuf = NULL;
    }
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
    
    DebugLog("txClearDescriptors() <===\n");
}

#pragma mark --- common interrupt methods ---

void RTL8111::pciErrorInterrupt()
{
    UInt16 cmdReg = pciDevice->configRead16(kIOPCIConfigCommand);
    UInt16 statusReg = pciDevice->configRead16(kIOPCIConfigStatus);
    
    DebugLog("Ethernet [RealtekRTL8111]: PCI error: cmdReg=0x%x, statusReg=0x%x\n", cmdReg, statusReg);

    cmdReg |= (kIOPCICommandSERR | kIOPCICommandParityError);
    statusReg &= (kIOPCIStatusParityErrActive | kIOPCIStatusSERRActive | kIOPCIStatusMasterAbortActive | kIOPCIStatusTargetAbortActive | kIOPCIStatusTargetAbortCapable);
    pciDevice->configWrite16(kIOPCIConfigCommand, cmdReg);
    pciDevice->configWrite16(kIOPCIConfigStatus, statusReg);
    
    /* Reset the NIC in order to resume operation. */
    restartRTL8111();
}

/* Some (all?) of the RTL8111 family members don't handle descriptors properly.
 * They randomly release control of descriptors pointing to certain packets
 * before the request has been completed and reclaim them later.
 *
 * As a workaround we should:
 * - leave returned descriptors untouched until they get reused.
 * - never reuse the descriptor which has been returned last, i.e. leave at
 *   least one of the descriptors in txDescArray unused.
 * - delay freeing packets until the next descriptor has been finished or a
 *   small period of time has passed (as these packets are really small a
 *   few µ secs should be enough).
 */

void RTL8111::txInterrupt()
{
    SInt32 numDirty = kNumTxDesc - txNumFreeDesc;
    UInt32 oldDirtyIndex = txDirtyDescIndex;
    UInt32 descStatus;
    
    while (numDirty-- > 0) {
        descStatus = OSSwapLittleToHostInt32(txDescArray[txDirtyDescIndex].opts1);
        
        if (descStatus & DescOwn)
            break;

        /* Now it's time to free the last mbuf as we can be sure it's not in use anymore. */
        if (txNext2FreeMbuf)
            freePacket(txNext2FreeMbuf, kDelayFree);

        txNext2FreeMbuf = txMbufArray[txDirtyDescIndex];
        txMbufArray[txDirtyDescIndex] = NULL;
        txDescDoneCount++;
        OSIncrementAtomic(&txNumFreeDesc);
        ++txDirtyDescIndex &= kTxDescMask;
    }
#ifdef __PRIVATE_SPI__
    if (oldDirtyIndex != txDirtyDescIndex) {
        if (txNumFreeDesc > kTxQueueWakeTreshhold)
            netif->signalOutputThread();
        
        WriteReg8(TxPoll, NPQ);
        releaseFreePackets();
    }
    if (!polling)
        etherStats->dot3TxExtraEntry.interrupts++;
#else
    if (stalled && (txNumFreeDesc > kTxQueueWakeTreshhold)) {
        DebugLog("Ethernet [RealtekRTL8111]: Restart stalled queue!\n");
        txQueue->service(IOBasicOutputQueue::kServiceAsync);
        stalled = false;
    }
    if (oldDirtyIndex != txDirtyDescIndex) {
        WriteReg8(TxPoll, NPQ);
        releaseFreePackets();
    }
    etherStats->dot3TxExtraEntry.interrupts++;
#endif /* __PRIVATE_SPI__ */
    
}

#ifdef __PRIVATE_SPI__

UInt32 RTL8111::rxInterrupt(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context)
{
    IOPhysicalSegment rxSegment;
    RtlDmaDesc *desc = &rxDescArray[rxNextDescIndex];
    mbuf_t bufPkt, newPkt;
    UInt64 addr;
    UInt32 opts1, opts2;
    UInt32 descStatus1, descStatus2;
    UInt32 pktSize;
    UInt32 goodPkts = 0;
    UInt16 vlanTag;
    bool replaced;
    
    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->opts1)) & DescOwn) && (goodPkts < maxCount)) {
        opts1 = (rxNextDescIndex == kRxLastDesc) ? (RingEnd | DescOwn) : DescOwn;
        opts2 = 0;
        addr = 0;
        
        /* As we don't support jumbo frames we consider fragmented packets as errors. */
        if ((descStatus1 & (FirstFrag|LastFrag)) != (FirstFrag|LastFrag)) {
            DebugLog("Ethernet [RealtekRTL8111]: Fragmented packet.\n");
            etherStats->dot3StatsEntry.frameTooLongs++;
            opts1 |= kRxBufferPktSize;
            goto nextDesc;
        }
        
        descStatus2 = OSSwapLittleToHostInt32(desc->opts2);
        pktSize = (descStatus1 & 0x1fff) - kIOEthernetCRCSize;
        bufPkt = rxMbufArray[rxNextDescIndex];
        vlanTag = (descStatus2 & RxVlanTag) ? OSSwapInt16(descStatus2 & 0xffff) : 0;
        //DebugLog("rxInterrupt(): descStatus1=0x%x, descStatus2=0x%x, pktSize=%u\n", descStatus1, descStatus2, pktSize);
        
        newPkt = replaceOrCopyPacket(&bufPkt, pktSize, &replaced);
        
        if (!newPkt) {
            /* Allocation of a new packet failed so that we must leave the original packet in place. */
            DebugLog("Ethernet [RealtekRTL8111]: replaceOrCopyPacket() failed.\n");
            etherStats->dot3RxExtraEntry.resourceErrors++;
            opts1 |= kRxBufferPktSize;
            goto nextDesc;
        }
        
        /* If the packet was replaced we have to update the descriptor's buffer address. */
        if (replaced) {
            if (rxMbufCursor->getPhysicalSegments(bufPkt, &rxSegment, 1) != 1) {
                DebugLog("Ethernet [RealtekRTL8111]: getPhysicalSegments() failed.\n");
                etherStats->dot3RxExtraEntry.resourceErrors++;
                freePacket(bufPkt);
                opts1 |= kRxBufferPktSize;
                goto nextDesc;
            }
            opts1 |= ((UInt32)rxSegment.length & 0x0000ffff);
            addr = rxSegment.location;
            rxMbufArray[rxNextDescIndex] = bufPkt;
        } else {
            opts1 |= kRxBufferPktSize;
        }
        getChecksumResult(newPkt, descStatus1, descStatus2);
        
        /* Also get the VLAN tag if there is any. */
        if (vlanTag)
            setVlanTag(newPkt, vlanTag);
        
        mbuf_pkthdr_setlen(newPkt, pktSize);
        mbuf_setlen(newPkt, pktSize);
        interface->enqueueInputPacket(newPkt, pollQueue);
        goodPkts++;
        
        /* Finally update the descriptor and get the next one to examine. */
    nextDesc:
        if (addr)
            desc->addr = OSSwapHostToLittleInt64(addr);
        
        desc->opts2 = OSSwapHostToLittleInt32(opts2);
        desc->opts1 = OSSwapHostToLittleInt32(opts1);
        
        ++rxNextDescIndex &= kRxDescMask;
        desc = &rxDescArray[rxNextDescIndex];
    }
    return goodPkts;
}

#else

void RTL8111::rxInterrupt()
{
    IOPhysicalSegment rxSegment;
    RtlDmaDesc *desc = &rxDescArray[rxNextDescIndex];
    mbuf_t bufPkt, newPkt;
    UInt64 addr;
    UInt32 opts1, opts2;
    UInt32 descStatus1, descStatus2;
    UInt32 pktSize;
    UInt16 vlanTag;
    UInt16 goodPkts = 0;
    bool replaced;
    
    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->opts1)) & DescOwn)) {
        opts1 = (rxNextDescIndex == kRxLastDesc) ? (RingEnd | DescOwn) : DescOwn;
        opts2 = 0;
        addr = 0;
        
        /* As we don't support jumbo frames we consider fragmented packets as errors. */
        if ((descStatus1 & (FirstFrag|LastFrag)) != (FirstFrag|LastFrag)) {
            DebugLog("Ethernet [RealtekRTL8111]: Fragmented packet.\n");
            etherStats->dot3StatsEntry.frameTooLongs++;
            opts1 |= kRxBufferPktSize;
            goto nextDesc;
        }
        
        descStatus2 = OSSwapLittleToHostInt32(desc->opts2);
        pktSize = (descStatus1 & 0x1fff) - kIOEthernetCRCSize;
        bufPkt = rxMbufArray[rxNextDescIndex];
        vlanTag = (descStatus2 & RxVlanTag) ? OSSwapInt16(descStatus2 & 0xffff) : 0;
        //DebugLog("rxInterrupt(): descStatus1=0x%x, descStatus2=0x%x, pktSize=%u\n", descStatus1, descStatus2, pktSize);
        
        newPkt = replaceOrCopyPacket(&bufPkt, pktSize, &replaced);
        
        if (!newPkt) {
            /* Allocation of a new packet failed so that we must leave the original packet in place. */
            DebugLog("Ethernet [RealtekRTL8111]: replaceOrCopyPacket() failed.\n");
            etherStats->dot3RxExtraEntry.resourceErrors++;
            opts1 |= kRxBufferPktSize;
            goto nextDesc;
        }
        
        /* If the packet was replaced we have to update the descriptor's buffer address. */
        if (replaced) {
            if (rxMbufCursor->getPhysicalSegments(bufPkt, &rxSegment, 1) != 1) {
                DebugLog("Ethernet [RealtekRTL8111]: getPhysicalSegments() failed.\n");
                etherStats->dot3RxExtraEntry.resourceErrors++;
                freePacket(bufPkt);
                opts1 |= kRxBufferPktSize;
                goto nextDesc;
            }
            opts1 |= ((UInt32)rxSegment.length & 0x0000ffff);
            addr = rxSegment.location;
            rxMbufArray[rxNextDescIndex] = bufPkt;
        } else {
            opts1 |= kRxBufferPktSize;
        }
        getChecksumResult(newPkt, descStatus1, descStatus2);
        
        /* Also get the VLAN tag if there is any. */
        if (vlanTag)
            setVlanTag(newPkt, vlanTag);
        
        netif->inputPacket(newPkt, pktSize, IONetworkInterface::kInputOptionQueuePacket);
        goodPkts++;
        
        /* Finally update the descriptor and get the next one to examine. */
    nextDesc:
        if (addr)
            desc->addr = OSSwapHostToLittleInt64(addr);
        
        desc->opts2 = OSSwapHostToLittleInt32(opts2);
        desc->opts1 = OSSwapHostToLittleInt32(opts1);
        
        ++rxNextDescIndex &= kRxDescMask;
        desc = &rxDescArray[rxNextDescIndex];
    }
    if (goodPkts)
        netif->flushInputQueue();
}

#endif /* __PRIVATE_SPI__ */

void RTL8111::checkLinkStatus()
{
    struct rtl8168_private *tp = &linuxData;
	UInt8 currLinkState;
    
    if (tp->mcfg == CFG_METHOD_11)
		rtl8168dp_10mbps_gphy_para(tp);
    
    currLinkState = ReadReg8(PHYstatus);
    
	if (currLinkState & LinkStatus) {
		if (tp->mcfg == CFG_METHOD_18 || tp->mcfg == CFG_METHOD_19 || tp->mcfg == CFG_METHOD_20) {
			if (currLinkState & _1000bpsF) {
				rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x00000011, ERIAR_ExGMAC);
				rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x00000005, ERIAR_ExGMAC);
			} else {
				rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x0000001f, ERIAR_ExGMAC);
				rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x0000003f, ERIAR_ExGMAC);
			}
		} else if ((tp->mcfg == CFG_METHOD_16 || tp->mcfg == CFG_METHOD_17) && isEnabled) {
			if (tp->mcfg == CFG_METHOD_16 && (currLinkState & _10bps)) {
				WriteReg32(RxConfig, ReadReg32(RxConfig) | AcceptAllPhys);
			} else if (tp->mcfg == CFG_METHOD_17) {
				if (currLinkState & _1000bpsF) {
					rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x00000011, ERIAR_ExGMAC);
					rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x00000005, ERIAR_ExGMAC);
				} else if (currLinkState & _100bps) {
					rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x0000001f, ERIAR_ExGMAC);
					rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x00000005, ERIAR_ExGMAC);
				} else {
					rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x0000001f, ERIAR_ExGMAC);
					rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x0000003f, ERIAR_ExGMAC);
				}
			}
		} else if ((tp->mcfg == CFG_METHOD_14 || tp->mcfg == CFG_METHOD_15) && linuxData.eeeEnable == 1){
			//Full -Duplex  mode
			if (currLinkState & FullDup) {
				mdio_write(tp, 0x1F, 0x0006);
				mdio_write(tp, 0x00, 0x5a30);
				mdio_write(tp, 0x1F, 0x0000);
                
				if (currLinkState & (_10bps | _100bps))
					WriteReg32(TxConfig, (ReadReg32(TxConfig) & ~BIT_19) | BIT_25);
			} else {
				mdio_write(tp, 0x1F, 0x0006);
				mdio_write(tp, 0x00, 0x5a00);
				mdio_write(tp, 0x1F, 0x0000);
                
				if (currLinkState & (_10bps | _100bps))
					WriteReg32(TxConfig, (ReadReg32(TxConfig) & ~BIT_19) | (InterFrameGap << TxInterFrameGapShift));
			}
		} else if ((tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
                    tp->mcfg == CFG_METHOD_23 || tp->mcfg == CFG_METHOD_24 ||
                    tp->mcfg == CFG_METHOD_25 || tp->mcfg == CFG_METHOD_26 ||
                    tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28 ||
                    tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) && isEnabled) {
            if (currLinkState & FullDup) {
                WriteReg32(TxConfig, (ReadReg32(TxConfig) | (BIT_24 | BIT_25)) & ~BIT_19);
            } else {
                WriteReg32(TxConfig, (ReadReg32(TxConfig) | BIT_25) & ~(BIT_19 | BIT_24));
                
                if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
                    tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28) {
                    /*half mode*/
                    mdio_write(tp, 0x1F, 0x0000);
                    mdio_write(tp, MII_ADVERTISE, mdio_read(tp, MII_ADVERTISE)&~(ADVERTISE_PAUSE_CAP|ADVERTISE_PAUSE_ASYM));
                }
            }
		}
        setLinkUp(currLinkState);
        timerSource->setTimeoutMS(kTimeoutMS);
	} else {
        /* Stop watchdog and statistics updates. */
        timerSource->cancelTimeout();
        setLinkDown();
        
		if (tp->mcfg == CFG_METHOD_23) {
			WriteReg32(ERIDR, 0x00000001);
			WriteReg32(ERIAR, 0x8042f108);
		}
	}
}

void RTL8111::interruptOccurred(OSObject *client, IOInterruptEventSource *src, int count)
{
    UInt64 time, abstime;
    
#ifdef __PRIVATE_SPI__
    UInt32 packets;
#endif /* __PRIVATE_SPI__ */

	UInt16 status;
    UInt16 rxMask;
    
	WriteReg16(IntrMask, 0x0000);
    status = ReadReg16(IntrStatus);
    
    /* hotplug/major error/no more work/shared irq */
    if ((status == 0xFFFF) || !status)
        goto done;
    
    /* Calculate time since last interrupt. */
    clock_get_uptime(&abstime);
    absolutetime_to_nanoseconds(abstime, &time);
    rxMask = ((time - lastIntrTime) < kFastIntrTreshhold) ? (RxOK | RxDescUnavail | RxFIFOOver) : (RxOK | RxDescUnavail | RxFIFOOver | TxOK);
    lastIntrTime = time;
    
    if (status & SYSErr) {
        pciErrorInterrupt();
        goto done;
    }
#ifdef __PRIVATE_SPI__
    if (!polling) {
        /* Rx interrupt */
        if (status & rxMask) {
            packets = rxInterrupt(netif, kNumRxDesc, NULL, NULL);
            
            if (packets)
                netif->flushInputQueue();
        }
        /* Tx interrupt */
        if (status & (TxOK | TxErr | TxDescUnavail))
            txInterrupt();
    }
#else
    /* Rx interrupt */
    if (status & rxMask)
        rxInterrupt();
    
    /* Tx interrupt */
    if (status & (TxOK | TxErr | TxDescUnavail))
        txInterrupt();
#endif /* __PRIVATE_SPI__ */

    if (status & LinkChg)
        checkLinkStatus();

done:
    WriteReg16(IntrStatus, status);
	WriteReg16(IntrMask, intrMask);
}

bool RTL8111::checkForDeadlock()
{
    bool deadlock = false;
    
    if ((txDescDoneCount == txDescDoneLast) && (txNumFreeDesc < kNumTxDesc)) {        
        if (++deadlockWarn == kTxCheckTreshhold) {
            /* Some members of the RTL8111 family seem to be prone to lose transmitter rinterrupts.
             * In order to avoid false positives when trying to detect transmitter deadlocks, check
             * the transmitter ring once for completed descriptors before we assume a deadlock. 
             */
            DebugLog("Ethernet [RealtekRTL8111]: Tx timeout. Lost interrupt?\n");
            etherStats->dot3TxExtraEntry.timeouts++;
            txInterrupt();
        } else if (deadlockWarn >= kTxDeadlockTreshhold) {
#ifdef DEBUG
            UInt32 i, index;
            
            for (i = 0; i < 10; i++) {
                index = ((txDirtyDescIndex - 1 + i) & kTxDescMask);
                IOLog("Ethernet [RealtekRTL8111]: desc[%u]: opts1=0x%x, opts2=0x%x, addr=0x%llx.\n", index, txDescArray[index].opts1, txDescArray[index].opts2, txDescArray[index].addr);
            }
#endif
            IOLog("Ethernet [RealtekRTL8111]: Tx stalled? Resetting chipset. ISR=0x%x, IMR=0x%x.\n", ReadReg16(IntrStatus), ReadReg16(IntrMask));
            etherStats->dot3TxExtraEntry.resets++;
            restartRTL8111();
            deadlock = true;
        }
    } else {
        deadlockWarn = 0;
    }
    return deadlock;
}

#pragma mark --- rx poll methods ---

#ifdef __PRIVATE_SPI__

IOReturn RTL8111::setInputPacketPollingEnable(IONetworkInterface *interface, bool enabled)
{
    //DebugLog("setInputPacketPollingEnable() ===>\n");

    if (enabled) {
        intrMask = intrMaskPoll;
        polling = true;
    } else {
        intrMask = intrMaskRxTx;
        polling = false;
    }
    if(isEnabled)
        WriteReg16(IntrMask, intrMask);
    
    //DebugLog("input polling %s.\n", enabled ? "enabled" : "disabled");

    //DebugLog("setInputPacketPollingEnable() <===\n");
    
    return kIOReturnSuccess;
}

void RTL8111::pollInputPackets(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context )
{
    //DebugLog("pollInputPackets() ===>\n");
    
    rxInterrupt(interface, maxCount, pollQueue, context);
    
    /* Finally cleanup the transmitter ring. */
    txInterrupt();
    
    //DebugLog("pollInputPackets() <===\n");
}

#endif /* __PRIVATE_SPI__ */

#pragma mark --- hardware specific methods ---

void RTL8111::getTso4Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags)
{
    if (revisionC) {
        *cmd1 = (GSendV4 | (kMinL4HdrOffsetV4 << GSendL4OffShift));
        *cmd2 = ((mssValue & MSSMask) << MSSShift_C);
    } else {
        *cmd1 = (LargeSend |((mssValue & MSSMask) << MSSShift));
    }
}

void RTL8111::getTso6Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags)
{
    *cmd1 = (GSendV6 | (kMinL4HdrOffsetV6 << GSendL4OffShift));
    *cmd2 = ((mssValue & MSSMask) << MSSShift_C);
}

void RTL8111::getChecksumCommand(UInt32 *cmd1, UInt32 *cmd2, mbuf_csum_request_flags_t checksums)
{
    if (revisionC) {
        if (checksums & kChecksumTCP)
            *cmd2 = (TxIPCS_C | TxTCPCS_C);
        else if (checksums & kChecksumUDP)
            *cmd2 = (TxIPCS_C | TxUDPCS_C);
        else if (checksums & kChecksumIP)
            *cmd2 = TxIPCS_C;
        else if (checksums & kChecksumTCPIPv6)
            *cmd2 = (TxTCPCS_C | TxIPV6_C | ((kMinL4HdrOffsetV6 & L4OffMask) << MSSShift_C));
        else if (checksums & kChecksumUDPIPv6)
            *cmd2 = (TxUDPCS_C | TxIPV6_C | ((kMinL4HdrOffsetV6 & L4OffMask) << MSSShift_C));
    } else {
        /* Setup the checksum command bits. */
        if (checksums & kChecksumTCP)
            *cmd1 = (TxIPCS | TxTCPCS);
        else if (checksums & kChecksumUDP)
            *cmd1 = (TxIPCS | TxUDPCS);
        else if (checksums & kChecksumIP)
            *cmd1 = TxIPCS;
    }
}

#ifdef DEBUG

void RTL8111::getChecksumResult(mbuf_t m, UInt32 status1, UInt32 status2)
{
    UInt32 resultMask = 0;
    UInt32 validMask = 0;
    UInt32 pktType = (status1 & RxProtoMask);
    
    /* Get the result of the checksum calculation and store it in the packet. */
    if (revisionC) {
        if (pktType == RxTCPT) {
            /* TCP packet */
            if (status2 & RxV4F) {
                resultMask = (kChecksumTCP | kChecksumIP);
                validMask = (status1 & RxTCPF) ? 0 : (kChecksumTCP | kChecksumIP);
            } else if (status2 & RxV6F) {
                resultMask = kChecksumTCPIPv6;
                validMask = (status1 & RxTCPF) ? 0 : kChecksumTCPIPv6;
            }
        } else if (pktType == RxUDPT) {
            /* UDP packet */
            if (status2 & RxV4F) {
                resultMask = (kChecksumUDP | kChecksumIP);
                validMask = (status1 & RxUDPF) ? 0 : (kChecksumUDP | kChecksumIP);
            } else if (status2 & RxV6F) {
                resultMask = kChecksumUDPIPv6;
                validMask = (status1 & RxUDPF) ? 0 : kChecksumUDPIPv6;
            }
        } else if ((pktType == 0) && (status2 & RxV4F)) {
            /* IP packet */
            resultMask = kChecksumIP;
            validMask = (status1 & RxIPF) ? 0 : kChecksumIP;
        }
    } else {
        if (pktType == RxProtoTCP) {
            /* TCP packet */
            resultMask = (kChecksumTCP | kChecksumIP);
            validMask = (status1 & RxTCPF) ? 0 : (kChecksumTCP | kChecksumIP);
        } else if (pktType == RxProtoUDP) {
            /* UDP packet */
            resultMask = (kChecksumUDP | kChecksumIP);
            validMask = (status1 & RxUDPF) ? 0 : (kChecksumUDP | kChecksumIP);
        } else if (pktType == RxProtoIP) {
            /* IP packet */
            resultMask = kChecksumIP;
            validMask = (status1 & RxIPF) ? 0 : kChecksumIP;
        }
    }
    if (validMask != resultMask)
        IOLog("Ethernet [RealtekRTL8111]: checksums applied: 0x%x, checksums valid: 0x%x\n", resultMask, validMask);

    if (validMask)
        setChecksumResult(m, kChecksumFamilyTCPIP, resultMask, validMask);
}

#else

void RTL8111::getChecksumResult(mbuf_t m, UInt32 status1, UInt32 status2)
{
    UInt32 resultMask = 0;
    UInt32 pktType = (status1 & RxProtoMask);
    
    if (revisionC) {
        /* Get the result of the checksum calculation and store it in the packet. */
        if (pktType == RxTCPT) {
            /* TCP packet */
            if (status2 & RxV4F)
                resultMask = (status1 & RxTCPF) ? 0 : (kChecksumTCP | kChecksumIP);
            else if (status2 & RxV6F)
                resultMask = (status1 & RxTCPF) ? 0 : kChecksumTCPIPv6;
        } else if (pktType == RxUDPT) {
            /* UDP packet */
            if (status2 & RxV4F)
                resultMask = (status1 & RxUDPF) ? 0 : (kChecksumUDP | kChecksumIP);
            else if (status2 & RxV6F)
                resultMask = (status1 & RxUDPF) ? 0 : kChecksumUDPIPv6;
        } else if ((pktType == 0) && (status2 & RxV4F)) {
            /* IP packet */
            resultMask = (status1 & RxIPF) ? 0 : kChecksumIP;
        }
    } else {
        if (pktType == RxProtoTCP)
            resultMask = (status1 & RxTCPF) ? 0 : (kChecksumTCP | kChecksumIP);  /* TCP packet */
        else if (pktType == RxProtoUDP)
            resultMask = (status1 & RxUDPF) ? 0 : (kChecksumUDP | kChecksumIP);  /* UDP packet */
        else if (pktType == RxProtoIP)
            resultMask = (status1 & RxIPF) ? 0 : kChecksumIP;                    /* IP packet */
    }
    if (resultMask)
        setChecksumResult(m, kChecksumFamilyTCPIP, resultMask, resultMask);
}

#endif

static const char *speed1GName = "1-Gigabit";
static const char *speed100MName = "100-Megabit";
static const char *speed10MName = "10-Megabit";
static const char *duplexFullName = "Full-duplex";
static const char *duplexHalfName = "Half-duplex";
static const char *offFlowName = "No flow-control";
static const char *onFlowName = "flow-control";

static const char* eeeNames[kEEETypeCount] = {
    "",
    ", EEE"
};

void RTL8111::setLinkUp(UInt8 linkState)
{
    UInt64 mediumSpeed;
    UInt32 mediumIndex = MEDIUM_INDEX_AUTO;
    const char *speedName;
    const char *duplexName;
    const char *flowName;
    const char *eeeName;
    UInt16 newIntrMitigate = 0x5f51;
    UInt16 eee = 0;
    
    eeeName = eeeNames[kEEETypeNo];

    /* Get EEE mode. */
    if (eeeCap) {
        mdio_write(&linuxData, 0x0D, 0x0007);
        mdio_write(&linuxData, 0x0E, 0x003D);
        mdio_write(&linuxData, 0x0D, 0x4007);
        eee = (mdio_read(&linuxData, 0x0E) & eeeAdv);
        //DebugLog("Ethernet [RealtekRTL8111]: LPA=%u\n", eee);
    }
    /* Get link speed, duplex and flow-control mode. */
    if (linkState &	(TxFlowCtrl | RxFlowCtrl)) {
        flowName = onFlowName;
        flowCtl = kFlowControlOn;
    } else {
        flowName = offFlowName;
        flowCtl = kFlowControlOff;
    }
    if (linkState & _1000bpsF) {
        mediumSpeed = kSpeed1000MBit;
        speed = SPEED_1000;
        speedName = speed1GName;
        duplexName = duplexFullName;
       
#ifdef __PRIVATE_SPI__
        if (!rxPoll)
            newIntrMitigate = intrMitigateValue;
#else
        newIntrMitigate = intrMitigateValue;
#endif /* __PRIVATE_SPI__ */

        if (flowCtl == kFlowControlOn) {
            if (eee & kEEEMode1000) {
                mediumIndex = MEDIUM_INDEX_1000FDFCEEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MEDIUM_INDEX_1000FDFC;
            }
        } else {
            if (eee & kEEEMode1000) {
                mediumIndex = MEDIUM_INDEX_1000FDEEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MEDIUM_INDEX_1000FD;
            }
        }
    } else if (linkState & _100bps) {
        mediumSpeed = kSpeed100MBit;
        speed = SPEED_100;
        speedName = speed100MName;
        
        if (linkState & FullDup) {
            duplexName = duplexFullName;
            
            if (flowCtl == kFlowControlOn) {
                if (eee & kEEEMode100) {
                    mediumIndex =  MEDIUM_INDEX_100FDFCEEE;
                    eeeName = eeeNames[kEEETypeYes];
                } else {
                    mediumIndex = MEDIUM_INDEX_100FDFC;
                }
            } else {
                if (eee & kEEEMode100) {
                    mediumIndex =  MEDIUM_INDEX_100FDEEE;
                    eeeName = eeeNames[kEEETypeYes];
                } else {
                    mediumIndex = MEDIUM_INDEX_100FD;
                }
            }
        } else {
            mediumIndex = MEDIUM_INDEX_100HD;
            duplexName = duplexHalfName;
        }
    } else {
        mediumSpeed = kSpeed10MBit;
        speed = SPEED_10;
        speedName = speed10MName;
        
        if (linkState & FullDup) {
            mediumIndex = MEDIUM_INDEX_10FD;
            duplexName = duplexFullName;
        } else {
            mediumIndex = MEDIUM_INDEX_10HD;
            duplexName = duplexHalfName;
        }
    }
    startRTL8111(newIntrMitigate, false);
    linkUp = true;
    setLinkStatus(kIONetworkLinkValid | kIONetworkLinkActive, mediumTable[mediumIndex], mediumSpeed, NULL);

#ifdef __PRIVATE_SPI__
    /* Start output thread, statistics update and watchdog. */
    if (rxPoll) {
        /* Update poll params according to link speed. */
        bzero(&pollParams, sizeof(IONetworkPacketPollingParameters));
        
        if (speed == SPEED_10) {
            pollParams.lowThresholdPackets = 2;
            pollParams.highThresholdPackets = 8;
            pollParams.lowThresholdBytes = 0x400;
            pollParams.highThresholdBytes = 0x1800;
            pollParams.pollIntervalTime = 1000000;  /* 1ms */
        } else {
            pollParams.lowThresholdPackets = 10;
            pollParams.highThresholdPackets = 40;
            pollParams.lowThresholdBytes = 0x1000;
            pollParams.highThresholdBytes = 0x10000;
            pollParams.pollIntervalTime = (speed == SPEED_1000) ? 170000 : 1000000;  /* 170µs / 1ms */
        }
        netif->setPacketPollingParameters(&pollParams, 0);
        DebugLog("Ethernet [RealtekRTL8111]: pollIntervalTime: %lluus\n", (pollParams.pollIntervalTime / 1000));
    }
    netif->startOutputThread();
#else
    /* Restart txQueue, statistics updates and watchdog. */
    txQueue->start();
    
    if (stalled) {
        txQueue->service();
        stalled = false;
        DebugLog("Ethernet [RealtekRTL8111]: Restart stalled queue!\n");
    }
#endif /* __PRIVATE_SPI__ */

    IOLog("Ethernet [RealtekRTL8111]: Link up on en%u, %s, %s, %s%s\n", netif->getUnitNumber(), speedName, duplexName, flowName, eeeName);
}

void RTL8111::setLinkDown()
{
    struct rtl8168_private *tp = &linuxData;

    deadlockWarn = 0;
    needsUpdate = false;

#ifdef __PRIVATE_SPI__
    /* Stop output thread and flush output queue. */
    netif->stopOutputThread();
    netif->flushOutputQueue();
#else
    /* Stop txQueue. */
    txQueue->stop();
    txQueue->flush();
#endif /* __PRIVATE_SPI__ */

    /* Update link status. */
    linkUp = false;
    setLinkStatus(kIONetworkLinkValid);

    rtl8168_nic_reset(&linuxData);

    /* Cleanup descriptor ring. */
    txClearDescriptors();
    
    setPhyMedium();
    
    switch (tp->mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
            if (tp->org_pci_offset_99 & BIT_2)
                if (!(ReadReg8(PHYstatus) & PowerSaveStatus)) {
                    rtl8168_issue_offset_99_event(tp);
                }
            break;
    }
    IOLog("Ethernet [RealtekRTL8111]: Link down on en%u\n", netif->getUnitNumber());
}

void RTL8111::updateStatitics()
{
    UInt32 sgColl, mlColl;
    UInt32 cmd;

    /* Check if a statistics dump has been completed. */
    if (needsUpdate && !(ReadReg32(CounterAddrLow) & CounterDump)) {
        needsUpdate = false;
        netStats->inputPackets = OSSwapLittleToHostInt64(statData->rxPackets) & 0x00000000ffffffff;
        netStats->inputErrors = OSSwapLittleToHostInt32(statData->rxErrors);
        netStats->outputPackets = OSSwapLittleToHostInt64(statData->txPackets) & 0x00000000ffffffff;
        netStats->outputErrors = OSSwapLittleToHostInt32(statData->txErrors);
        
        sgColl = OSSwapLittleToHostInt32(statData->txOneCollision);
        mlColl = OSSwapLittleToHostInt32(statData->txMultiCollision);
        netStats->collisions = sgColl + mlColl;
        
        etherStats->dot3StatsEntry.singleCollisionFrames = sgColl;
        etherStats->dot3StatsEntry.multipleCollisionFrames = mlColl;
        etherStats->dot3StatsEntry.alignmentErrors = OSSwapLittleToHostInt16(statData->alignErrors);
        etherStats->dot3StatsEntry.missedFrames = OSSwapLittleToHostInt16(statData->rxMissed);
        etherStats->dot3TxExtraEntry.underruns = OSSwapLittleToHostInt16(statData->txUnderun);
    }
    /* Some chips are unable to dump the tally counter while the receiver is disabled. */
    if (ReadReg8(ChipCmd) & CmdRxEnb) {
        WriteReg32(CounterAddrHigh, (statPhyAddr >> 32));
        cmd = (statPhyAddr & 0x00000000ffffffff);
        WriteReg32(CounterAddrLow, cmd);
        WriteReg32(CounterAddrLow, cmd | CounterDump);
        needsUpdate = true;
    }
}

#pragma mark --- hardware initialization methods ---

bool RTL8111::initPCIConfigSpace(IOPCIDevice *provider)
{
    UInt32 pcieLinkCap;
    UInt16 pcieLinkCtl;
    UInt16 cmdReg;
    UInt16 pmCap;
    UInt8 pmCapOffset;
    UInt8 pcieCapOffset;
    bool result = false;
    
    /* Get vendor and device info. */
    pciDeviceData.vendor = provider->configRead16(kIOPCIConfigVendorID);
    pciDeviceData.device = provider->configRead16(kIOPCIConfigDeviceID);
    pciDeviceData.subsystem_vendor = provider->configRead16(kIOPCIConfigSubSystemVendorID);
    pciDeviceData.subsystem_device = provider->configRead16(kIOPCIConfigSubSystemID);

    /* Setup power management. */
    if (provider->findPCICapability(kIOPCIPowerManagementCapability, &pmCapOffset)) {
        pmCap = provider->configRead16(pmCapOffset + kIOPCIPMCapability);
        DebugLog("Ethernet [RealtekRTL8111]: PCI power management capabilities: 0x%x.\n", pmCap);
        
        if (pmCap & kPCIPMCPMESupportFromD3Cold) {
            wolCapable = true;
            DebugLog("Ethernet [RealtekRTL8111]: PME# from D3 (cold) supported.\n");
        }
    } else {
        IOLog("Ethernet [RealtekRTL8111]: PCI power management unsupported.\n");
    }
    provider->enablePCIPowerManagement(kPCIPMCSPowerStateD0);
    
    /* Get PCIe link information. */
    if (provider->findPCICapability(kIOPCIPCIExpressCapability, &pcieCapOffset)) {
        pcieLinkCap = provider->configRead32(pcieCapOffset + kIOPCIELinkCapability);
        pcieLinkCtl = provider->configRead16(pcieCapOffset + kIOPCIELinkControl);
        DebugLog("Ethernet [RealtekRTL8111]: PCIe link capabilities: 0x%08x, link control: 0x%04x.\n", pcieLinkCap, pcieLinkCtl);
        
        if (pcieLinkCtl & kIOPCIELinkCtlASPM) {
            if (disableASPM) {
                IOLog("Ethernet [RealtekRTL8111]: Disable PCIe ASPM.\n");
                provider-> setASPMState(this, 0);
            } else {
                IOLog("Ethernet [RealtekRTL8111]: Warning: PCIe ASPM enabled.\n");
                linuxData.aspm = 1;
            }
        }
    }
    /* Enable the device. */
    cmdReg	= provider->configRead16(kIOPCIConfigCommand);
    cmdReg  &= ~kIOPCICommandIOSpace;
    cmdReg	|= (kIOPCICommandBusMaster | kIOPCICommandMemorySpace | kIOPCICommandMemWrInvalidate);
	provider->configWrite16(kIOPCIConfigCommand, cmdReg);
    provider->configWrite8(kIOPCIConfigLatencyTimer, 0x40);

    //baseMap = provider->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
    baseMap = provider->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2, kIOMapInhibitCache);

    if (!baseMap) {
        IOLog("Ethernet [RealtekRTL8111]: region #2 not an MMIO resource, aborting.\n");
        goto done;
    }
    baseAddr = reinterpret_cast<volatile void *>(baseMap->getVirtualAddress());
    linuxData.mmio_addr = baseAddr;
    result = true;
    
done:
    return result;
}

IOReturn RTL8111::setPowerStateWakeAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4)
{
    RTL8111 *ethCtlr = OSDynamicCast(RTL8111, owner);
    
    if (ethCtlr)
        ethCtlr->pciDevice->enablePCIPowerManagement(kPCIPMCSPowerStateD0);

    return kIOReturnSuccess;
}

IOReturn RTL8111::setPowerStateSleepAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4)
{    
    RTL8111 *ethCtlr = OSDynamicCast(RTL8111, owner);
    IOPCIDevice *dev;
    
    if (ethCtlr) {
        dev = ethCtlr->pciDevice;
        
        if (ethCtlr->wolActive)
            dev->enablePCIPowerManagement(kPCIPMCSPMEStatus | kPCIPMCSPMEEnable | kPCIPMCSPowerStateD3);
        else
            dev->enablePCIPowerManagement(kPCIPMCSPowerStateD3);
    }
    return kIOReturnSuccess;
}

bool RTL8111::initRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    UInt32 i, csi_tmp;
    UInt16 mac_addr[4];
    UInt8 options1, options2;
    bool result = false;
    bool wol;

    /* Identify chip attached to board. */
	rtl8168_get_mac_version(tp, baseAddr);
    
    if (tp->mcfg == CFG_METHOD_DEFAULT) {
        DebugLog("Ethernet [RealtekRTL8111]: Retry chip recognition.\n");
        
        /* In case chip recognition failed clear corresponding bits... */
        WriteReg32(TxConfig, ReadReg32(TxConfig) & ~0x7CF00000);
        
        /* ...and try again. */
        rtl8168_get_mac_version(tp, baseAddr);
    }
    if (tp->mcfg >= CFG_METHOD_MAX) {
        DebugLog("Ethernet [RealtekRTL8111]: Unsupported chip found. Aborting...\n");
        goto done;
    }
    tp->chipset =  tp->mcfg;
    
    /* Setup EEE support. */
    if ((tp->mcfg >= CFG_METHOD_14) && (linuxData.eeeEnable != 0)) {
        eeeAdv = eeeCap = (kEEEMode100 | kEEEMode1000);
    }
    /* Select the chip revision. */
    revisionC = ((tp->chipset == CFG_METHOD_1) || (tp->chipset == CFG_METHOD_2) || (tp->chipset == CFG_METHOD_3)) ? false : true;
    
	//tp->set_speed = rtl8168_set_speed_xmii;
	tp->get_settings = rtl8168_gset_xmii;
	tp->phy_reset_enable = rtl8168_xmii_reset_enable;
	tp->phy_reset_pending = rtl8168_xmii_reset_pending;
	tp->link_ok = rtl8168_xmii_link_ok;
    
    tp->max_jumbo_frame_size = rtl_chip_info[tp->chipset].jumbo_frame_sz;

    rtl8168_get_bios_setting(tp);
    
    switch (tp->mcfg) {
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
            tp->HwSuppDashVer = 1;
            break;
        case CFG_METHOD_23:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
            tp->HwSuppDashVer = 2;
            break;
        default:
            tp->HwSuppDashVer = 0;
            break;
    }

    if (HW_DASH_SUPPORT_DASH(tp) && rtl8168_check_dash(tp))
        tp->DASH = 1;
    else
        tp->DASH = 0;

    switch (tp->mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            tp->org_pci_offset_99 = csiFun0ReadByte(0x99);
            tp->org_pci_offset_99 &= ~(BIT_5|BIT_6);
            break;
    }
    switch (tp->mcfg) {
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            tp->org_pci_offset_180 = csiFun0ReadByte(0x180);
            break;
    }
    tp->org_pci_offset_80 = pciDevice->configRead8(0x80);
    tp->org_pci_offset_81 = pciDevice->configRead8(0x81);
    
    if (tp->mcfg == CFG_METHOD_30) {
        u16 ioffset_p3, ioffset_p2, ioffset_p1, ioffset_p0;
        u16 TmpUshort;
        
        mac_ocp_write( tp, 0xDD02, 0x807D);
        TmpUshort = mac_ocp_read( tp, 0xDD02 );
        ioffset_p3 = ( (TmpUshort & BIT_7) >>7 );
        ioffset_p3 <<= 3;
        TmpUshort = mac_ocp_read( tp, 0xDD00 );
        
        ioffset_p3 |= ((TmpUshort & (BIT_15 | BIT_14 | BIT_13))>>13);
        
        ioffset_p2 = ((TmpUshort & (BIT_12|BIT_11|BIT_10|BIT_9))>>9);
        ioffset_p1 = ((TmpUshort & (BIT_8|BIT_7|BIT_6|BIT_5))>>5);
        
        ioffset_p0 = ( (TmpUshort & BIT_4) >>4 );
        ioffset_p0 <<= 3;
        ioffset_p0 |= (TmpUshort & (BIT_2| BIT_1 | BIT_0));
        
        if((ioffset_p3 == 0x0F) && (ioffset_p2 == 0x0F) && (ioffset_p1 == 0x0F) && (ioffset_p0 == 0x0F)) {
            tp->RequireAdcBiasPatch = FALSE;
        } else {
            tp->RequireAdcBiasPatch = TRUE;
            tp->AdcBiasPatchIoffset = (ioffset_p3<<12)|(ioffset_p2<<8)|(ioffset_p1<<4)|(ioffset_p0);
        }
    }
    if ((tp->mcfg == CFG_METHOD_29) || (tp->mcfg == CFG_METHOD_30)) {
        u16 rg_saw_cnt;
        
        mdio_write(tp, 0x1F, 0x0C42);
        rg_saw_cnt = mdio_read(tp, 0x13);
        rg_saw_cnt &= ~(BIT_15|BIT_14);
        mdio_write(tp, 0x1F, 0x0000);
        
        if ( rg_saw_cnt > 0) {
            tp->SwrCnt1msIni = 16000000/rg_saw_cnt;
            tp->SwrCnt1msIni &= 0x0FFF;
            
            tp->RequireAdjustUpsTxLinkPulseTiming = TRUE;
        }
    }
    switch (tp->mcfg) {
        case CFG_METHOD_14:
        case CFG_METHOD_15:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_14;
            break;
        case CFG_METHOD_16:
        case CFG_METHOD_17:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_16;
            break;
        case CFG_METHOD_18:
        case CFG_METHOD_19:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_18;
            break;
        case CFG_METHOD_20:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_20;
            break;
        case CFG_METHOD_21:
        case CFG_METHOD_22:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_21;
            break;
        case CFG_METHOD_23:
        case CFG_METHOD_27:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_23;
            break;
        case CFG_METHOD_24:
        case CFG_METHOD_25:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_24;
            break;
        case CFG_METHOD_26:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_26;
            break;
        case CFG_METHOD_28:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_28;
            break;
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_29;
            break;
    }
    
    if (tp->HwIcVerUnknown) {
        tp->NotWrRamCodeToMicroP = TRUE;
        tp->NotWrMcuPatchCode = TRUE;
    }
    rtl8168_exit_oob(tp);
    rtl8168_hw_init(tp);
    rtl8168_nic_reset(tp);
    
    /* Get production from EEPROM */
    if (((tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
          tp->mcfg == CFG_METHOD_25 || tp->mcfg == CFG_METHOD_29 ||
          tp->mcfg == CFG_METHOD_30) && (mac_ocp_read(tp, 0xDC00) & BIT_3)) ||
        ((tp->mcfg == CFG_METHOD_26) && (mac_ocp_read(tp, 0xDC00) & BIT_4)))
        tp->eeprom_type = EEPROM_TYPE_NONE;
    else
        rtl_eeprom_type(tp);
    
    if (tp->eeprom_type == EEPROM_TYPE_93C46 || tp->eeprom_type == EEPROM_TYPE_93C56)
        rtl_set_eeprom_sel_low(baseAddr);

    if (tp->mcfg == CFG_METHOD_18 ||
        tp->mcfg == CFG_METHOD_19 ||
        tp->mcfg == CFG_METHOD_20 ||
        tp->mcfg == CFG_METHOD_21 ||
        tp->mcfg == CFG_METHOD_22 ||
        tp->mcfg == CFG_METHOD_23 ||
        tp->mcfg == CFG_METHOD_24 ||
        tp->mcfg == CFG_METHOD_25 ||
        tp->mcfg == CFG_METHOD_26 ||
        tp->mcfg == CFG_METHOD_27 ||
        tp->mcfg == CFG_METHOD_28 ||
        tp->mcfg == CFG_METHOD_29 ||
        tp->mcfg == CFG_METHOD_30) {
        
        *(UInt32*)&mac_addr[0] = rtl8168_eri_read(baseAddr, 0xE0, 4, ERIAR_ExGMAC);
        *(UInt16*)&mac_addr[2] = rtl8168_eri_read(baseAddr, 0xE4, 2, ERIAR_ExGMAC);
        
        mac_addr[3] = 0;
		WriteReg8(Cfg9346, Cfg9346_Unlock);
        WriteReg32(MAC0, (mac_addr[1] << 16) | mac_addr[0]);
        WriteReg32(MAC4, (mac_addr[3] << 16) | mac_addr[2]);
		WriteReg8(Cfg9346, Cfg9346_Lock);
    } else {
        if (tp->eeprom_type != EEPROM_TYPE_NONE) {
            
            /* Get MAC address from EEPROM */
            if (tp->mcfg == CFG_METHOD_16 ||
                tp->mcfg == CFG_METHOD_17 ||
                tp->mcfg == CFG_METHOD_18 ||
                tp->mcfg == CFG_METHOD_19 ||
                tp->mcfg == CFG_METHOD_20 ||
                tp->mcfg == CFG_METHOD_21 ||
                tp->mcfg == CFG_METHOD_22 ||
                tp->mcfg == CFG_METHOD_23 ||
                tp->mcfg == CFG_METHOD_24 ||
                tp->mcfg == CFG_METHOD_25 ||
                tp->mcfg == CFG_METHOD_26 ||
                tp->mcfg == CFG_METHOD_27 ||
                tp->mcfg == CFG_METHOD_28 ||
                tp->mcfg == CFG_METHOD_29 ||
                tp->mcfg == CFG_METHOD_30) {
                mac_addr[0] = rtl_eeprom_read_sc(tp, 1);
                mac_addr[1] = rtl_eeprom_read_sc(tp, 2);
                mac_addr[2] = rtl_eeprom_read_sc(tp, 3);
            } else {
                mac_addr[0] = rtl_eeprom_read_sc(tp, 7);
                mac_addr[1] = rtl_eeprom_read_sc(tp, 8);
                mac_addr[2] = rtl_eeprom_read_sc(tp, 9);
            }
            mac_addr[3] = 0;
            WriteReg8(Cfg9346, Cfg9346_Unlock);
            WriteReg32(MAC0, (mac_addr[1] << 16) | mac_addr[0]);
            WriteReg32(MAC4, (mac_addr[3] << 16) | mac_addr[2]);
            WriteReg8(Cfg9346, Cfg9346_Lock);
        }
    }
	for (i = 0; i < MAC_ADDR_LEN; i++) {
		currMacAddr.bytes[i] = ReadReg8(MAC0 + i);
		origMacAddr.bytes[i] = currMacAddr.bytes[i]; /* keep the original MAC address */
	}
    IOLog("Ethernet [RealtekRTL8111]: %s: (Chipset %d) at 0x%lx, %02x:%02x:%02x:%02x:%02x:%02x\n",
          rtl_chip_info[tp->chipset].name, tp->chipset, (unsigned long)baseAddr,
          origMacAddr.bytes[0], origMacAddr.bytes[1],
          origMacAddr.bytes[2], origMacAddr.bytes[3],
          origMacAddr.bytes[4], origMacAddr.bytes[5]);
    
    tp->cp_cmd = ReadReg16(CPlusCmd);
    
#ifdef __PRIVATE_SPI__
    if (revisionC) {
        intrMaskRxTx = (SYSErr | LinkChg | RxDescUnavail | TxErr | TxOK | RxErr | RxOK);
        intrMaskPoll = (SYSErr | LinkChg);
    } else {
        intrMaskRxTx = (SYSErr | RxDescUnavail | TxErr | TxOK | RxErr | RxOK);
        intrMaskPoll = SYSErr;
    }
    intrMask = intrMaskRxTx;
#else
    intrMask = (revisionC) ? (SYSErr | LinkChg | RxDescUnavail | TxErr | TxOK | RxErr | RxOK) : (SYSErr | RxDescUnavail | TxErr | TxOK | RxErr | RxOK);
#endif /* __PRIVATE_SPI__ */

    /* Get the RxConfig parameters. */
    rxConfigReg = rtl_chip_info[tp->chipset].RCR_Cfg;
    rxConfigMask = rtl_chip_info[tp->chipset].RxConfigMask;

    rtl8168_get_hw_wol(tp);

    options1 = ReadReg8(Config3);
	options2 = ReadReg8(Config5);
	csi_tmp = rtl8168_eri_read(baseAddr, 0xDE, 4, ERIAR_ExGMAC);
    
    switch (tp->mcfg) {
        case CFG_METHOD_16:
        case CFG_METHOD_17:
        case CFG_METHOD_18:
        case CFG_METHOD_19:
        case CFG_METHOD_20:
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            wol = ((options1 & LinkUp) || (csi_tmp & BIT_0) || (options2 & UWF) || (options2 & BWF) || (options2 & MWF)) ? true : false;
            break;
            
        case CFG_METHOD_DEFAULT:
            wol = false;
            break;
            
        default:
            wol = ((options1 & LinkUp) || (options1 & MagicPacket) || (options2 & UWF) || (options2 & BWF) || (options2 & MWF)) ? true : false;
            break;
    }
    /* Set wake on LAN support. */
    wolCapable = wolCapable && wol;

#ifdef DEBUG
    
    if (wolCapable)
        IOLog("Ethernet [RealtekRTL8111]: Device is WoL capable.\n");

#endif
    
    result = true;
    
done:
    return result;
}

void RTL8111::enableRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    
    setLinkStatus(kIONetworkLinkValid);

#ifdef __PRIVATE_SPI__
    intrMask = intrMaskRxTx;
    polling = false;
#endif  /* __PRIVATE_SPI__ */

    rtl8168_exit_oob(tp);
    rtl8168_hw_init(tp);
    rtl8168_nic_reset(tp);
    rtl8168_powerup_pll(tp);
    rtl8168_hw_ephy_config(tp);
    rtl8168_hw_phy_config(tp);
	startRTL8111(intrMitigateValue, true);
	rtl8168_dsm(tp, DSM_IF_UP);
    
    setPhyMedium();
}

void RTL8111::disableRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    
	rtl8168_dsm(tp, DSM_IF_DOWN);

    /* Disable all interrupts by clearing the interrupt mask. */
    WriteReg16(IntrMask, 0);
    WriteReg16(IntrStatus, ReadReg16(IntrStatus));

    rtl8168_nic_reset(tp);
    rtl8168_sleep_rx_enable(tp);
    hardwareD3Para();
	rtl8168_powerdown_pll(tp);
    
    if (linkUp) {
        linkUp = false;
        setLinkStatus(kIONetworkLinkValid);
        IOLog("Ethernet [RealtekRTL8111]: Link down on en%u\n", netif->getUnitNumber());
    }
}

/* Reset the NIC in case a tx deadlock or a pci error occurred. timerSource and txQueue
 * are stopped immediately but will be restarted by checkLinkStatus() when the link has
 * been reestablished.
 */

void RTL8111::restartRTL8111()
{
#ifdef __PRIVATE_SPI__
    /* Stop output thread and flush txQueue */
    netif->stopOutputThread();
    netif->flushOutputQueue();
#else
    /* Stop and cleanup txQueue. */
    txQueue->stop();
    txQueue->flush();
#endif /* __PRIVATE_SPI__ */

    linkUp = false;
    setLinkStatus(kIONetworkLinkValid);
        
    /* Reset NIC and cleanup both descriptor rings. */
    rtl8168_nic_reset(&linuxData);
    txClearDescriptors();

#ifdef __PRIVATE_SPI__
    if (rxInterrupt(netif, kNumRxDesc, NULL, NULL))
        netif->flushInputQueue();
#else
    rxInterrupt();
#endif /* __PRIVATE_SPI__ */

    rxNextDescIndex = 0;
    deadlockWarn = 0;
    
    /* Reinitialize NIC. */
    enableRTL8111();
}

void RTL8111::startRTL8111(UInt16 newIntrMitigate, bool enableInterrupts)
{
    struct rtl8168_private *tp = &linuxData;
    UInt32 csi_tmp;
    UInt16 mac_ocp_data;
    UInt8 device_control;
    
	WriteReg32(RxConfig, (RX_DMA_BURST << RxCfgDMAShift));
    
	rtl8168_nic_reset(tp);
    
	WriteReg8(Cfg9346, Cfg9346_Unlock);
    
    switch (tp->mcfg) {
        case CFG_METHOD_14:
        case CFG_METHOD_15:
        case CFG_METHOD_16:
        case CFG_METHOD_17:
        case CFG_METHOD_18:
        case CFG_METHOD_19:
        case CFG_METHOD_20:
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            WriteReg8(0xF1, ReadReg8(0xF1) & ~BIT_7);
            WriteReg8(Config2, ReadReg8(Config2) & ~BIT_7);
            WriteReg8(Config5, ReadReg8(Config5) & ~BIT_0);
            break;
    }
    //clear io_rdy_l23
    switch (tp->mcfg) {
        case CFG_METHOD_20:
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            WriteReg8(Config3, ReadReg8(Config3) & ~BIT_1);
            break;
    }

	WriteReg8(MTPS, Reserved1_data);
    
	tp->cp_cmd |= PktCntrDisable | INTT_1 | RxChkSum;
	WriteReg16(CPlusCmd, tp->cp_cmd);
    
    /* The original value 0x5f51 seems to cause performance issues with SMB. */
    /* WriteReg16(IntrMitigate, 0x5f51); */
    WriteReg16(IntrMitigate, newIntrMitigate);

	WriteReg8(Config5, ReadReg8(Config5) & ~BIT_7);

    txNextDescIndex = txDirtyDescIndex = 0;
    txNumFreeDesc = kNumTxDesc;
    rxNextDescIndex = 0;

    WriteReg32(TxDescStartAddrLow, (txPhyAddr & 0x00000000ffffffff));
    WriteReg32(TxDescStartAddrHigh, (txPhyAddr >> 32));
    WriteReg32(RxDescAddrLow, (rxPhyAddr & 0x00000000ffffffff));
    WriteReg32(RxDescAddrHigh, (rxPhyAddr >> 32));

	/* Set DMA burst size and Interframe Gap Time */
	if (tp->mcfg == CFG_METHOD_1)
		WriteReg32(TxConfig, (TX_DMA_BURST_512 << TxDMAShift) |
                (InterFrameGap << TxInterFrameGapShift));
	else
		WriteReg32(TxConfig, (TX_DMA_BURST_unlimited << TxDMAShift) |
                (InterFrameGap << TxInterFrameGapShift));
    
	/* Clear the interrupt status register. */
	WriteReg16(IntrStatus, 0xFFFF);
    
    if (tp->mcfg == CFG_METHOD_4) {
        set_offset70F(tp, 0x27);
        
        WriteReg8(DBG_reg, (0x0E << 4) | Fix_Nak_1 | Fix_Nak_2);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
        
        setOffset79(0x50);

    } else if (tp->mcfg == CFG_METHOD_5) {
        set_offset70F(tp, 0x27);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
        setOffset79(0x50);

    } else if (tp->mcfg == CFG_METHOD_6) {
        set_offset70F(tp, 0x27);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
        setOffset79(0x50);

    } else if (tp->mcfg == CFG_METHOD_7) {
        set_offset70F(tp, 0x27);
        
        rtl8168_eri_write(baseAddr, 0x1EC, 1, 0x07, ERIAR_ASF);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
        setOffset79(0x50);

    } else if (tp->mcfg == CFG_METHOD_8) {
        set_offset70F(tp, 0x27);
        
        rtl8168_eri_write(baseAddr, 0x1EC, 1, 0x07, ERIAR_ASF);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg8(0xD1, 0x20);
    
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
        setOffset79(0x50);
        
    } else if (tp->mcfg == CFG_METHOD_9) {
        set_offset70F(tp, 0x27);
        
        /* disable clock request. */
        pciDevice->configWrite8(0x81, 0x00);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~BIT_4);
        WriteReg8(DBG_reg, ReadReg8(DBG_reg) | BIT_7 | BIT_1);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
        setOffset79(0x50);
        WriteReg8(TDFNR, 0x8);
        
    } else if (tp->mcfg == CFG_METHOD_10) {
        set_offset70F(tp, 0x27);
        
        WriteReg8(DBG_reg, ReadReg8(DBG_reg) | BIT_7 | BIT_1);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
        
        setOffset79(0x50);
        WriteReg8(TDFNR, 0x8);
        WriteReg8(Config1, ReadReg8(Config1) | 0x10);
        
        /* disable clock request. */
        pciDevice->configWrite8(0x81, 0x00);
        
    } else if (tp->mcfg == CFG_METHOD_11 || tp->mcfg == CFG_METHOD_13) {
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);        
        pciDevice->configWrite8(0x81, 0x00);
        
        WriteReg8(Config1, ReadReg8(Config1) | 0x10);
        
    } else if (tp->mcfg == CFG_METHOD_12) {
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        pciDevice->configWrite8(0x81, 0x01);
        
        WriteReg8(Config1, ReadReg8(Config1) | 0x10);
        
    } else if (tp->mcfg == CFG_METHOD_14 || tp->mcfg == CFG_METHOD_15) {
        set_offset70F(tp, 0x27);
        setOffset79(0x50);
        
        tp->cp_cmd &= 0x2063;
        WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
        WriteReg8(Config4, ReadReg8(Config4) & ~0x01);
        WriteReg8(0xF3, ReadReg8(0xF3) | BIT_5);
        WriteReg8(0xF3, ReadReg8(0xF3) & ~BIT_5);
                
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_7 | BIT_6);
        
        WriteReg8(0xD1, ReadReg8(0xD1) | BIT_2 | BIT_3);
        
        WriteReg8(0xF1, ReadReg8(0xF1) | BIT_6 | BIT_5 | BIT_4 | BIT_2 | BIT_1);
        
        WriteReg8(TDFNR, 0x8);
        
        if (tp->aspm)
            WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7);
        
        WriteReg8(Config5, ReadReg8(Config5) & ~BIT_3);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
    } else if (tp->mcfg == CFG_METHOD_16 || tp->mcfg == CFG_METHOD_17) {
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD5, 1, ERIAR_ExGMAC) | BIT_3 | BIT_2;
        rtl8168_eri_write(baseAddr, 0xD5, 1, csi_tmp, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xC8, 4, 0x00100002, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1D0, 4, ERIAR_ExGMAC);
        csi_tmp |= BIT_1;
        rtl8168_eri_write(baseAddr, 0x1D0, 1, csi_tmp, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xDC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        
        WriteReg32(TxConfig, ReadReg32(TxConfig) | BIT_7);
        WriteReg8(0xD3, ReadReg8(0xD3) & ~BIT_7);
        WriteReg8(0x1B, ReadReg8(0x1B) & ~0x07);
        
        if (tp->mcfg == CFG_METHOD_16) {
            WriteReg32(0xB0, 0xEE480010);
            WriteReg8(0x1A, ReadReg8(0x1A) & ~(BIT_2|BIT_3));
            rtl8168_eri_write(baseAddr, 0x1DC, 1, 0x64, ERIAR_ExGMAC);
        } else {
            csi_tmp = rtl8168_eri_read(baseAddr, 0x1B0, 4, ERIAR_ExGMAC);
            csi_tmp |= BIT_4;
            rtl8168_eri_write(baseAddr, 0x1B0, 1, csi_tmp, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0xCC, 4, 0x00000050, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0xD0, 4, 0x07ff0060, ERIAR_ExGMAC);
        }
        
        WriteReg8(TDFNR, 0x8);
        
        WriteReg8(Config2, ReadReg8(Config2) & ~PMSTS_En);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        
        tp->cp_cmd &= 0x2063;
        
        /* disable clock request. */
        pciDevice->configWrite8(0x81, 0x00);
        
    } else if (tp->mcfg == CFG_METHOD_18 || tp->mcfg == CFG_METHOD_19) {
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        rtl8168_eri_write(baseAddr, 0xC8, 4, 0x00100002, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        WriteReg32(TxConfig, ReadReg32(TxConfig) | BIT_7);
        WriteReg8(0xD3, ReadReg8(0xD3) & ~BIT_7);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xDC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        
        if (tp->aspm)
            WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7);
        
        tp->cp_cmd &= 0x2063;
        
        WriteReg8(TDFNR, 0x8);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD5, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_3 | BIT_2;
        rtl8168_eri_write(baseAddr, 0xD5, 1, csi_tmp, ERIAR_ExGMAC);
        WriteReg8(0x1B,ReadReg8(0x1B) & ~0x07);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1B0, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_4;
        rtl8168_eri_write(baseAddr, 0x1B0, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1d0, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_4 | BIT_1;
        rtl8168_eri_write(baseAddr, 0x1d0, 1, csi_tmp, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xCC, 4, 0x00000050, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xd0, 4, 0x00000060, ERIAR_ExGMAC);
        
    } else if (tp->mcfg == CFG_METHOD_20) {
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        rtl8168_eri_write(baseAddr, 0xC8, 4, 0x00100002, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        WriteReg32(TxConfig, ReadReg32(TxConfig) | BIT_7);
        WriteReg8(0xD3, ReadReg8(0xD3) & ~BIT_7);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xDC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        
        if (tp->aspm)
            WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7);
        
        tp->cp_cmd &= 0x2063;
        
        WriteReg8(TDFNR, 0x8);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD5, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_3 | BIT_2;
        rtl8168_eri_write(baseAddr, 0xD5, 1, csi_tmp, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1B0, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_4;
        rtl8168_eri_write(baseAddr, 0x1B0, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1d0, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_4 | BIT_1;
        rtl8168_eri_write(baseAddr, 0x1d0, 1, csi_tmp, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xCC, 4, 0x00000050, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xd0, 4, 0x00000060, ERIAR_ExGMAC);
        
    } else if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
               tp->mcfg == CFG_METHOD_24 || tp->mcfg == CFG_METHOD_25 ||
               tp->mcfg == CFG_METHOD_26 || tp->mcfg == CFG_METHOD_29 ||
               tp->mcfg == CFG_METHOD_30) {
        
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22)
            set_offset711(tp, 0x04);

        rtl8168_eri_write(baseAddr, 0xC8, 4, 0x00080002, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xCC, 1, 0x38, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xD0, 1, 0x48, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        
        WriteReg32(TxConfig, ReadReg32(TxConfig) | BIT_7);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xDC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        
        if (tp->mcfg == CFG_METHOD_26) {
            mac_ocp_data = mac_ocp_read(tp, 0xD3C0);
            mac_ocp_data &= ~(BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
            mac_ocp_data |= 0x03A9;
            mac_ocp_write(tp, 0xD3C0, mac_ocp_data);
            mac_ocp_data = mac_ocp_read(tp, 0xD3C2);
            mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
            mac_ocp_write(tp, 0xD3C2, mac_ocp_data);
            mac_ocp_data = mac_ocp_read(tp, 0xD3C4);
            mac_ocp_data |= BIT_0;
            mac_ocp_write(tp, 0xD3C4, mac_ocp_data);
        } else if (tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) {
            
            if(tp->RequireAdjustUpsTxLinkPulseTiming) {
                mac_ocp_data = mac_ocp_read(tp, 0xD412);
                mac_ocp_data &= ~(0x0FFF);
                mac_ocp_data |= tp->SwrCnt1msIni ;
                mac_ocp_write(tp, 0xD412, mac_ocp_data);
            }
            
            mac_ocp_data = mac_ocp_read(tp, 0xE056);
            mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4);
            mac_ocp_data |= (BIT_6 | BIT_5 | BIT_4);
            mac_ocp_write(tp, 0xE056, mac_ocp_data);
            
            mac_ocp_data = mac_ocp_read(tp, 0xE052);
            mac_ocp_data &= ~( BIT_14 | BIT_13);
            mac_ocp_data |= BIT_15;
            mac_ocp_data |= BIT_3;
            mac_ocp_write(tp, 0xE052, mac_ocp_data);
            
            mac_ocp_data = mac_ocp_read(tp, 0xD420);
            mac_ocp_data &= ~(BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
            mac_ocp_data |= 0x47F;
            mac_ocp_write(tp, 0xD420, mac_ocp_data);
            
            mac_ocp_data = mac_ocp_read(tp, 0xE0D6);
            mac_ocp_data &= ~(BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
            mac_ocp_data |= 0x17F;
            mac_ocp_write(tp, 0xE0D6, mac_ocp_data);
        }
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg8(0x1B, ReadReg8(0x1B) & ~0x07);
        
        WriteReg8(TDFNR, 0x4);
        
        WriteReg8(Config2, ReadReg8(Config2) & ~PMSTS_En);
        
        if (tp->aspm)
            WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_7);
        
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        
        rtl8168_eri_write(baseAddr, 0x5F0, 2, 0x4F87, ERIAR_ExGMAC);
        
        if (tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) {
            csi_tmp = rtl8168_eri_read(baseAddr, 0xD4, 4, ERIAR_ExGMAC);
            csi_tmp |= (BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12);
            rtl8168_eri_write(baseAddr, 0xD4, 4, csi_tmp, ERIAR_ExGMAC);
            
            csi_tmp = rtl8168_eri_read(baseAddr, 0xDC, 4, ERIAR_ExGMAC);
            csi_tmp |= (BIT_2 | BIT_3 | BIT_4);
            rtl8168_eri_write(baseAddr, 0xDC, 4, csi_tmp, ERIAR_ExGMAC);
        } else {
            csi_tmp = rtl8168_eri_read(baseAddr, 0xD4, 4, ERIAR_ExGMAC);
            csi_tmp |= (BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12);
            rtl8168_eri_write(baseAddr, 0xD4, 4, csi_tmp, ERIAR_ExGMAC);
        }
        
        if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
            tp->mcfg == CFG_METHOD_24 || tp->mcfg == CFG_METHOD_25) {
            mac_ocp_write(tp, 0xC140, 0xFFFF);
        } else if (tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) {
            mac_ocp_write(tp, 0xC140, 0xFFFF);
            mac_ocp_write(tp, 0xC142, 0xFFFF);
        }
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1B0, 4, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_12;
        rtl8168_eri_write(baseAddr, 0x1B0, 4, csi_tmp, ERIAR_ExGMAC);
        
        if (tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) {
            csi_tmp = rtl8168_eri_read(baseAddr, 0x2FC, 1, ERIAR_ExGMAC);
            csi_tmp &= ~(BIT_2);
            rtl8168_eri_write(baseAddr, 0x2FC, 1, csi_tmp, ERIAR_ExGMAC);
        } else {
            csi_tmp = rtl8168_eri_read(baseAddr, 0x2FC, 1, ERIAR_ExGMAC);
            csi_tmp &= ~(BIT_0 | BIT_1 | BIT_2);
            csi_tmp |= BIT_0;
            rtl8168_eri_write(baseAddr, 0x2FC, 1, csi_tmp, ERIAR_ExGMAC);
        }
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1D0, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_1;
        rtl8168_eri_write(baseAddr, 0x1D0, 1, csi_tmp, ERIAR_ExGMAC);
        
    } else if (tp->mcfg == CFG_METHOD_23 || tp->mcfg == CFG_METHOD_27 ||
               tp->mcfg == CFG_METHOD_28) {
        
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        rtl8168_eri_write(baseAddr, 0xC8, 4, 0x00080002, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xCC, 1, 0x2F, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xD0, 1, 0x5F, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        
        WriteReg32(TxConfig, ReadReg32(TxConfig) | BIT_7);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xDC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_7);
        
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        WriteReg8(0x1B, ReadReg8(0x1B) & ~0x07);
        
        WriteReg8(TDFNR, 0x4);
        
        if (tp->aspm)
            WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1B0, 4, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_12;
        rtl8168_eri_write(baseAddr, 0x1B0, 4, csi_tmp, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x2FC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~(BIT_0 | BIT_1 | BIT_2);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0x2FC, 1, csi_tmp, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1D0, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_1;
        rtl8168_eri_write(baseAddr, 0x1D0, 1, csi_tmp, ERIAR_ExGMAC);
        
        if (tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28) {
            OOB_mutex_lock(tp);
            rtl8168_eri_write(baseAddr, 0x5F0, 2, 0x4F87, ERIAR_ExGMAC);
            OOB_mutex_unlock(tp);
        }
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD4, 4, ERIAR_ExGMAC);
        csi_tmp  |= ( BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12 );
        rtl8168_eri_write(baseAddr, 0xD4, 4, csi_tmp, ERIAR_ExGMAC);
        
        mac_ocp_write(tp, 0xC140, 0xFFFF);
        mac_ocp_write(tp, 0xC142, 0xFFFF);
        
        if (tp->mcfg == CFG_METHOD_28) {
            mac_ocp_data = mac_ocp_read(tp, 0xD3E2);
            mac_ocp_data &= 0xF000;
            mac_ocp_data |= 0x3A9;
            mac_ocp_write(tp, 0xD3E2, mac_ocp_data);
            
            mac_ocp_data = mac_ocp_read(tp, 0xD3E4);
            mac_ocp_data &= 0xFF00;
            mac_ocp_write(tp, 0xD3E4, mac_ocp_data);
            
            mac_ocp_data = mac_ocp_read(tp, 0xE860);
            mac_ocp_data |= BIT_7;
            mac_ocp_write(tp, 0xE860, mac_ocp_data);
        }
        
	} else if (tp->mcfg == CFG_METHOD_1) {
		WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
		WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        device_control = pciDevice->configRead8(0x69);
        device_control &= ~0x70;
        device_control |= 0x58;
        pciDevice->configWrite8(0x69, device_control);
        
	} else if (tp->mcfg == CFG_METHOD_2) {
		WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
		WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
		WriteReg8(MTPS, Reserved1_data);
        device_control = pciDevice->configRead8(0x69);
        device_control &= ~0x70;
        device_control |= 0x58;
        pciDevice->configWrite8(0x69, device_control);
        WriteReg8(Config4, ReadReg8(Config4) & ~(1 << 0));

	} else if (tp->mcfg == CFG_METHOD_3) {
		WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
		WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
		WriteReg8(MTPS, Reserved1_data);
        device_control = pciDevice->configRead8(0x69);
        device_control &= ~0x70;
        device_control |= 0x58;
        pciDevice->configWrite8(0x69, device_control);
        WriteReg8(Config4, ReadReg8(Config4) & ~(1 << 0));

	} else if (tp->mcfg == CFG_METHOD_DEFAULT) {
		tp->cp_cmd &= 0x2043;
		WriteReg8(MTPS, 0x0C);
	}
    if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
        tp->mcfg == CFG_METHOD_23 || tp->mcfg == CFG_METHOD_24 ||
        tp->mcfg == CFG_METHOD_25 || tp->mcfg == CFG_METHOD_26 ||
        tp->mcfg == CFG_METHOD_27)
        rtl8168_eri_write(baseAddr, 0x2F8, 2, 0x1D8F, ERIAR_ExGMAC);
    
    if (tp->bios_setting & BIT_28) {
        if (tp->mcfg == CFG_METHOD_18 || tp->mcfg == CFG_METHOD_19 ||
            tp->mcfg == CFG_METHOD_20) {
            u32 gphy_val;
            
            mdio_write(tp, 0x1F, 0x0007);
            mdio_write(tp, 0x1E, 0x002C);
            gphy_val = mdio_read(tp, 0x16);
            gphy_val |= BIT_10;
            mdio_write(tp, 0x16, gphy_val);
            mdio_write(tp, 0x1F, 0x0005);
            mdio_write(tp, 0x05, 0x8B80);
            gphy_val = mdio_read(tp, 0x06);
            gphy_val |= BIT_7;
            mdio_write(tp, 0x06, gphy_val);
            mdio_write(tp, 0x1F, 0x0000);
        }
    }
    switch (tp->mcfg) {
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            mac_ocp_write(tp, 0xE098, 0x0AA2);
            break;
    }
    switch (tp->mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            if (tp->aspm) {
                initPCIOffset99();
            }
            break;
    }
    switch (tp->mcfg) {
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            if (tp->aspm) {
                rtl8168_init_pci_offset_180(tp);
            }
            break;
    }
    tp->cp_cmd &= ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en | Cxpl_dbg_sel | ASF | Macdbgo_sel);
    tp->cp_cmd |= (RxChkSum | RxVlan);
	WriteReg16(CPlusCmd, tp->cp_cmd);
    ReadReg16(CPlusCmd);
	WriteReg8(ChipCmd, CmdTxEnb | CmdRxEnb);
	
    switch (tp->mcfg) {
        case CFG_METHOD_16:
        case CFG_METHOD_17:
        case CFG_METHOD_18:
        case CFG_METHOD_19:
        case CFG_METHOD_20:
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:	{
            int timeout;
            for (timeout = 0; timeout < 10; timeout++) {
                if ((rtl8168_eri_read(baseAddr, 0x1AE, 2, ERIAR_ExGMAC) & BIT_13)==0)
                    break;
                mdelay(1);
            }
        }
        break;
    }        
    /* Set RxMaxSize register */
    WriteReg16(RxMaxSize, RX_BUF_SIZE);
    
    rtl8168_disable_rxdvgate(tp);
    rtl8168_dsm(tp, DSM_MAC_INIT);

    /* Set receiver mode. */
    setMulticastMode(multicastMode);
    
    switch (tp->mcfg) {
        case CFG_METHOD_14:
        case CFG_METHOD_15:
        case CFG_METHOD_16:
        case CFG_METHOD_17:
        case CFG_METHOD_18:
        case CFG_METHOD_19:
        case CFG_METHOD_20:
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            if (tp->aspm) {
                WriteReg8(Config5, ReadReg8(Config5) | BIT_0);
                WriteReg8(Config2, ReadReg8(Config2) | BIT_7);
            } else {
                WriteReg8(Config2, ReadReg8(Config2) & ~BIT_7);
                WriteReg8(Config5, ReadReg8(Config5) & ~BIT_0);
            }
            break;
    }    
    WriteReg8(Cfg9346, Cfg9346_Lock);
    
    if (enableInterrupts) {
        /* Enable all known interrupts by setting the interrupt mask. */
        WriteReg16(IntrMask, intrMask);
    }
	udelay(10);
}

void RTL8111::setPhyMedium()
{
    struct rtl8168_private *tp = &linuxData;
    int autoNego = 0;
    int gigaCtrl = 0;
    int force = 0;
    
    if (tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) {
        /* Disable Giga Lite. */
        mdio_write(tp, 0x1F, 0x0A42);
        ClearEthPhyBit(tp, 0x14, BIT_9);
        mdio_write(tp, 0x1F, 0x0A40);
        mdio_write(tp, 0x1F, 0x0000);
    }
    if ((speed != SPEED_1000) && (speed != SPEED_100) && (speed != SPEED_10)) {
        speed = SPEED_1000;
        duplex = DUPLEX_FULL;
        autoneg = AUTONEG_ENABLE;
    }
    autoNego = mdio_read(tp, MII_ADVERTISE);
    autoNego &= ~(ADVERTISE_10HALF | ADVERTISE_10FULL | ADVERTISE_100HALF | ADVERTISE_100FULL | ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);
    
    gigaCtrl = mdio_read(tp, MII_CTRL1000);
    gigaCtrl &= ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL);
    
    if ((autoneg == AUTONEG_ENABLE) || (speed == SPEED_1000)) {
        /* n-way force */
        if ((speed == SPEED_10) && (duplex == DUPLEX_HALF)) {
            autoNego |= ADVERTISE_10HALF;
        } else if ((speed == SPEED_10) && (duplex == DUPLEX_FULL)) {
            autoNego |= ADVERTISE_10HALF |
            ADVERTISE_10FULL;
        } else if ((speed == SPEED_100) && (duplex == DUPLEX_HALF)) {
            autoNego |= ADVERTISE_100HALF |
            ADVERTISE_10HALF |
            ADVERTISE_10FULL;
        } else if ((speed == SPEED_100) && (duplex == DUPLEX_FULL)) {
            autoNego |= ADVERTISE_100HALF | ADVERTISE_100FULL | ADVERTISE_10HALF | ADVERTISE_10FULL;
        } else if (speed == SPEED_1000) {
            gigaCtrl |= ADVERTISE_1000HALF | ADVERTISE_1000FULL;
            
            autoNego |= ADVERTISE_100HALF | ADVERTISE_100FULL | ADVERTISE_10HALF | ADVERTISE_10FULL;
        }
        autoneg = AUTONEG_ENABLE;
        
        /* Set flow control support. */
        if (flowCtl)
            autoNego |= ADVERTISE_PAUSE_CAP|ADVERTISE_PAUSE_ASYM;
        
        tp->phy_auto_nego_reg = autoNego;
        tp->phy_1000_ctrl_reg = gigaCtrl;
        
        /* Setup EEE advertisemnet. */
        if (eeeCap) {
            mdio_write(&linuxData, 0x0D, 0x0007);
            mdio_write(&linuxData, 0x0E, 0x003C);
            mdio_write(&linuxData, 0x0D, 0x4007);
            mdio_write(&linuxData, 0x0E, eeeAdv);
        }
        mdio_write(tp, 0x1f, 0x0000);
        mdio_write(tp, MII_ADVERTISE, autoNego);
        mdio_write(tp, MII_CTRL1000, gigaCtrl);
        mdio_write(tp, MII_BMCR, BMCR_RESET | BMCR_ANENABLE | BMCR_ANRESTART);
        mdelay(20);
    } else {
        /* true force */
        if ((speed == SPEED_10) && (duplex == DUPLEX_HALF)) {
            force = BMCR_SPEED10;
        } else if ((speed == SPEED_10) && (duplex == DUPLEX_FULL)) {
            force = BMCR_SPEED10 | BMCR_FULLDPLX;
        } else if ((speed == SPEED_100) && (duplex == DUPLEX_HALF)) {
            force = BMCR_SPEED100;
        } else if ((speed == SPEED_100) && (duplex == DUPLEX_FULL)) {
            force = BMCR_SPEED100 | BMCR_FULLDPLX;
        }
        
        mdio_write(tp, 0x1f, 0x0000);
        mdio_write(tp, MII_BMCR, force);
    }
    tp->autoneg = autoneg;
    tp->speed = speed;
    tp->duplex = duplex;
    
    if (tp->mcfg == CFG_METHOD_11)
        rtl8168dp_10mbps_gphy_para(&linuxData);
}

/* Set PCI configuration space offset 0x79 to setting. */

void RTL8111::setOffset79(UInt8 setting)
{
    UInt8 deviceControl;
    
    DebugLog("setOffset79() ===>\n");
    
    deviceControl = pciDevice->configRead8(0x79);
    deviceControl &= ~0x70;
    deviceControl |= setting;
    pciDevice->configWrite8(0x79, deviceControl);
    
    DebugLog("setOffset79() <===\n");
}

UInt8 RTL8111::csiFun0ReadByte(UInt32 addr)
{
    UInt8 retVal = 0;
    
    if (linuxData.mcfg == CFG_METHOD_20 || linuxData.mcfg == CFG_METHOD_26) {
        UInt32 tmpUlong;
        UInt8 shiftByte;
        
        shiftByte = addr & (0x3);
        tmpUlong = rtl8168_csi_other_fun_read(&linuxData, 0, addr);
        tmpUlong >>= (8 * shiftByte);
        retVal = (UInt8)tmpUlong;
    } else {        
        retVal = pciDevice->configRead8(addr);
    }
    return retVal;
}

void RTL8111::csiFun0WriteByte(UInt32 addr, UInt8 value)
{
    if (linuxData.mcfg == CFG_METHOD_20 || linuxData.mcfg == CFG_METHOD_26) {
        UInt32 tmpUlong;
        UInt16 regAlignAddr;
        UInt8 shiftByte;
        
        regAlignAddr = addr & ~(0x3);
        shiftByte = addr & (0x3);
        tmpUlong = rtl8168_csi_other_fun_read(&linuxData, 0, regAlignAddr);
        tmpUlong &= ~(0xFF << (8 * shiftByte));
        tmpUlong |= (value << (8 * shiftByte));
        rtl8168_csi_other_fun_write(&linuxData, 0, regAlignAddr, tmpUlong );
    } else {
        pciDevice->configWrite8(addr, value);
    }
}

void RTL8111::enablePCIOffset99()
{
    u32 csi_tmp;
    
    switch (linuxData.mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_26:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            csiFun0WriteByte(0x99, linuxData.org_pci_offset_99);
            break;
    }
    
    switch (linuxData.mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            csi_tmp = rtl8168_eri_read(baseAddr, 0x3F2, 2, ERIAR_ExGMAC);
            csi_tmp &= ~(BIT_0 | BIT_1);
            if (!(linuxData.org_pci_offset_99 & (BIT_5 | BIT_6)))
                csi_tmp |= BIT_1;
            if (!(linuxData.org_pci_offset_99 & BIT_2))
                csi_tmp |= BIT_0;
            rtl8168_eri_write(baseAddr, 0x3F2, 2, csi_tmp, ERIAR_ExGMAC);
            break;
    }
}

void RTL8111::disablePCIOffset99()
{
    UInt32 csi_tmp;
    
    switch (linuxData.mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            csi_tmp = rtl8168_eri_read(baseAddr, 0x3F2, 2, ERIAR_ExGMAC);
            csi_tmp &= ~(BIT_0 | BIT_1);
            rtl8168_eri_write(baseAddr, 0x3F2, 2, csi_tmp, ERIAR_ExGMAC);
            break;
    }
    switch (linuxData.mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_26:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            csiFun0WriteByte(0x99, 0x00);
            break;
    }
}

void RTL8111::initPCIOffset99()
{
    struct rtl8168_private *tp = &linuxData;
    UInt32 csi_tmp;
    
    switch (tp->mcfg) {
        case CFG_METHOD_26:
            if (tp->org_pci_offset_99 & BIT_2) {
                csi_tmp = rtl8168_eri_read(baseAddr, 0x5C2, 1, ERIAR_ExGMAC);
                csi_tmp &= ~BIT_1;
                rtl8168_eri_write(baseAddr, 0x5C2, 1, csi_tmp, ERIAR_ExGMAC);
            }
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            csi_tmp = rtl8168_eri_read(baseAddr, 0x3F2, 2, ERIAR_ExGMAC);
            csi_tmp &= ~( BIT_8 | BIT_9  | BIT_10 | BIT_11  | BIT_12  | BIT_13  | BIT_14 | BIT_15 );
            csi_tmp |= ( BIT_9 | BIT_10 | BIT_13  | BIT_14 | BIT_15 );
            rtl8168_eri_write(baseAddr, 0x3F2, 2, csi_tmp, ERIAR_ExGMAC);
            csi_tmp = rtl8168_eri_read(baseAddr, 0x3F5, 1, ERIAR_ExGMAC);
            csi_tmp |= BIT_6 | BIT_7;
            rtl8168_eri_write(baseAddr, 0x3F5, 1, csi_tmp, ERIAR_ExGMAC);
            mac_ocp_write(tp, 0xE02C, 0x1880);
            mac_ocp_write(tp, 0xE02E, 0x4880);
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_26:
            rtl8168_eri_write(baseAddr, 0x5C0, 1, 0xFA, ERIAR_ExGMAC);
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_26:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            if (tp->org_pci_offset_99 & BIT_2) {
                csi_tmp = rtl8168_eri_read(baseAddr, 0x5C8, 1, ERIAR_ExGMAC);
                csi_tmp |= BIT_0;
                rtl8168_eri_write(baseAddr, 0x5C8, 1, csi_tmp, ERIAR_ExGMAC);
            }
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_23:
            rtl8168_eri_write(baseAddr, 0x2E8, 2, 0x883C, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2EA, 2, 0x8C12, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2EC, 2, 0x9003, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2E2, 2, 0x883C, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2E4, 2, 0x8C12, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2E6, 2, 0x9003, ERIAR_ExGMAC);
            break;
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            rtl8168_eri_write(baseAddr, 0x2E8, 2, 0x9003, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2EA, 2, 0x9003, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2EC, 2, 0x9003, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2E2, 2, 0x883C, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2E4, 2, 0x8C12, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0x2E6, 2, 0x9003, ERIAR_ExGMAC);
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
            csi_tmp = rtl8168_eri_read(baseAddr, 0x3FA, 2, ERIAR_ExGMAC);
            csi_tmp |= BIT_14;
            rtl8168_eri_write(baseAddr, 0x3FA, 2, csi_tmp, ERIAR_ExGMAC);
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_26:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            if (tp->org_pci_offset_99 & BIT_2)
                WriteReg8(0xB6, ReadReg8(0xB6) | BIT_0);
            break;
    }
    
    enablePCIOffset99();
}

void RTL8111::setPCI99_180ExitDriverPara()
{
    struct rtl8168_private *tp = &linuxData;
    
    switch (tp->mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            rtl8168_issue_offset_99_event(tp);
            break;
    }
    switch (tp->mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            disablePCIOffset99();
            break;
    }
    switch (tp->mcfg) {
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            rtl8168_disable_pci_offset_180(tp);
            break;
    }
}

void RTL8111::hardwareD3Para()
{
    struct rtl8168_private *tp = &linuxData;
    
    /* Set RxMaxSize register */
    WriteReg16(RxMaxSize, RX_BUF_SIZE);

    switch (tp->mcfg) {
        case CFG_METHOD_14:
        case CFG_METHOD_15:
        case CFG_METHOD_16:
        case CFG_METHOD_17:
        case CFG_METHOD_18:
        case CFG_METHOD_19:
        case CFG_METHOD_20:
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_23:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            WriteReg8(0xF1, ReadReg8(0xF1) & ~BIT_7);
            WriteReg8(Cfg9346, Cfg9346_Unlock);
            WriteReg8(Config2, ReadReg8(Config2) & ~BIT_7);
            WriteReg8(Config5, ReadReg8(Config5) & ~BIT_0);
            WriteReg8(Cfg9346, Cfg9346_Lock);
            break;
    }
    if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
        tp->mcfg == CFG_METHOD_23 || tp->mcfg == CFG_METHOD_24 ||
        tp->mcfg == CFG_METHOD_25 || tp->mcfg == CFG_METHOD_26 ||
        tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28) {
        rtl8168_eri_write(baseAddr, 0x2F8, 2, 0x0064, ERIAR_ExGMAC);
    }
    
    if (tp->bios_setting & BIT_28) {
        if (tp->mcfg == CFG_METHOD_18 || tp->mcfg == CFG_METHOD_19 ||
            tp->mcfg == CFG_METHOD_20) {
            u32 gphy_val;
            
            mdio_write(tp, 0x1F, 0x0000);
            mdio_write(tp, 0x04, 0x0061);
            mdio_write(tp, 0x09, 0x0000);
            mdio_write(tp, 0x00, 0x9200);
            mdio_write(tp, 0x1F, 0x0005);
            mdio_write(tp, 0x05, 0x8B80);
            gphy_val = mdio_read(tp, 0x06);
            gphy_val &= ~BIT_7;
            mdio_write(tp, 0x06, gphy_val);
            mdelay(1);
            mdio_write(tp, 0x1F, 0x0007);
            mdio_write(tp, 0x1E, 0x002C);
            gphy_val = mdio_read(tp, 0x16);
            gphy_val &= ~BIT_10;
            mdio_write(tp, 0x16, gphy_val);
            mdio_write(tp, 0x1F, 0x0000);
        }
    }
    setPCI99_180ExitDriverPara();
    
    /*disable ocp phy power saving*/
    if (tp->mcfg == CFG_METHOD_25 || tp->mcfg == CFG_METHOD_26 ||
        tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28 ||
        tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) {
        mdio_write_phy_ocp(tp, 0x0C41, 0x13, 0x0000);
        mdio_write_phy_ocp(tp, 0x0C41, 0x13, 0x0500);
    }
    rtl8168_disable_rxdvgate(tp);
}

#pragma mark --- RTL8111C specific methods ---

void RTL8111::timerActionRTL8111C(IOTimerEventSource *timer)
{
    if (!linkUp) {
        DebugLog("Ethernet [RealtekRTL8111]: Timer fired while link down.\n");
        goto done;
    }
    /* Check for tx deadlock. */
    if (checkForDeadlock())
        goto done;
    
    updateStatitics();
    timerSource->setTimeoutMS(kTimeoutMS);
    
    /* We can savely free the mbuf here because the timer action gets called
     * synchronized to the workloop.
     */
    if (txNext2FreeMbuf) {
        freePacket(txNext2FreeMbuf);
        txNext2FreeMbuf = NULL;
    }
    
done:
    txDescDoneLast = txDescDoneCount;
    
    //DebugLog("timerActionRTL8111C() <===\n");
}

#pragma mark --- RTL8111B/8168B specific methods ---

void RTL8111::timerActionRTL8111B(IOTimerEventSource *timer)
{
	UInt8 currLinkState;
    bool newLinkState;

    currLinkState = ReadReg8(PHYstatus);
	newLinkState = (currLinkState & LinkStatus) ? true : false;
    
    if (newLinkState != linkUp) {
        if (newLinkState)
            setLinkUp(currLinkState);
        else
            setLinkDown();
    }
    /* Check for tx deadlock. */
    if (linkUp) {
        if (checkForDeadlock())
            goto done;
        
        updateStatitics();
    }
    /* We can savely free the mbuf here because the timer action gets called
     * synchronized to the workloop.
     */
    if (txNext2FreeMbuf) {
        freePacket(txNext2FreeMbuf);
        txNext2FreeMbuf = NULL;
    }
    
done:
    timerSource->setTimeoutMS(kTimeoutMS);
    txDescDoneLast = txDescDoneCount;
    
    //DebugLog("timerActionRTL8111B() <===\n");
}

#pragma mark --- miscellaneous functions ---

static inline UInt32 adjustIPv6Header(mbuf_t m)
{
    struct ip6_hdr *ip6Hdr = (struct ip6_hdr *)((UInt8 *)mbuf_data(m) + ETHER_HDR_LEN);
    struct tcphdr *tcpHdr = (struct tcphdr *)((UInt8 *)ip6Hdr + sizeof(struct ip6_hdr));
    UInt32 plen = ntohs(ip6Hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
    UInt32 csum = ntohs(tcpHdr->th_sum) - plen;
    
    csum += (csum >> 16);
    ip6Hdr->ip6_ctlun.ip6_un1.ip6_un1_plen = 0;
    tcpHdr->th_sum = htons((UInt16)csum);
    
    return (plen + kMinL4HdrOffsetV6);
}

static unsigned const ethernet_polynomial = 0x04c11db7U;

static inline u32 ether_crc(int length, unsigned char *data)
{
    int crc = -1;
    
    while(--length >= 0) {
        unsigned char current_octet = *data++;
        int bit;
        for (bit = 0; bit < 8; bit++, current_octet >>= 1) {
            crc = (crc << 1) ^
            ((crc < 0) ^ (current_octet & 1) ? ethernet_polynomial : 0);
        }
    }
    return crc;
}

