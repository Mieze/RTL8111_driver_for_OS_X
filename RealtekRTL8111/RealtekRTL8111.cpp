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
 * This driver is based on Realtek's r8168 Linux driver.
 */


#include "RealtekRTL8111.h"

#pragma mark --- function prototypes ---

static inline void fillDescriptorAddr(volatile void *baseAddr, IOPhysicalAddress64 txPhyAddr, IOPhysicalAddress64 rxPhyAddr);
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
        pciDevice = NULL;
        mediumDict = NULL;
        txQueue = NULL;
        interruptSource = NULL;
        timerSource = NULL;
        txLock = NULL;
        netif = NULL;
        netStats = NULL;
        etherStats = NULL;
        baseMap = NULL;
        baseAddr = NULL;
        rxMbufCursor = NULL;
        txMbufCursor = NULL;
        statBufDesc = NULL;
        statPhyAddr = NULL;
        statData = NULL;
        isEnabled = false;
        promiscusMode = false;
        multicastMode = false;
        linkUp = false;
        stalled = false;
        useMSI = false;
        mtu = ETH_DATA_LEN;
        powerState = 0;
        speed = SPEED_1000;
        duplex = DUPLEX_FULL;
        autoneg = AUTONEG_ENABLE;
        linuxData.eeeEnable = 0;
        linuxData.aspm = 0;
        pciDeviceData.vendor = 0;
        pciDeviceData.device = 0;
        pciDeviceData.subsystem_vendor = 0;
        pciDeviceData.subsystem_device = 0;
        linuxData.pci_dev = &pciDeviceData;
        unitNumber = 0;
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
    RELEASE(txQueue);

    if (txLock) {
        IOLockFree(txLock);
        txLock = NULL;
    }
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

bool RTL8111::start(IOService *provider)
{
    bool result;
    
    result = super::start(provider);
    
    if (!result) {
        IOLog("RTL8111: IOEthernetController::start failed.\n");
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
    
    if (!initPCIConfigSpace(pciDevice)) {
        goto error2;
    }
    
    if (!initRTL8111()) {
        goto error2;
    }
    
    if (!setupMediumDict()) {
        IOLog("Ethernet [RealtekRTL8111]: Failed to setup medium dictionary.\n");
        goto error2;
    }
    
    txLock = IOLockAlloc();
    
    if (!txLock) {
        goto error2;
    }
    
    if (!initEventSources(provider)) {
        IOLog("Ethernet [RealtekRTL8111]: initEventSources() failed.\n");
        goto error3;
    }
    
    result = attachInterface(reinterpret_cast<IONetworkInterface**>(&netif));

    if (!result) {
        IOLog("Ethernet [RealtekRTL8111]: attachInterface() failed.\n");
        goto error3;
    }
    setLinkStatus(kIONetworkLinkValid);
    pciDevice->close(this);
    result = true;
    
done:
    return result;

error3:
    IOLockFree(txLock);
    txLock = NULL;
    
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
    RELEASE(txQueue);
    
    if (txLock) {
        IOLockFree(txLock);
        txLock = NULL;
    }
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
    
    DebugLog("Ethernet [RealtekRTL8111]: swithing to power state %lu.\n", powerStateOrdinal);
    
    DebugLog("setPowerState() <===\n");

    return result;
}

void RTL8111::systemWillShutdown(IOOptionBits specifier)
{
    DebugLog("systemWillShutdown() ===>\n");
    
    if ((kIOMessageSystemWillPowerOff | kIOMessageSystemWillRestart) & specifier)
        disable(netif);
    
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
    
    /* In case we are using an msi the interrupt hasn't been enabled by start(). */
    if (useMSI)
        interruptSource->enable();

    txReqDoneCount = txReqDoneLast = 0;
    deadlockWarn = 0;
    needsUpdate = false;
    txQueue->setCapacity(kTransmitQueueCapacity);
    isEnabled = true;
    stalled = false;

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

    timerSource->cancelTimeout();
    needsUpdate = false;
    txReqDoneCount = txReqDoneLast = 0;

    /* In case we are using msi disable the interrupt. */
    if (useMSI)
        interruptSource->disable();

    txQueue->stop();
    txQueue->setCapacity(0);
    txQueue->flush();    
    disableRTL8111();

    setLinkStatus(kIONetworkLinkValid);
    linkUp = false;
    isEnabled = false;
    stalled = false;
    txClearDescriptors(true);

    if (pciDevice && pciDevice->isOpen())
        pciDevice->close(this);
    
    freeDMADescriptors();

    DebugLog("disable() <===\n");

done:
    return result;
}

UInt32 RTL8111::outputPacket(mbuf_t m, void *param)
{
    IOPhysicalSegment txSegments[kMaxSegs];
    RtlDmaDesc *desc, *firstDesc;
    UInt32 result = kIOReturnOutputDropped;
    mbuf_tso_request_flags_t tsoFlags;
    UInt32 mssValue;
    UInt32 tsoCmd;
    UInt32 opts1;
    UInt32 opts2;
    UInt32 vlanTag;
    UInt32 checksums;
    UInt32 numSegs;
    UInt32 lastSeg;
    UInt32 index;
    UInt32 i;
    
    //DebugLog("outputPacket() ===>\n");
    
    if (!(isEnabled && linkUp)) {
        DebugLog("Ethernet [RealtekRTL8111]: Interface down. Dropping packet.\n");
        goto error1;
    }
    
    if (!IOLockTryLock(txLock)) {
        DebugLog("Ethernet [RealtekRTL8111]: Couldn't aquire txLock. Dropping packet.\n");
        goto error1;
    }
    
    if (mbuf_get_tso_requested(m, &tsoFlags, &mssValue)) {
        DebugLog("Ethernet [RealtekRTL8111]: mbuf_get_tso_requested() failed. Dropping packet.\n");
        goto error2;
    }
    
    numSegs = txMbufCursor->getPhysicalSegmentsWithCoalesce(m, &txSegments[0], kMaxSegs);
    
    if (!numSegs) {
        DebugLog("Ethernet [RealtekRTL8111]: getPhysicalSegmentsWithCoalesce() failed. Dropping packet.\n");
        goto error2;
    }
    /* Alloc required number of descriptors. */
    if ((txNumFreeDesc < numSegs)) {
        DebugLog("Ethernet [RealtekRTL8111]: Not enough descriptors. Stalling.\n");
        result = kIOReturnOutputStall;
        stalled = true;
        goto error2;
    }
    OSAddAtomic(-numSegs, &txNumFreeDesc);
    index = txNextDescIndex;
    txNextDescIndex = (txNextDescIndex + numSegs) & kTxDescMask;
    firstDesc = desc = &txDescArray[index];
    lastSeg = numSegs - 1;
    tsoCmd = 0;
    
    /* First fill in the VLAN tag. */
    opts2 = (getVlanTagDemand(m, &vlanTag)) ? (OSSwapInt16(vlanTag) | TxVlanTag) : 0;
    
    /* Next setup the checksum command bits. */
    getChecksumDemand(m, kChecksumFamilyTCPIP, &checksums);
    
    if (checksums & (kChecksumTCP | kChecksumTCPIPv6))
        opts2 |= linuxData.tx_tcp_csum_cmd;
    else if (checksums & (kChecksumUDP | kChecksumUDPIPv6))
        opts2 |= linuxData.tx_udp_csum_cmd;
    else if (checksums & kChecksumIP)
        opts2 |= linuxData.tx_ip_csum_cmd;
    
    if (tsoFlags) {
        opts2 |= ((mssValue & MSSMask) << MSSShift_C);
        tsoCmd = LargeSend;
    }
    /* And finally fill in the descriptors. */
    for (i = 0; i < numSegs; i++) {
        desc = &txDescArray[index];
        opts1 = (((UInt32)txSegments[i].length) | tsoCmd);
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
        
    IOLockUnlock(txLock);
    
done:
    //DebugLog("outputPacket() <===\n");
    
    return result;
    
error2:
    IOLockUnlock(txLock);
    
error1:
    freePacket(m);
    goto done;
    
}

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
    IONetworkData *data;
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
    unitNumber = interface->getUnitNumber();
    
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
        IOLog("Ethernet [RealtekRTL8111]: Promiscuous mode enabled.\n");
        rxMode = (AcceptBroadcast | AcceptMulticast | AcceptMyPhys | AcceptAllPhys);
        mcFilter[1] = mcFilter[0] = 0xffffffff;
    } else{
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
    
    if (count <= kMCFilterLimit) {
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
    
    if ((checksumFamily == kChecksumFamilyTCPIP) && checksumMask) {
        if (isOutput)
            *checksumMask = (kChecksumTCP | kChecksumUDP | kChecksumIP);
        else
            *checksumMask = (kChecksumTCP | kChecksumUDP | kChecksumIP);

        result = kIOReturnSuccess;
    }
    return result;
}

IOReturn RTL8111::setMaxPacketSize (UInt32 maxSize)
{
    IOReturn result = kIOReturnUnsupported;
    
done:
    return result;
}

IOReturn RTL8111::getMaxPacketSize (UInt32 *maxSize) const
{
    IOReturn result = kIOReturnBadArgument;
    
    if (maxSize) {
        *maxSize = mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;
        result = kIOReturnSuccess;
    }
    return result;
}

IOReturn RTL8111::getMinPacketSize (UInt32 *minSize) const
{
    IOReturn result = super::getMinPacketSize(minSize);
    
done:
    return result;
}

IOReturn RTL8111::setWakeOnMagicPacket(bool active)
{
    IOReturn result = kIOReturnUnsupported;
    
done:
    return result;
}

IOReturn RTL8111::getPacketFilters(const OSSymbol *group, UInt32 *filters) const
{
    IOReturn result;
    
    result = super::getPacketFilters(group, filters);
    
done:
    return result;
}


UInt32 RTL8111::getFeatures() const
{    
    return (kIONetworkFeatureMultiPages | kIONetworkFeatureHardwareVlan | kIONetworkFeatureTSOIPv4 | kIONetworkFeatureTSOIPv6);
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
    bool success;
    
    DebugLog("selectMedium() ===>\n");
    
    if (medium) {
        switch (medium->getIndex()) {
            case MEDIUM_INDEX_AUTO:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                break;
                
            case MEDIUM_INDEX_10HD:
                autoneg = AUTONEG_DISABLE;
                speed = SPEED_10;
                duplex = DUPLEX_HALF;
                break;
                
            case MEDIUM_INDEX_10FD:
                autoneg = AUTONEG_DISABLE;
                speed = SPEED_10;
                duplex = DUPLEX_FULL;
                break;
                
            case MEDIUM_INDEX_100HD:
                autoneg = AUTONEG_DISABLE;
                speed = SPEED_100;
                duplex = DUPLEX_HALF;
                break;
                
            case MEDIUM_INDEX_100FD:
                autoneg = AUTONEG_DISABLE;
                speed = SPEED_100;
                duplex = DUPLEX_FULL;
                break;
                
            case MEDIUM_INDEX_1000FD:
                autoneg = AUTONEG_DISABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                break;
        }
        rtl8168_set_speed(&linuxData, autoneg, speed, duplex);
        success = setCurrentMedium(medium);
    }
    
    DebugLog("selectMedium() <===\n");
    
done:
    return result;
}

#pragma mark --- data structure initialization methods ---

static IOMediumType mediumTypeArray[MEDIUM_INDEX_COUNT] = {
    kIOMediumEthernetAuto,
    (kIOMediumEthernet10BaseT | kIOMediumOptionHalfDuplex),
    (kIOMediumEthernet10BaseT | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionHalfDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex)
};

static UInt32 mediumSpeedArray[MEDIUM_INDEX_COUNT] = {
    0,
    10 * MBit,
    10 * MBit,
    100 * MBit,
    100 * MBit,
    1000 * MBit
};

bool RTL8111::setupMediumDict()
{
	IONetworkMedium *medium;
    UInt32 i;
    bool result = false;

    mediumDict = OSDictionary::withCapacity(MEDIUM_INDEX_COUNT + 1);

    if (mediumDict) {
        for (i = MEDIUM_INDEX_AUTO; i < MEDIUM_INDEX_COUNT; i++) {
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
        DebugLog("Ethernet [RealtekRTL8111]: Warning: MSI index was not found or MSI interrupt could not be enabled.\n");
        interruptSource = IOInterruptEventSource::interruptEventSource(this, OSMemberFunctionCast(IOInterruptEventSource::Action, this, &RTL8111::interruptOccurred), provider);
        useMSI = false;
    } else {
        useMSI = true;
    }
    if (!interruptSource)
        goto error1;
    
    workLoop->addEventSource(interruptSource);
    
    /*
     * This is important. If the interrupt line is shared with other devices,
	 * then the interrupt vector will be enabled only if all corresponding
	 * interrupt event sources are enabled. To avoid masking interrupts for
	 * other devices that are sharing the interrupt line, the event source
	 * is enabled immediately.
     */
    if (!useMSI)
        interruptSource->enable();
    
    timerSource = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &RTL8111::timerAction));
    
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
    txMbufCursor = IOMbufNaturalMemoryCursor::withSpecification(PAGE_SIZE, kIOPacketBufferAlign1);
    
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
    
    rxMbufCursor = IOMbufNaturalMemoryCursor::withSpecification(PAGE_SIZE, kIOPacketBufferAlign8);
    
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
        
        if (rxMbufCursor->getPhysicalSegmentsWithCoalesce(m, &rxSegment, 1) != 1) {
            IOLog("Ethernet [RealtekRTL8111]: getPhysicalSegmentsWithCoalesce() for receive buffer failed.\n");
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

void RTL8111::txClearDescriptors(bool withReset)
{
    mbuf_t m;
    UInt32 lastIndex = kTxLastDesc;
    UInt32 i;
    
    DebugLog("txClearDescriptors() ===>\n");
    
    for (i = 0; i < kNumTxDesc; i++) {
        txDescArray[i].opts1 = OSSwapHostToLittleInt32((i != lastIndex) ? 0 : RingEnd);
        m = txMbufArray[i];
        
        if (m) {
            freePacket(m);
            txMbufArray[i] = NULL;
        }
    }
    if (withReset)
        txDirtyDescIndex = txNextDescIndex = 0;
    else
        txDirtyDescIndex = txNextDescIndex;
    
    txNumFreeDesc = kNumTxDesc;
    
    DebugLog("txClearDescriptors() <===\n");
}

#pragma mark --- interrupt and timer action methods ---

void RTL8111::txInterrupt()
{
    mbuf_t m;
    SInt32 numDirty = kNumTxDesc - txNumFreeDesc;
    UInt32 oldDirtyIndex = txDirtyDescIndex;
    UInt32 descStatus;
    
    while (numDirty-- > 0) {
        descStatus = OSSwapLittleToHostInt32(txDescArray[txDirtyDescIndex].opts1);
        
        if (descStatus & DescOwn)
            break;

        m = txMbufArray[txDirtyDescIndex];
        
        if (m) {
            freePacket(m);
            txMbufArray[txDirtyDescIndex] = NULL;
            txReqDoneCount++;
        }
        txDescArray[txDirtyDescIndex].addr = NULL;
        OSIncrementAtomic(&txNumFreeDesc);
        ++txDirtyDescIndex &= kTxDescMask;
    }
    if (stalled && (txNumFreeDesc >= kMaxSegs)) {
        DebugLog("Ethernet [RealtekRTL8111]: Restart stalled queue!\n");
        txQueue->service();
        stalled = false;
    }
    if (oldDirtyIndex != txDirtyDescIndex)
        WriteReg8(TxPoll, NPQ);
}

void RTL8111::rxInterrupt()
{
    IOPhysicalSegment rxSegment;
    RtlDmaDesc *desc = &rxDescArray[rxNextDescIndex];
    mbuf_t bufPkt, newPkt;
    UInt64 addr;
    UInt32 opts1, opts2;
    UInt32 descStatus1, descStatus2;
    UInt32 pktSize, pktType;
    UInt32 resultMask, validMask;
    UInt16 vlanTag;
    bool replaced;
    bool goodPkt = false;
        
    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->opts1)) & DescOwn)) {
        opts1 = (rxNextDescIndex == kRxLastDesc) ? (RingEnd | DescOwn) : DescOwn;
        opts2 = 0;
        addr = 0;
        
        /* As we don't support jumbo frames we consider fragmented packets as errors. */
        if ((descStatus1 & (FirstFrag|LastFrag)) != (FirstFrag|LastFrag)) {
            DebugLog("Ethernet [RealtekRTL8111]: Fragmented packet.\n");
            netStats->inputErrors++;
            opts1 |= kRxBufferPktSize;
            goto nextDesc;
        }
        
        descStatus2 = OSSwapLittleToHostInt32(desc->opts2);
        pktSize = (descStatus1 & 0x1fff) - 4;
        bufPkt = rxMbufArray[rxNextDescIndex];
        vlanTag = (descStatus2 & RxVlanTag) ? OSSwapInt16(descStatus2 & 0xffff) : 0;
        pktType = descStatus1 & RxProtoMask;
        
        //DebugLog("rxInterrupt(): descStatus1=0x%x, descStatus2=0x%x, pktSize=%u\n", descStatus1, descStatus2, pktSize);

        newPkt = replaceOrCopyPacket(&bufPkt, pktSize, &replaced);
        
        if (!newPkt) {
            /* Allocation of a new packet failed so that we must leave the original packet in place. */
            DebugLog("Ethernet [RealtekRTL8111]: replaceOrCopyPacket() failed.\n");
            netStats->inputErrors++;
            opts1 |= kRxBufferPktSize;
            goto nextDesc;
        }
        
        /* If the packet was replaced we have to update the descriptor's buffer address. */
        if (replaced) {
            if (rxMbufCursor->getPhysicalSegmentsWithCoalesce(bufPkt, &rxSegment, 1) != 1) {
                DebugLog("Ethernet [RealtekRTL8111]: getPhysicalSegmentsWithCoalesce() failed.\n");
                freePacket(bufPkt);
                netStats->inputErrors++;
                opts1 |= kRxBufferPktSize;
                goto nextDesc;
            }
            opts1 |= ((UInt32)rxSegment.length & 0x0000ffff);
            addr = rxSegment.location;
            rxMbufArray[rxNextDescIndex] = bufPkt;
        } else {
            opts1 |= kRxBufferPktSize;
        }
        resultMask = validMask = 0;

        /* Get the result of the checksum calculation and store it in the packet. */
        if (pktType == RxTCPT) {
            /* TCP packet */
            if (descStatus2 & RxV4F) {
                resultMask = (kChecksumTCP | kChecksumIP);
                validMask = (descStatus1 & RxTCPF) ? 0 : (kChecksumTCP | kChecksumIP);
            } else {
                resultMask = kChecksumTCPIPv6;
                validMask = (descStatus1 & RxTCPF) ? 0 : kChecksumTCPIPv6;
            }
        } else if (pktType == RxUDPT) {
            /* UDP packet */
            if (descStatus2 & RxV4F) {
                resultMask = (kChecksumUDP | kChecksumIP);
                validMask = (descStatus1 & RxUDPF) ? 0 : (kChecksumUDP | kChecksumIP);
            } else {
                resultMask = kChecksumUDPIPv6;
                validMask = (descStatus1 & RxTCPF) ? 0 : kChecksumUDPIPv6;
            }
        } else if ((pktType == 0) && (descStatus2 & RxV4F)) {
            /* IP packet */
            resultMask = kChecksumIP;
            validMask = (descStatus1 & RxIPF) ? 0 : kChecksumIP;
        }
        setChecksumResult(newPkt, kChecksumFamilyTCPIP, resultMask, validMask);

        /* Also get the VLAN tag if there is any. */
        if (vlanTag)
            setVlanTag(newPkt, vlanTag);

        netif->inputPacket(newPkt, pktSize, IONetworkInterface::kInputOptionQueuePacket);
        goodPkt = true;

        /* Finally update the descriptor and get the next one to examine. */
nextDesc:
        if (addr)
            desc->addr = OSSwapHostToLittleInt64(addr);

        desc->opts2 = OSSwapHostToLittleInt32(opts2);
        desc->opts1 = OSSwapHostToLittleInt32(opts1);

        ++rxNextDescIndex &= kRxDescMask;
        desc = &rxDescArray[rxNextDescIndex];
    }
    if (goodPkt)
        netif->flushInputQueue();
}

void RTL8111::updateStatitics()
{
    UInt32 sgColl, mlColl;
    
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

static const char *speed1GName = "1-Gigabit";
static const char *speed100MName = "100-Megabit";
static const char *speed10MName = "10-Megabit";
static const char *duplexFullName = "Full-duplex";
static const char *duplexHalfName = "Half-duplex";
static const char *offFlowName = "No flow-control";
static const char *onFlowName = "flow-control";

void RTL8111::checkLinkStatus()
{
    struct rtl8168_private *tp = &linuxData;
    UInt64 mediumSpeed;
    UInt32 mediumIndex = MEDIUM_INDEX_AUTO;
	UInt8 currLinkState;
    const char *speedName;
    const char *duplexName;
    const char *flowName;
    
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
			if (isEnabled && (ReadReg8(ChipCmd) & (CmdRxEnb | CmdTxEnb))==0) {
				int timeout;
                
				for (timeout = 0; timeout < 10; timeout++) {
					if ((rtl8168_eri_read(baseAddr, 0x1AE, 4, ERIAR_ExGMAC) & BIT_13)==0)
						break;
					mdelay(1);
				}
				//rtl8168_init_ring_indexes(tp);
				WriteReg8(ChipCmd, CmdRxEnb | CmdTxEnb);
			}
		} else if ((tp->mcfg == CFG_METHOD_16 || tp->mcfg == CFG_METHOD_17) && isEnabled) {
			u32 eri_data;
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
            
			eri_data = rtl8168_eri_read(baseAddr, 0xDC, 1, ERIAR_ExGMAC);
			eri_data &= ~BIT_0;
			rtl8168_eri_write(baseAddr, 0xDC, 1, eri_data, ERIAR_ExGMAC);
			eri_data |= BIT_0;
			rtl8168_eri_write(baseAddr, 0xDC, 1, eri_data, ERIAR_ExGMAC);
            
			if ((ReadReg8(ChipCmd) & (CmdRxEnb | CmdTxEnb))==0) {
				int timeout;
                
				for (timeout = 0; timeout < 10; timeout++) {
					if ((rtl8168_eri_read(baseAddr, 0x1AE, 4, ERIAR_ExGMAC) & BIT_13)==0)
						break;
					mdelay(1);
				}
				//rtl8168_init_ring_indexes(tp);
				WriteReg8(ChipCmd, CmdRxEnb | CmdTxEnb);
			}
            
		} else if ((tp->mcfg == CFG_METHOD_14 || tp->mcfg == CFG_METHOD_15) && eee_enable ==1){
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
		} else if ((tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 || tp->mcfg == CFG_METHOD_24) && isEnabled) {
			if ((ReadReg8(ChipCmd) & (CmdRxEnb | CmdTxEnb)) == 0) {
				//rtl8168_init_ring_indexes(tp);
                //fillDescriptorAddr(baseAddr, txPhyAddr, rxPhyAddr);
                WriteReg8(ChipCmd, CmdRxEnb | CmdTxEnb);
			}
		} else if (tp->mcfg == CFG_METHOD_23) {
			WriteReg32(ERIDR, 0x00000000);
			WriteReg32(ERIAR, 0x8042f108);
		}
        /* Get link speed, duplex and flow-control mode. */
        if (currLinkState & _1000bpsF) {
            mediumSpeed = kSpeed1000MBit;
            speed = SPEED_1000;
            mediumIndex = MEDIUM_INDEX_1000FD;
            speedName = speed1GName;
            duplexName = duplexFullName;
        } else if (currLinkState & _100bps) {
            mediumSpeed = kSpeed100MBit;
            speed = SPEED_100;
            speedName = speed100MName;
            
            if (currLinkState & FullDup) {
                mediumIndex = MEDIUM_INDEX_100FD;
                duplexName = duplexFullName;
            } else {
                mediumIndex = MEDIUM_INDEX_100HD;
                duplexName = duplexHalfName;
            }
        } else {
            mediumSpeed = kSpeed10MBit;
            speed = SPEED_10;
            speedName = speed10MName;
            
            if (currLinkState & FullDup) {
                mediumIndex = MEDIUM_INDEX_10FD;
                duplexName = duplexFullName;
            } else {
                mediumIndex = MEDIUM_INDEX_10HD;
                duplexName = duplexHalfName;
            }
        }
        if (currLinkState &	(TxFlowCtrl | RxFlowCtrl))
            flowName = onFlowName;
        else
            flowName = offFlowName;
        
        linkUp = true;
        setLinkStatus(kIONetworkLinkValid | kIONetworkLinkActive, mediumTable[mediumIndex], mediumSpeed, NULL);
        
        /* Restart txQueue, statistics updates and watchdog. */
        txQueue->start();
        
        if (stalled) {
            txQueue->service();
            stalled = false;
            DebugLog("Ethernet [RealtekRTL8111]: Restart stalled queue!\n");
        }
        timerSource->setTimeoutMS(kTimeoutMS);
        IOLog("Ethernet [RealtekRTL8111]: Link up on en%u, %s, %s, %s\n", unitNumber, speedName, duplexName, flowName);
	} else {
        /* Stop watchdog and statistics updates. */
        timerSource->cancelTimeout();
        deadlockWarn = 0;
        needsUpdate = false;
        
        /* Update link status. */
        linkUp = false;
        setLinkStatus(kIONetworkLinkValid);
        
        /* Stop txQueue and cleanup descriptor ring. */
        txQueue->stop();
        txQueue->flush();
        IOLockLock(txLock);
        txClearDescriptors(false);
        IOLockUnlock(txLock);
        IOLog("Ethernet [RealtekRTL8111]: Link down on en%u\n", unitNumber);
        
		if (tp->mcfg == CFG_METHOD_23) {
			WriteReg32(ERIDR, 0x00000001);
			WriteReg32(ERIAR, 0x8042f108);
		}
	}
}

void RTL8111::interruptOccurred(OSObject *client, IOInterruptEventSource *src, int count)
{
	UInt16 status;
    
	WriteReg16(IntrMask, 0x0000);
    status = ReadReg16(IntrStatus);
    
    /* hotplug/major error/no more work/shared irq */
    if ((status == 0xFFFF) || !status)
        goto done;
    
    /* Rx interrupt */
    if (status & (RxOK | RxDescUnavail | RxFIFOOver))
        rxInterrupt();
    
    /* Tx interrupt */
    if (status & (TxOK | TxErr))
        txInterrupt();
    
    if (status & LinkChg)
        checkLinkStatus();
    
    /* Check if a statistics dump has been completed. */
    if (needsUpdate && !(ReadReg32(CounterAddrLow) & CounterDump))
        updateStatitics();
    
done:
    WriteReg16(IntrStatus, 0xffff);
	WriteReg16(IntrMask, linuxData.intr_mask);
}

void RTL8111::timerAction(IOTimerEventSource *timer)
{
    UInt32 cmd;
    //DebugLog("timerAction() ===>\n");
    
    if (!linkUp) {
        DebugLog("Ethernet [RealtekRTL8111]: Timer fired while link down.\n");
        goto done;
    }
    /* Check for tx deadlock. */
    //DebugLog("Ethernet [RealtekRTL8111]: Check for Tx deadlock: txReqDoneCount=%llu, txNumFreeDesc=%u\n", txReqDoneCount, txNumFreeDesc);

    if ((txReqDoneCount == txReqDoneLast) && (txNumFreeDesc < kNumTxDesc)) {
        if (++deadlockWarn >= kTxDeadlockTreshhold) {
            IOLog("Ethernet [RealtekRTL8111]: Tx deadlock detected.\n");
            /* Stop and cleanup txQueue. Also set the link status to down. */
            txQueue->stop();
            txQueue->flush();
            linkUp = false;
            setLinkStatus(kIONetworkLinkValid);
            
            /* Lock the transmitter. */
            IOLockLock(txLock);
            
            /* Reset NIC and cleanup both descriptor rings. */
            rtl8168_nic_reset(&linuxData);
            txClearDescriptors(true);
            rxInterrupt();
            rxNextDescIndex = 0;
            deadlockWarn = 0;

            /* Reinitialize NIC and release txLock. */
            enableRTL8111();
            IOLockUnlock(txLock);
            /* timerSource and txQueue will be restarted when the link has been reestablished. */
            goto done;
        }
    } else {
        /* Some chips are unable to dump the tally counter while the receiver is disabled. */
        if (ReadReg8(ChipCmd) & CmdRxEnb) {
            WriteReg32(CounterAddrHigh, (statPhyAddr >> 32));
            cmd = (statPhyAddr & 0x00000000ffffffff);
            WriteReg32(CounterAddrLow, cmd);
            WriteReg32(CounterAddrLow, cmd | CounterDump);
            needsUpdate = true;
        }
        deadlockWarn = 0;
    }
    timerSource->setTimeoutMS(kTimeoutMS);

done:
    txReqDoneLast = txReqDoneCount;

    //DebugLog("timerAction() <===\n");
}

#pragma mark --- hardware initialization methods ---

bool RTL8111::initPCIConfigSpace(IOPCIDevice *provider)
{
    UInt16 pmCap;
    UInt16 cmdReg;
    UInt8 pmCapOffset;
    bool result = false;
    
    cmdReg	= provider->configRead16(kIOPCIConfigCommand);
    cmdReg  &= ~kIOPCICommandIOSpace;
    cmdReg	|= (kIOPCICommandBusMaster | kIOPCICommandMemorySpace | kIOPCICommandMemWrInvalidate);
	provider->configWrite16(kIOPCIConfigCommand, cmdReg);
    //provider->setBusMasterEnable(true);

    pciDeviceData.vendor = provider->configRead16(kIOPCIConfigVendorID);
    pciDeviceData.device = provider->configRead16(kIOPCIConfigDeviceID);
    pciDeviceData.subsystem_vendor = provider->configRead16(kIOPCIConfigSubSystemVendorID);
    pciDeviceData.subsystem_device = provider->configRead16(kIOPCIConfigSubSystemID);
        
    if (provider->findPCICapability(kIOPCIPowerManagementCapability, &pmCapOffset)) {
        pmCap = provider->configRead16(pmCapOffset + 2);
        IOLog("Ethernet [RealtekRTL8111]: PCI power management capabilities: 0x%x.\n", pmCap);
    } else {
        IOLog("Ethernet [RealtekRTL8111]: PCI power management unsupported.\n");
    }
    provider->enablePCIPowerManagement();
    
    baseMap = provider->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
    
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

bool RTL8111::initRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    UInt32 i;
    UInt16 mac_addr[4];
    bool result = false;
        
    /* Identify chip attached to board */
	rtl8168_get_mac_version(tp, baseAddr);
    rtl8168_print_mac_version(tp);
    
    /* Assume original RTL-8168 in case of unkown chipset. */
    tp->chipset = (tp->mcfg <= CFG_METHOD_24) ? tp->mcfg : CFG_METHOD_1;
    
    /* As of now the driver doesn't support RTL8168B/8111B. */
    if ((tp->chipset == CFG_METHOD_1) || (tp->chipset == CFG_METHOD_2) || (tp->chipset == CFG_METHOD_3)) {
        IOLog("[RTL8111] RTL8168B/8111B currently unsupported. Aborting!");
        goto done;
    }
	tp->set_speed = rtl8168_set_speed_xmii;
	tp->get_settings = rtl8168_gset_xmii;
	tp->phy_reset_enable = rtl8168_xmii_reset_enable;
	tp->phy_reset_pending = rtl8168_xmii_reset_pending;
	tp->link_ok = rtl8168_xmii_link_ok;
    
    if ((tp->mcfg == CFG_METHOD_9) || (tp->mcfg == CFG_METHOD_10))
		WriteReg8(DBG_reg, ReadReg8(DBG_reg) | BIT_1 | BIT_7);
    
	/* Get production from EEPROM */
	rtl_eeprom_type(tp);
	if (tp->eeprom_type != EEPROM_TYPE_NONE) {
		/* Get MAC address from EEPROM */
		if (tp->mcfg == CFG_METHOD_16 ||
		    tp->mcfg == CFG_METHOD_17 ||
		    tp->mcfg == CFG_METHOD_18 ||
		    tp->mcfg == CFG_METHOD_19 ||
		    tp->mcfg == CFG_METHOD_20 ||
			tp->mcfg == CFG_METHOD_21 ||
			tp->mcfg == CFG_METHOD_22 ||
			tp->mcfg == CFG_METHOD_24) {
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
	for (i = 0; i < MAC_ADDR_LEN; i++) {
		currMacAddr.bytes[i] = ReadReg8(MAC0 + i);
		origMacAddr.bytes[i] = currMacAddr.bytes[i]; /* keep the original MAC address */
	}
    IOLog("Ethernet [RealtekRTL8111]: %s: (Chipset %d) at 0x%lx, %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
          rtl_chip_info[tp->chipset].name, tp->chipset, (unsigned long)baseAddr,
          origMacAddr.bytes[0], origMacAddr.bytes[1],
          origMacAddr.bytes[2], origMacAddr.bytes[3],
          origMacAddr.bytes[4], origMacAddr.bytes[5]);
    
    tp->cp_cmd = ReadReg16(CPlusCmd);
    tp->max_jumbo_frame_size = rtl_chip_info[tp->chipset].jumbo_frame_sz;
    tp->intr_mask = LinkChg | RxDescUnavail | TxErr | TxOK | RxErr | RxOK;
    /*
     tp->intr_mask =  SYSErr | LinkChg | TxErr | TxOK | TxDescUnavail | RxDescUnavail | RxErr | RxOK | PCSTimeout;
     */
    /* Get the RxConfig parameters. */
    rxConfigReg = rtl_chip_info[tp->chipset].RCR_Cfg;
    rxConfigMask = rtl_chip_info[tp->chipset].RxConfigMask;
    
	if (tp->mcfg == CFG_METHOD_11 || tp->mcfg==CFG_METHOD_12 ||
	    tp->mcfg == CFG_METHOD_13 || tp->mcfg == CFG_METHOD_23)
		rtl8168_driver_start(tp);
    
	rtl8168_phy_power_up(tp);
	rtl8168_hw_phy_config(tp);
    pciDevice->configWrite8(kIOPCIConfigLatencyTimer, 0x40);
	rtl8168_set_speed(tp, autoneg, speed, duplex);
    rtl8168_init_sequence(tp);
    result = true;
    
done:
    return result;
}

void RTL8111::enableRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    
    rtl8168_powerup_pll(tp);
	startRTL8111();
	rtl8168_dsm(tp, DSM_IF_UP);
}

void RTL8111::disableRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    
    IOLockLock(txLock);
        
	rtl8168_dsm(tp, DSM_IF_DOWN);
    rtl8168_hw_reset(tp);
    rtl8168_sleep_rx_enable(tp);
	rtl8168_powerdown_pll(tp);
    
    IOLockUnlock(txLock);
}

void RTL8111::startRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    UInt8 device_control, options1, options2;
    UInt16 ephy_data;
    UInt32 csi_tmp;
    
    switch (tp->mcfg) {
        case CFG_METHOD_1:
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        case CFG_METHOD_6:
        case CFG_METHOD_7:
        case CFG_METHOD_8:
        case CFG_METHOD_9:
        case CFG_METHOD_10:
        case CFG_METHOD_11:
        case CFG_METHOD_12:
        case CFG_METHOD_13:
        case CFG_METHOD_14:
        case CFG_METHOD_15:
            break;
        default:
            WriteReg32(RxConfig, RxCfg_128_int_en | (RX_DMA_BURST << RxCfgDMAShift));
            break;
    }
    
    rtl8168_nic_reset(tp);
    
    //rtl8168_rx_desc_offset0_init(tp, 1);
    
    WriteReg8(Cfg9346, Cfg9346_Unlock);
    
    WriteReg8(MTPS, Reserved1_data);
    
    tp->cp_cmd |= PktCntrDisable | INTT_1 | PCIDAC;
    WriteReg16(CPlusCmd, tp->cp_cmd);
    
    WriteReg16(IntrMitigate, 0x5f51);
    WriteReg8(Config5, ReadReg8(Config5) & ~BIT_7);
    /*
     //Work around for RxFIFO overflow
     if (tp->mcfg == CFG_METHOD_1) {
     rtl8168_intr_mask |= RxFIFOOver | PCSTimeout;
     rtl8168_intr_mask &= ~RxDescUnavail;
     }
     */
    //rtl8168_desc_addr_fill(tp);
    fillDescriptorAddr(baseAddr, txPhyAddr, rxPhyAddr);
    
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
        
        /*Set EPHY registers	begin*/
        /*Set EPHY register offset 0x02 bit 11 to 0 and bit 12 to 1*/
        ephy_data = rtl8168_ephy_read(baseAddr, 0x02);
        ephy_data &= ~BIT_11;
        ephy_data |= BIT_12;
        rtl8168_ephy_write(baseAddr, 0x02, ephy_data);
        
        /*Set EPHY register offset 0x03 bit 1 to 1*/
        ephy_data = rtl8168_ephy_read(baseAddr, 0x03);
        ephy_data |= (1 << 1);
        rtl8168_ephy_write(baseAddr, 0x03, ephy_data);
        
        /*Set EPHY register offset 0x06 bit 7 to 0*/
        ephy_data = rtl8168_ephy_read(baseAddr, 0x06);
        ephy_data &= ~(1 << 7);
        rtl8168_ephy_write(baseAddr, 0x06, ephy_data);
        /*Set EPHY registers	end*/
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) | Jumbo_En1);
            
            setOffset79(0x20);
            
            //tx checksum offload disable
            //dev->features &= ~NETIF_F_IP_CSUM;
            
            //rx checksum offload disable
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
            
            setOffset79(0x50);
            
            //tx checksum offload enable
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
        //rx checksum offload enable
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        tp->cp_cmd |= RxChkSum;
        WriteReg16(CPlusCmd, tp->cp_cmd);
#else
        //dev->features |= NETIF_F_RXCSUM;
#endif
    } else if (tp->mcfg == CFG_METHOD_5) {
        
        set_offset70F(tp, 0x27);
        
        /******set EPHY registers for RTL8168CP	begin******/
        //Set EPHY register offset 0x01 bit 0 to 1.
        ephy_data = rtl8168_ephy_read(baseAddr, 0x01);
        ephy_data |= (1 << 0);
        rtl8168_ephy_write(baseAddr, 0x01, ephy_data);
        
        //Set EPHY register offset 0x03 bit 10 to 0, bit 9 to 1 and bit 5 to 1.
        ephy_data = rtl8168_ephy_read(baseAddr, 0x03);
        ephy_data &= ~(1 << 10);
        ephy_data |= (1 << 9);
        ephy_data |= (1 << 5);
        rtl8168_ephy_write(baseAddr, 0x03, ephy_data);
        /******set EPHY registers for RTL8168CP	end******/
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) | Jumbo_En1);
            
            setOffset79(0x20);
            
            //tx checksum offload disable
            //features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
            
            setOffset79(0x50);
            
            //tx checksum offload enable
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
        //rx checksum offload enable
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        tp->cp_cmd |= RxChkSum;
        WriteReg16(CPlusCmd, tp->cp_cmd);
#else
        //dev->features |= NETIF_F_RXCSUM;
#endif
    } else if (tp->mcfg == CFG_METHOD_6) {
        set_offset70F(tp, 0x27);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) | Jumbo_En1);
            
            setOffset79(0x20);
            
            //tx checksum offload disable
            //dev->features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
            
            setOffset79(0x50);
            
            //tx checksum offload enable
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
        //rx checksum offload enable
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        tp->cp_cmd |= RxChkSum;
        WriteReg16(CPlusCmd, tp->cp_cmd);
#else
        //dev->features |= NETIF_F_RXCSUM;
#endif
    } else if (tp->mcfg == CFG_METHOD_7) {
        set_offset70F(tp, 0x27);
        
        rtl8168_eri_write(baseAddr, 0x1EC, 1, 0x07, ERIAR_ASF);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) | Jumbo_En1);
            
            setOffset79(0x20);
            
            //tx checksum offload disable
            //dev->features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
            
            
            setOffset79(0x50);
            
            //tx checksum offload enable
            //dev->features |= NETIF_F_IP_CSUM;
        }
    } else if (tp->mcfg == CFG_METHOD_8) {
        
        set_offset70F(tp, 0x27);
        
        rtl8168_eri_write(baseAddr, 0x1EC, 1, 0x07, ERIAR_ASF);
        
        //disable clock request.
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg8(0xD1, 0x20);
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) | Jumbo_En1);
            
            setOffset79(0x20);
            
            //tx checksum offload disable
            //dev->features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
            
            
            setOffset79(0x50);
            
            //tx checksum offload enable
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
    } else if (tp->mcfg == CFG_METHOD_9) {
        set_offset70F(tp, 0x27);
        
        /* disable clock request. */
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~BIT_4);
        WriteReg8(DBG_reg, ReadReg8(DBG_reg) | BIT_7 | BIT_1);
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) | Jumbo_En1);
            
            setOffset79(0x20);
            
            /* tx checksum offload disable */
            //dev->features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
            
            
            setOffset79(0x50);
            
            /* tx checksum offload enable */
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
        /* set EPHY registers */
        rtl8168_ephy_write(baseAddr, 0x01, 0x7C7D);
        rtl8168_ephy_write(baseAddr, 0x02, 0x091F);
        rtl8168_ephy_write(baseAddr, 0x06, 0xB271);
        rtl8168_ephy_write(baseAddr, 0x07, 0xCE00);
    } else if (tp->mcfg == CFG_METHOD_10) {
        set_offset70F(tp, 0x27);
        
        WriteReg8(DBG_reg, ReadReg8(DBG_reg) | BIT_7 | BIT_1);
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) | Jumbo_En1);
            
            setOffset79(0x20);
            
            /* tx checksum offload disable */
            //dev->features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) & ~Jumbo_En1);
            
            
            
            setOffset79(0x50);
            
            /* tx checksum offload enable */
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
        WriteReg8(Config1, ReadReg8(Config1) | 0x10);
        
        /* set EPHY registers */
        rtl8168_ephy_write(baseAddr, 0x01, 0x6C7F);
        rtl8168_ephy_write(baseAddr, 0x02, 0x011F);
        rtl8168_ephy_write(baseAddr, 0x03, 0xC1B2);
        rtl8168_ephy_write(baseAddr, 0x1A, 0x0546);
        rtl8168_ephy_write(baseAddr, 0x1C, 0x80C4);
        rtl8168_ephy_write(baseAddr, 0x1D, 0x78E4);
        rtl8168_ephy_write(baseAddr, 0x0A, 0x8100);
        
        /* disable clock request. */
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
        WriteReg8(0xF3, ReadReg8(0xF3) | BIT_2);
        
    } else if (tp->mcfg == CFG_METHOD_11 || tp->mcfg == CFG_METHOD_13) {
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            
            /* tx checksum offload disable */
            //dev->features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            
            /* tx checksum offload enable */
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
        WriteReg8(Config1, ReadReg8(Config1) | 0x10);
        
    } else if (tp->mcfg == CFG_METHOD_12) {
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            
            /* tx checksum offload disable */
            //dev->features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            
            /* tx checksum offload enable */
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x0B);
        rtl8168_ephy_write(baseAddr, 0x0B, ephy_data|0x48);
        ephy_data = rtl8168_ephy_read(baseAddr, 0x19);
        ephy_data &= ~0x20;
        rtl8168_ephy_write(baseAddr, 0x19, ephy_data|0x50);
        ephy_data = rtl8168_ephy_read(baseAddr, 0x0C);
        ephy_data &= ~0x100;
        rtl8168_ephy_write(baseAddr, 0x0C, ephy_data|0x20);
        
        pciDevice->configWrite8(0x81, 0x01);
        //pci_write_config_byte(pdev, 0x81, 0x01);
        
        WriteReg8(Config1, ReadReg8(Config1) | 0x10);
        
    } else if (tp->mcfg == CFG_METHOD_14 || tp->mcfg == CFG_METHOD_15) {
        
        set_offset70F(tp, 0x27);
        setOffset79(0x50);
        
        /* set EPHY registers */
        ephy_data = rtl8168_ephy_read(baseAddr, 0x00) & ~0x0200;
        ephy_data |= 0x0100;
        rtl8168_ephy_write(baseAddr, 0x00, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x00);
        ephy_data |= 0x0004;
        rtl8168_ephy_write(baseAddr, 0x00, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x06) & ~0x0002;
        ephy_data |= 0x0001;
        rtl8168_ephy_write(baseAddr, 0x06, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x06);
        ephy_data |= 0x0030;
        rtl8168_ephy_write(baseAddr, 0x06, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x07);
        ephy_data |= 0x2000;
        rtl8168_ephy_write(baseAddr, 0x07, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x00);
        ephy_data |= 0x0020;
        rtl8168_ephy_write(baseAddr, 0x00, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x03) & ~0x5800;
        ephy_data |= 0x2000;
        rtl8168_ephy_write(baseAddr, 0x03, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x03);
        ephy_data |= 0x0001;
        rtl8168_ephy_write(baseAddr, 0x03, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x01) & ~0x0800;
        ephy_data |= 0x1000;
        rtl8168_ephy_write(baseAddr, 0x01, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x07);
        ephy_data |= 0x4000;
        rtl8168_ephy_write(baseAddr, 0x07, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x1E);
        ephy_data |= 0x2000;
        rtl8168_ephy_write(baseAddr, 0x1E, ephy_data);
        
        rtl8168_ephy_write(baseAddr, 0x19, 0xFE6C);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x0A);
        ephy_data |= 0x0040;
        rtl8168_ephy_write(baseAddr, 0x0A, ephy_data);
        
        tp->cp_cmd &= 0x2063;
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(MTPS, 0x24);
            WriteReg8(Config3, ReadReg8(Config3) | Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) | 0x01);
            
            /* tx checksum offload disable */
            //dev->features &= ~NETIF_F_IP_CSUM;
        } else {
            WriteReg8(MTPS, 0x0C);
            WriteReg8(Config3, ReadReg8(Config3) & ~Jumbo_En0);
            WriteReg8(Config4, ReadReg8(Config4) & ~0x01);
            
            /* tx checksum offload enable */
            //dev->features |= NETIF_F_IP_CSUM;
        }
        
        //rtl8168_set_rxbufsize(tp, dev);
        
        
        //		WriteReg8(0xF2, ReadReg8(0xF2) | BIT_0);
        //		WriteReg32(CounterAddrLow, ReadReg32(CounterAddrLow) | BIT_0);
        
        WriteReg8(0xF3, ReadReg8(0xF3) | BIT_5);
        WriteReg8(0xF3, ReadReg8(0xF3) & ~BIT_5);
        
        //		WriteReg8(0xD3, ReadReg8(0xD3) | BIT_3 | BIT_2);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_7 | BIT_6);
        
        WriteReg8(0xD1, ReadReg8(0xD1) | BIT_2 | BIT_3);
        
        WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_2 | BIT_1);
        
        WriteReg8(Config5, (ReadReg8(Config5)&~0x08) | BIT_0);
        WriteReg8(Config2, ReadReg8(Config2) | BIT_7);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
    } else if (tp->mcfg == CFG_METHOD_16 || tp->mcfg == CFG_METHOD_17) {
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD5, 1, ERIAR_ExGMAC) | BIT_3 | BIT_2;
        rtl8168_eri_write(baseAddr, 0xD5, 1, csi_tmp, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x00000000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 2, 0x00000000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xC8, 4, 0x00100002, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1D0, 4, ERIAR_ExGMAC);
        csi_tmp |= BIT_1;
        rtl8168_eri_write(baseAddr, 0x1D0, 1, csi_tmp, ERIAR_ExGMAC);
        
        WriteReg32(TxConfig, ReadReg32(TxConfig) | BIT_7);
        WriteReg8(0xD3, ReadReg8(0xD3) & ~BIT_7);
        WriteReg8(0x1B, ReadReg8(0x1B) & ~0x07);
        
        if (tp->mcfg == CFG_METHOD_16) {
            WriteReg32(0xB0, 0xEE480010);
            WriteReg8(0x1A, ReadReg8(0x1A) & ~(BIT_2|BIT_3));
            rtl8168_eri_write(baseAddr, 0x1DC, 1, 0x64, ERIAR_ExGMAC);
            
            rtl8168_ephy_write(baseAddr, 0x06, 0xF020);
            rtl8168_ephy_write(baseAddr, 0x07, 0x01FF);
            rtl8168_ephy_write(baseAddr, 0x00, 0x5027);
            rtl8168_ephy_write(baseAddr, 0x01, 0x0003);
            rtl8168_ephy_write(baseAddr, 0x02, 0x2D16);
            rtl8168_ephy_write(baseAddr, 0x03, 0x6D49);
            rtl8168_ephy_write(baseAddr, 0x08, 0x0006);
            rtl8168_ephy_write(baseAddr, 0x0A, 0x00C8);
        } else {
            csi_tmp = rtl8168_eri_read(baseAddr, 0x1B0, 4, ERIAR_ExGMAC);
            csi_tmp |= BIT_4;
            rtl8168_eri_write(baseAddr, 0x1B0, 1, csi_tmp, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0xCC, 4, 0x00000050, ERIAR_ExGMAC);
            rtl8168_eri_write(baseAddr, 0xd0, 4, 0x07ff0060, ERIAR_ExGMAC);
            //			WriteReg8(0xF2, (ReadReg8(0xF2) | BIT_2 | BIT_0) & ~BIT_1);	// early tally counter causes kernel panic
            WriteReg8(TDFNR, (ReadReg8(TDFNR) & ~0x3F) | 0x8);
        }
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x09);
        ephy_data |= BIT_7;
        rtl8168_ephy_write(baseAddr, 0x09, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x19);
        ephy_data |= (BIT_2 | BIT_5 | BIT_9);
        rtl8168_ephy_write(baseAddr, 0x19, ephy_data);
        
        if (tp->aspm) {
            WriteReg8(Config5, ReadReg8(Config5) | BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) | BIT_7);
        } else {
            WriteReg8(Config5, ReadReg8(Config5) & ~BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) & ~BIT_7);
        }
        
        WriteReg8(Config2, ReadReg8(Config2) & ~BIT_5);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        
        tp->cp_cmd &= 0x2063;
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(MTPS, 0x27);
            
            /* tx checksum offload disable */
        } else {
            WriteReg8(MTPS, 0x0C);
            
            /* tx checksum offload enable */
        }
        
        //rtl8168_set_rxbufsize(tp, dev);
        
        /* disable clock request. */
        pciDevice->configWrite8(0x81, 0x00);
        //pci_write_config_byte(pdev, 0x81, 0x00);
        
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
        
        if (tp->mcfg == CFG_METHOD_18) {
            ephy_data = rtl8168_ephy_read(baseAddr, 0x06);
            ephy_data |= BIT_5;
            ephy_data &= ~(BIT_7 | BIT_6);
            rtl8168_ephy_write(baseAddr, 0x06, ephy_data);
            
            ephy_data = rtl8168_ephy_read(baseAddr, 0x08);
            ephy_data |= BIT_1;
            ephy_data &= ~BIT_0;
            rtl8168_ephy_write(baseAddr, 0x08, ephy_data);
        }
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x09);
        ephy_data |= BIT_7;
        rtl8168_ephy_write(baseAddr, 0x09, ephy_data);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x19);
        ephy_data |= (BIT_2 | BIT_5 | BIT_9);
        rtl8168_ephy_write(baseAddr, 0x19, ephy_data);
        
        if (tp->aspm) {
            WriteReg8(Config5, ReadReg8(Config5) | BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) | BIT_7);
        } else {
            WriteReg8(Config5, ReadReg8(Config5) & ~BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) & ~BIT_7);
        }
        
        tp->cp_cmd &= 0x2063;
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(MTPS, 0x27);
            
            /* tx checksum offload disable */
        } else {
            WriteReg8(MTPS, 0x0C);
            
            /* tx checksum offload enable */
        }
        
        //rtl8168_set_rxbufsize(tp, dev);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        //		WriteReg8(0xF2, (ReadReg8(0xF2) | BIT_2 | BIT_0) & ~BIT_1);	// early tally counter causes kernel panic
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x00000000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 2, 0x00000000, ERIAR_ExGMAC);
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
        
        if (ReadReg8(0x8c) & BIT_28) {
            //unsigned long flags;
            u32 gphy_val;
            
            spin_lock_irqsave(&tp->phy_lock, flags);
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
            spin_unlock_irqrestore(&tp->phy_lock, flags);
        }
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
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x06);
        ephy_data |= BIT_5;
        ephy_data &= ~(BIT_7 | BIT_6);
        rtl8168_ephy_write(baseAddr, 0x06, ephy_data);
        
        rtl8168_ephy_write(baseAddr, 0x0f, 0x5200);
        
        ephy_data = rtl8168_ephy_read(baseAddr, 0x19);
        ephy_data |= (BIT_2 | BIT_5 | BIT_9);
        rtl8168_ephy_write(baseAddr, 0x19, ephy_data);
        
        if (tp->aspm) {
            WriteReg8(Config5, ReadReg8(Config5) | BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) | BIT_7);
        } else {
            WriteReg8(Config5, ReadReg8(Config5) & ~BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) & ~BIT_7);
        }
        
        tp->cp_cmd &= 0x2063;
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(MTPS, 0x27);
            
            /* tx checksum offload disable */
        } else {
            WriteReg8(MTPS, 0x0C);
            
            /* tx checksum offload enable */
        }
        
        //rtl8168_set_rxbufsize(tp, dev);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x00000000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 2, 0x00000000, ERIAR_ExGMAC);
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
    } else if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 || tp->mcfg == CFG_METHOD_24) {
        rtl8168_eri_write(baseAddr, 0xC8, 1, 0x02, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xCA, 1, 0x08, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xCC, 1, 0x38, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xD0, 1, 0x48, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xDC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        tp->cp_cmd = ReadReg16(CPlusCmd) &
        ~(EnableBist | Macdbgo_oe | Force_halfdup |
          Force_rxflow_en | Force_txflow_en |
          Cxpl_dbg_sel | ASF | PktCntrDisable |
          Macdbgo_sel);
        
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x00000000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 2, 0x00000000, ERIAR_ExGMAC);
        WriteReg8(0x1B, ReadReg8(0x1B) & ~0x07);
        
        if (tp->aspm) {
            WriteReg8(Config5, ReadReg8(Config5) | BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) | BIT_7);
        } else {
            WriteReg8(Config5, ReadReg8(Config5) & ~BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) & ~BIT_7);
        }
        
        WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x2FC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~(BIT_0 | BIT_1 | BIT_2);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0x2FC, 1, csi_tmp, ERIAR_ExGMAC);
        
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(MTPS, 0x27);
            
            /* tx checksum offload disable */
        } else {
            WriteReg8(MTPS, 0x0C);
            
            /* tx checksum offload enable */
        }
        
        //rtl8168_set_rxbufsize(tp, dev);
    } else if (tp->mcfg == CFG_METHOD_23) {
        rtl8168_eri_write(baseAddr, 0xC8, 1, 0x02, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xCA, 1, 0x08, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xCC, 1, 0x2f, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xD0, 1, 0x5f, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        set_offset70F(tp, 0x17);
        setOffset79(0x50);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xDC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0xDC, 1, csi_tmp, ERIAR_ExGMAC);
        
        rtl8168_ephy_write(baseAddr, 0x00, 0x10a3);
        rtl8168_ephy_write(baseAddr, 0x06, 0xf030);
        rtl8168_ephy_write(baseAddr, 0x08, 0x2006);
        rtl8168_ephy_write(baseAddr, 0x0d, 0x1666);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        tp->cp_cmd = ReadReg16(CPlusCmd) &
        ~(EnableBist | Macdbgo_oe | Force_halfdup |
          Force_rxflow_en | Force_txflow_en |
          Cxpl_dbg_sel | ASF | PktCntrDisable |
          Macdbgo_sel);
        
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x00000000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 2, 0x00000000, ERIAR_ExGMAC);
        WriteReg8(0x1B, ReadReg8(0x1B) & ~0x07);
        
        if (tp->aspm) {
            WriteReg8(Config5, ReadReg8(Config5) | BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) | BIT_7);
        } else {
            WriteReg8(Config5, ReadReg8(Config5) & ~BIT_0);
            WriteReg8(Config2, ReadReg8(Config2) & ~BIT_7);
        }
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x2FC, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_2;
        rtl8168_eri_write(baseAddr, 0x2FC, 1, csi_tmp, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1d0, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_1;
        rtl8168_eri_write(baseAddr, 0x1d0, 1, csi_tmp, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1B0, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_1 | BIT_0;
        rtl8168_eri_write(baseAddr, 0x1B0, 1, csi_tmp, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x3F2, 2, ERIAR_ExGMAC);
        csi_tmp &= ~(BIT_8 | BIT_11);
        csi_tmp |= (BIT_0 | BIT_1 | BIT_9 | BIT_10 | BIT_12 | BIT_13 | BIT_14);
        rtl8168_eri_write(baseAddr, 0x3F2, 2, csi_tmp, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0x3F5, 1, ERIAR_ExGMAC);
        csi_tmp |= BIT_6 | BIT_7;
        rtl8168_eri_write(baseAddr, 0x3F5, 1, csi_tmp, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0x2E8, 2, 0x883C, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0x2EA, 2, 0x8C12, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0x2EC, 2, 0x9003, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xd4, 2, ERIAR_ExGMAC);
        csi_tmp |= 0x1f80;
        rtl8168_eri_write(baseAddr, 0xd4, 2, csi_tmp, ERIAR_ExGMAC);
        
        if (mtu > ETH_DATA_LEN) {
            WriteReg8(MTPS, 0x27);
            
            /* tx checksum offload disable */
        } else {
            WriteReg8(MTPS, 0x0C);
            
            /* tx checksum offload enable */
        }
        
        //rtl8168_set_rxbufsize(tp, dev);
    } else if (tp->mcfg == CFG_METHOD_1) {
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        if (mtu > ETH_DATA_LEN) {
            device_control = pciDevice->configRead8(0x69);
            device_control &= ~0x70;
            device_control |= 0x28;
            pciDevice->configWrite8(0x69, device_control);
        } else {
            device_control = pciDevice->configRead8(0x69);
            device_control &= ~0x70;
            device_control |= 0x58;
            pciDevice->configWrite8(0x69, device_control);
        }
    } else if (tp->mcfg == CFG_METHOD_2) {
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            device_control = pciDevice->configRead8(0x69);
            device_control &= ~0x70;
            device_control |= 0x28;
            pciDevice->configWrite8(0x69, device_control);
            
            WriteReg8(Config4, ReadReg8(Config4) | (1 << 0));
        } else {
            device_control = pciDevice->configRead8(0x69);
            device_control &= ~0x70;
            device_control |= 0x58;
            pciDevice->configWrite8(0x69, device_control);
            
            WriteReg8(Config4, ReadReg8(Config4) & ~(1 << 0));
        }
    } else if (tp->mcfg == CFG_METHOD_3) {
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg16(CPlusCmd, ReadReg16(CPlusCmd) &
                ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en |
                  Cxpl_dbg_sel | ASF | PktCntrDisable | Macdbgo_sel));
        
        WriteReg8(MTPS, Reserved1_data);
        if (mtu > ETH_DATA_LEN) {
            device_control = pciDevice->configRead8(0x69);
            device_control &= ~0x70;
            device_control |= 0x28;
            pciDevice->configWrite8(0x69, device_control);
            
            WriteReg8(Config4, ReadReg8(Config4) | (1 << 0));
        } else {
            device_control = pciDevice->configRead8(0x69);
            device_control &= ~0x70;
            device_control |= 0x58;
            pciDevice->configWrite8(0x69, device_control);
            
            WriteReg8(Config4, ReadReg8(Config4) & ~(1 << 0));
        }
    } else if (tp->mcfg == CFG_METHOD_DEFAULT) {
        tp->cp_cmd &= 0x2043;
        WriteReg8(MTPS, 0x0C);
        
        //dev->features &= ~NETIF_F_IP_CSUM;
        //rtl8168_set_rxbufsize(tp, dev);
    }
    
    if ((tp->mcfg == CFG_METHOD_1) || (tp->mcfg == CFG_METHOD_2) || (tp->mcfg == CFG_METHOD_3)) {
        /* csum offload command for RTL8168B/8111B */
        tp->tx_tcp_csum_cmd = TxIPCS | TxTCPCS;
        tp->tx_udp_csum_cmd = TxIPCS | TxUDPCS;
        tp->tx_ip_csum_cmd = TxIPCS;
    } else {
        /* csum offload command for RTL8168C/8111C and RTL8168CP/8111CP */
        tp->tx_tcp_csum_cmd = TxIPCS_C | TxTCPCS_C;
        tp->tx_udp_csum_cmd = TxIPCS_C | TxUDPCS_C;
        tp->tx_ip_csum_cmd = TxIPCS_C;
    }
    
    tp->cp_cmd |= (RxChkSum|RxVlan|PCIDAC);
	WriteReg16(CPlusCmd, tp->cp_cmd);
	ReadReg16(CPlusCmd);
    
    WriteReg8(ChipCmd, CmdTxEnb | CmdRxEnb);
    
    if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
        tp->mcfg == CFG_METHOD_23 || tp->mcfg == CFG_METHOD_24)
        WriteReg8(0xF2, ReadReg8(0xF2) & ~BIT_3);
    /*
     if (tp->mcfg == CFG_METHOD_11 || tp->mcfg == CFG_METHOD_12)
     rtl8168_mac_loopback_test(tp);
     */
    /* Set Rx Config register */
    //rtl8168_set_rx_mode();
    setMulticastMode(multicastMode);
    
    /* Enable all known interrupts by setting the interrupt mask. */
    WriteReg16(IntrMask, tp->intr_mask);
    
    WriteReg8(Cfg9346, Cfg9346_Lock);
    
    rtl8168_dsm(tp, DSM_MAC_INIT);
    
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
        case CFG_METHOD_23:
        case CFG_METHOD_24:
            if ((options1 & LinkUp) || (csi_tmp & BIT_0) || (options2 & UWF) || (options2 & BWF) || (options2 & MWF))
                tp->wol_enabled = WOL_ENABLED;
            else
                tp->wol_enabled = WOL_DISABLED;
            break;
        case CFG_METHOD_DEFAULT:
            tp->wol_enabled = WOL_DISABLED;
            break;
        default:
            if ((options1 & LinkUp) || (options1 & MagicPacket) || (options2 & UWF) || (options2 & BWF) || (options2 & MWF))
                tp->wol_enabled = WOL_ENABLED;
            else
                tp->wol_enabled = WOL_DISABLED;
            break;
    }
    /* Disable wake on LAN because the driver still lacks full support. */
    tp->wol_enabled = WOL_DISABLED;
    udelay(10);
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

#pragma mark --- miscellaneous functions ---

static inline void fillDescriptorAddr(volatile void *baseAddr, IOPhysicalAddress64 txPhyAddr, IOPhysicalAddress64 rxPhyAddr)
{
    WriteReg32(TxDescStartAddrLow, (txPhyAddr & 0x00000000ffffffff));
    WriteReg32(TxDescStartAddrHigh, (txPhyAddr >> 32));
    WriteReg32(RxDescAddrLow, (rxPhyAddr & 0x00000000ffffffff));
    WriteReg32(RxDescAddrHigh, (rxPhyAddr >> 32));
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

