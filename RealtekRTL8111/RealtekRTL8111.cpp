/* RealtekRTL8111.cpp -- RTL8111 driver class implementation.
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


#include "RealtekRTL8111.hpp"

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
        rxBufArrayMem = NULL;
        txBufArrayMem = NULL;
        statBufDesc = NULL;
        txPhyAddr = (IOPhysicalAddress64)NULL;
        rxPhyAddr = (IOPhysicalAddress64)NULL;
        statPhyAddr = (IOPhysicalAddress64)NULL;
        statData = NULL;
        rxPacketHead = NULL;
        rxPacketTail = NULL;
        rxPacketSize = 0;
        isEnabled = false;
        promiscusMode = false;
        multicastMode = false;
        linkUp = false;
        
        rxPoll = false;
        polling = false;
        
        mtu = ETH_DATA_LEN;
        powerState = 0;
        speed = SPEED_1000;
        duplex = DUPLEX_FULL;
        autoneg = AUTONEG_ENABLE;
        flowCtl = kFlowControlOff;
        linuxData.eee_adv_t = 0;
        eeeCap = 0;
        linuxData.aspm = 0;
        linuxData.s0_magic_packet = 0;
        linuxData.hwoptimize = 0;
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
        enableTSO6 = false;
        enableCSO6 = false;
        disableASPM = false;
        pciPMCtrlOffset = 0;
        memset(fallBackMacAddr.bytes, 0, kIOEthernetAddressSize);
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
    freeTxResources();
    freeRxResources();
    freeStatResources();

    DebugLog("free() <===\n");
    
    super::free();
}

bool RTL8111::start(IOService *provider)
{
    bool result;
    
    result = super::start(provider);
    
    if (!result) {
        IOLog("IOEthernetController::start failed.\n");
        goto done;
    }
    multicastMode = false;
    promiscusMode = false;
    multicastFilter = 0;

    pciDevice = OSDynamicCast(IOPCIDevice, provider);
    
    if (!pciDevice) {
        IOLog("No provider.\n");
        goto done;
    }
    pciDevice->retain();
    
    if (!pciDevice->open(this)) {
        IOLog("Failed to open provider.\n");
        goto error_open;
    }
    mapper = IOMapper::copyMapperForDevice(pciDevice);

    getParams();
    
    if (!initPCIConfigSpace(pciDevice)) {
        goto error_cfg;
    }

    if (!initRTL8111()) {
        goto error_cfg;
    }
    
    if (!setupMediumDict()) {
        IOLog("Failed to setup medium dictionary.\n");
        goto error_cfg;
    }
    commandGate = getCommandGate();
    
    if (!commandGate) {
        IOLog("getCommandGate() failed.\n");
        goto error_gate;
    }
    commandGate->retain();
    
    if (!setupTxResources()) {
        IOLog("Error allocating Tx resources.\n");
        goto error_dma1;
    }

    if (!setupRxResources()) {
        IOLog("Error allocating Rx resources.\n");
        goto error_dma2;
    }

    if (!setupStatResources()) {
        IOLog("Error allocating Stat resources.\n");
        goto error_dma3;
    }

    if (!initEventSources(provider)) {
        IOLog("initEventSources() failed.\n");
        goto error_src;
    }

    result = attachInterface(reinterpret_cast<IONetworkInterface**>(&netif));

    if (!result) {
        IOLog("attachInterface() failed.\n");
        goto error_src;
    }
    pciDevice->close(this);
    result = true;
    
done:
    return result;

error_src:
    freeStatResources();

error_dma3:
    freeRxResources();

error_dma2:
    freeTxResources();
    
error_dma1:
    RELEASE(commandGate);

error_gate:
    RELEASE(mediumDict);
    
error_cfg:
    pciDevice->close(this);
    
error_open:
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

    freeStatResources();
    freeRxResources();
    freeTxResources();

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
        DebugLog("Already in power state %lu.\n", powerStateOrdinal);
        goto done;
    }
    DebugLog("switching to power state %lu.\n", powerStateOrdinal);
    
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
        DebugLog("Interface already enabled.\n");
        result = kIOReturnSuccess;
        goto done;
    }
    if (!pciDevice || pciDevice->isOpen()) {
        IOLog("Unable to open PCI device.\n");
        goto done;
    }
    pciDevice->open(this);
    
    selectedMedium = getSelectedMedium();
    
    if (!selectedMedium) {
        DebugLog("No medium selected. Falling back to autonegotiation.\n");
        selectedMedium = mediumTable[MEDIUM_INDEX_AUTO];
    }
    selectMedium(selectedMedium);
    enableRTL8111();
    
    /* We have to enable the interrupt because we are using a msi interrupt. */
    interruptSource->enable();

    rxPacketHead = rxPacketTail = NULL;
    rxPacketSize = 0;
    txDescDoneCount = txDescDoneLast = 0;
    deadlockWarn = 0;
    needsUpdate = false;
    isEnabled = true;
    polling = false;

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
    
    netif->stopOutputThread();
    netif->flushOutputQueue();
    
    polling = false;
    isEnabled = false;

    timerSource->cancelTimeout();
    needsUpdate = false;
    txDescDoneCount = txDescDoneLast = 0;

    /* Disable interrupt as we are using msi. */
    interruptSource->disable();

    disableRTL8111();
    
    clearDescriptors();
    
    if (pciDevice && pciDevice->isOpen())
        pciDevice->close(this);
        
    DebugLog("disable() <===\n");
    
done:
    return result;
}

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
        DebugLog("Interface down. Dropping packets.\n");
        goto done;
    }
    while ((txNumFreeDesc > (kMaxSegs + 3)) && (interface->dequeueOutputPackets(1, &m, NULL, NULL, NULL) == kIOReturnSuccess)) {
        cmd = 0;
        opts2 = 0;

        if (mbuf_get_tso_requested(m, &tsoFlags, &mssValue)) {
            DebugLog("mbuf_get_tso_requested() failed. Dropping packet.\n");
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
            DebugLog("getPhysicalSegmentsWithCoalesce() failed. Dropping packet.\n");
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

void RTL8111::getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const
{
    DebugLog("getPacketBufferConstraints() ===>\n");

	constraints->alignStart = kIOPacketBufferAlign1;
	constraints->alignLength = kIOPacketBufferAlign1;
    
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
    IOReturn error;
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
            IOLog("Error getting IONetworkStats\n.");
            result = false;
            goto done;
        }
    }
    /* Get the Ethernet statistics structure. */    
    data = interface->getParameter(kIOEthernetStatsKey);
    
    if (data) {
        etherStats = (IOEthernetStats *)data->getBuffer();
        
        if (!etherStats) {
            IOLog("Error getting IOEthernetStats\n.");
            result = false;
            goto done;
        }
    }
    error = interface->configureOutputPullModel(512, 0, 0, IONetworkInterface::kOutputPacketSchedulingModelNormal);
    
    if (error != kIOReturnSuccess) {
        IOLog("configureOutputPullModel() failed\n.");
        result = false;
        goto done;
    }
    if (rxPoll) {
        error = interface->configureInputPacketPolling(kNumRxDesc, kIONetworkWorkLoopSynchronous);
        
        if (error != kIOReturnSuccess) {
            IOLog("configureInputPacketPolling() failed\n.");
            result = false;
            goto done;
        }
    }
    snprintf(modelName, kNameLenght, "Realtek %s PCIe Gigabit Ethernet", rtl_chip_info[linuxData.chipset].name);
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
        DebugLog("Promiscuous mode enabled.\n");
        rxMode = (AcceptBroadcast | AcceptMulticast | AcceptMyPhys | AcceptAllPhys);
        mcFilter[1] = mcFilter[0] = 0xffffffff;
    } else {
        DebugLog("Promiscuous mode disabled.\n");
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
        
        DebugLog("WakeOnMagicPacket %s.\n", active ? "enabled" : "disabled");

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
        DebugLog("kIOEthernetWakeOnMagicPacket added to filters.\n");
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
        linuxData.eee_adv_t = 0;
        
        switch (medium->getIndex()) {
            case MEDIUM_INDEX_AUTO:
                autoneg = AUTONEG_ENABLE;
                speed = 0;
                duplex = DUPLEX_FULL;
                flowCtl = kFlowControlOn;
                linuxData.eee_adv_t = eeeCap;
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
                linuxData.eee_adv_t = eeeCap;
                break;
                
            case MEDIUM_INDEX_100FDFCEEE:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_100;
                duplex = DUPLEX_FULL;
                flowCtl = kFlowControlOn;
                linuxData.eee_adv_t = eeeCap;
                break;
                
            case MEDIUM_INDEX_1000FDEEE:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                linuxData.eee_adv_t = eeeCap;
                break;
                
            case MEDIUM_INDEX_1000FDFCEEE:
                autoneg = AUTONEG_ENABLE;
                speed = SPEED_1000;
                duplex = DUPLEX_FULL;
                flowCtl = kFlowControlOn;
                linuxData.eee_adv_t = eeeCap;
                break;
        }
        setPhyMedium();
        setCurrentMedium(medium);
    }
    
    DebugLog("selectMedium() <===\n");
    
done:
    return result;
}

IOReturn RTL8111::getMaxPacketSize(UInt32 * maxSize) const
{
    IOReturn result = kIOReturnSuccess;

    DebugLog("getMaxPacketSize() ===>\n");
    
    if (linuxData.mcfg >= kJumboFrameSupport)
        *maxSize = kMaxPacketSize;
    else
        result = super::getMaxPacketSize(maxSize);
    
    DebugLog("getMaxPacketSize() <===\n");
    
    return result;
}

IOReturn RTL8111::setMaxPacketSize(UInt32 maxSize)
{
    IOReturn result = kIOReturnError;
    ifnet_t ifnet = netif->getIfnet();
    ifnet_offload_t offload;
    UInt32 mask = 0;
    
    DebugLog("setMaxPacketSize() ===>\n");
    
    if (linuxData.mcfg >= kJumboFrameSupport) {
        if (maxSize <= linuxData.max_jumbo_frame_size) {
            mtu = maxSize - (ETH_HLEN + ETH_FCS_LEN);
            
            DebugLog("maxSize: %u, mtu: %u\n", maxSize, mtu);
            
            if (enableTSO4)
                mask |= IFNET_TSO_IPV4;
            
            if (enableTSO6)
                mask |= IFNET_TSO_IPV6;

            offload = ifnet_offload(ifnet);
            
            if (mtu > MSS_MAX) {
                offload &= ~mask;
                DebugLog("Disable hardware offload features: %x!\n", mask);
            } else {
                offload |= mask;
                DebugLog("Enable hardware offload features: %x!\n", mask);
            }
            if (ifnet_set_offload(ifnet, offload))
                IOLog("Error setting hardware offload: %x!\n", offload);
            
            /* Force reinitialization. */
            setLinkDown();
            timerSource->cancelTimeout();
            //updateStatistics(&adapterData);
            restartRTL8111();
            
            result = kIOReturnSuccess;
        }
    } else {
        result = super::setMaxPacketSize(maxSize);
    }
    DebugLog("setMaxPacketSize() <===\n");
    
    return result;
}

#pragma mark --- common interrupt methods ---

void RTL8111::pciErrorInterrupt()
{
    UInt16 cmdReg = pciDevice->configRead16(kIOPCIConfigCommand);
    UInt16 statusReg = pciDevice->configRead16(kIOPCIConfigStatus);
    
    DebugLog("PCIe error: cmdReg=0x%x, statusReg=0x%x\n", cmdReg, statusReg);

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
    if (oldDirtyIndex != txDirtyDescIndex) {
        if (txNumFreeDesc > kTxQueueWakeTreshhold)
            netif->signalOutputThread();
        
        WriteReg8(TxPoll, NPQ);
        releaseFreePackets();
    }
    if (!polling)
        etherStats->dot3TxExtraEntry.interrupts++;
}

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
    bool replaced;
    
    while (!((descStatus1 = OSSwapLittleToHostInt32(desc->opts1)) & DescOwn) && (goodPkts < maxCount)) {
        opts1 = (rxNextDescIndex == kRxLastDesc) ? (RingEnd | DescOwn) : DescOwn;
        opts2 = 0;
        addr = 0;

        descStatus2 = OSSwapLittleToHostInt32(desc->opts2);
        pktSize = (descStatus1 & 0x1fff) - kIOEthernetCRCSize;
        bufPkt = rxMbufArray[rxNextDescIndex];
        //DebugLog("rxInterrupt(): descStatus1=0x%x, descStatus2=0x%x, pktSize=%u\n", descStatus1, descStatus2, pktSize);
        
        newPkt = replaceOrCopyPacket(&bufPkt, pktSize, &replaced);
        
        if (!newPkt) {
            /* Allocation of a new packet failed so that we must leave the original packet in place. */
            DebugLog("replaceOrCopyPacket() failed.\n");
            etherStats->dot3RxExtraEntry.resourceErrors++;
            opts1 |= kRxBufferPktSize;
            goto nextDesc;
        }
        
        /* If the packet was replaced we have to update the descriptor's buffer address. */
        if (replaced) {
            if (rxMbufCursor->getPhysicalSegments(bufPkt, &rxSegment, 1) != 1) {
                DebugLog("getPhysicalSegments() failed.\n");
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

/*
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
        
        // As we don't support jumbo frames we consider fragmented packets as errors.
        if ((descStatus1 & (FirstFrag|LastFrag)) != (FirstFrag|LastFrag)) {
            DebugLog("Fragmented packet.\n");
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
            // Allocation of a new packet failed so that we must leave the original packet in place.
            DebugLog("replaceOrCopyPacket() failed.\n");
            etherStats->dot3RxExtraEntry.resourceErrors++;
            opts1 |= kRxBufferPktSize;
            goto nextDesc;
        }
        
        // If the packet was replaced we have to update the descriptor's buffer address.
        if (replaced) {
            if (rxMbufCursor->getPhysicalSegments(bufPkt, &rxSegment, 1) != 1) {
                DebugLog("getPhysicalSegments() failed.\n");
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
        
        // Also get the VLAN tag if there is any.
        if (vlanTag)
            setVlanTag(newPkt, vlanTag);
        
        netif->inputPacket(newPkt, pktSize, IONetworkInterface::kInputOptionQueuePacket);
        goodPkts++;
        
        // Finally update the descriptor and get the next one to examine.
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
*/

void RTL8111::checkLinkStatus()
{
    struct rtl8168_private *tp = &linuxData;
    UInt16 newIntrMitigate = 0x5f51;
	UInt8 currLinkState;
    
    if (tp->mcfg == CFG_METHOD_11)
		rtl8168dp_10mbps_gphy_para(tp);
    
    currLinkState = ReadReg8(PHYstatus);
    
	if (currLinkState & LinkStatus) {
        /* Get EEE mode. */
        eeeMode = getEEEMode();
        
        /* Get link speed, duplex and flow-control mode. */
        if (currLinkState & (TxFlowCtrl | RxFlowCtrl)) {
            flowCtl = kFlowControlOn;
        } else {
            flowCtl = kFlowControlOff;
        }
        if (currLinkState & _1000bpsF) {
            speed = SPEED_1000;
            duplex = DUPLEX_FULL;

            newIntrMitigate = intrMitigateValue;
        } else if (currLinkState & _100bps) {
            speed = SPEED_100;
            
            if (currLinkState & FullDup) {
                duplex = DUPLEX_FULL;
            } else {
                duplex = DUPLEX_HALF;
            }
        } else {
            speed = SPEED_10;
            
            if (currLinkState & FullDup) {
                duplex = DUPLEX_FULL;
            } else {
                duplex = DUPLEX_HALF;
            }
        }
        setupRTL8111(newIntrMitigate, true);
        
        if (tp->mcfg == CFG_METHOD_18 || tp->mcfg == CFG_METHOD_19 || tp->mcfg == CFG_METHOD_20) {
            if (currLinkState & _1000bpsF) {
                rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x00000011, ERIAR_ExGMAC);
                rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x0000001f, ERIAR_ExGMAC);
            } else if (currLinkState & _100bps) {
                rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x0000001f, ERIAR_ExGMAC);
                rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x0000001f, ERIAR_ExGMAC);
            } else {
                rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x0000001f, ERIAR_ExGMAC);
                rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x0000002d, ERIAR_ExGMAC);
            }
        } else if ((tp->mcfg == CFG_METHOD_16 || tp->mcfg == CFG_METHOD_17) && isEnabled) {
            if (tp->mcfg == CFG_METHOD_16 && (currLinkState & _10bps)) {
                WriteReg32(RxConfig, ReadReg32(RxConfig) | AcceptAllPhys);
            } else if (tp->mcfg == CFG_METHOD_17) {
                if (ReadReg8(PHYstatus) & _1000bpsF) {
                    rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x00000011, ERIAR_ExGMAC);
                    rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x00000005, ERIAR_ExGMAC);
                } else if (ReadReg8(PHYstatus) & _100bps) {
                    rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x0000001f, ERIAR_ExGMAC);
                    rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x00000005, ERIAR_ExGMAC);
                } else {
                    rtl8168_eri_write(baseAddr, 0x1bc, 4, 0x0000001f, ERIAR_ExGMAC);
                    rtl8168_eri_write(baseAddr, 0x1dc, 4, 0x0000003f, ERIAR_ExGMAC);
                }
            }
        } else if ((tp->mcfg == CFG_METHOD_14 || tp->mcfg == CFG_METHOD_15) && tp->eee_enabled ==1) {
            /*Full -Duplex  mode*/
            if (currLinkState & FullDup) {
                rtl8168_mdio_write(tp, 0x1F, 0x0006);
                rtl8168_mdio_write(tp, 0x00, 0x5a30);
                rtl8168_mdio_write(tp, 0x1F, 0x0000);
                if (ReadReg8(PHYstatus) & (_10bps | _100bps))
                    WriteReg32(TxConfig, (ReadReg32(TxConfig) & ~BIT_19) | BIT_25);
                
            } else {
                rtl8168_mdio_write(tp, 0x1F, 0x0006);
                rtl8168_mdio_write(tp, 0x00, 0x5a00);
                rtl8168_mdio_write(tp, 0x1F, 0x0000);
                if (currLinkState & (_10bps | _100bps))
                    WriteReg32(TxConfig, (ReadReg32(TxConfig) & ~BIT_19) | (InterFrameGap << TxInterFrameGapShift));
            }
        } else if ((tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
                    tp->mcfg == CFG_METHOD_23 || tp->mcfg == CFG_METHOD_24 ||
                    tp->mcfg == CFG_METHOD_25 || tp->mcfg == CFG_METHOD_26 ||
                    tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28 ||
                    tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30 ||
                    tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) &&
                   isEnabled) {
            if (currLinkState & FullDup)
                WriteReg32(TxConfig, (ReadReg32(TxConfig) | (BIT_24 | BIT_25)) & ~BIT_19);
            else
                WriteReg32(TxConfig, (ReadReg32(TxConfig) | BIT_25) & ~(BIT_19 | BIT_24));
        }
        
        if (tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
            tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28 ||
            tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) {
            /*half mode*/
            if (!(currLinkState & FullDup)) {
                rtl8168_mdio_write(tp, 0x1F, 0x0000);
                rtl8168_mdio_write(tp, MII_ADVERTISE, rtl8168_mdio_read(tp, MII_ADVERTISE)&~(ADVERTISE_PAUSE_CAP|ADVERTISE_PAUSE_ASYM));
            }
        }
        
        if ((tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) && (currLinkState & _10bps)) {
            u32 csi_tmp;
            
            csi_tmp = rtl8168_eri_read(baseAddr, 0x1D0, 1, ERIAR_ExGMAC);
            csi_tmp |= BIT_1;
            rtl8168_eri_write(baseAddr, 0x1D0, 1, csi_tmp, ERIAR_ExGMAC);
        }
        setLinkUp();
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

void RTL8111::interruptOccurredPoll(OSObject *client, IOInterruptEventSource *src, int count)
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
            packets = rxInterrupt(netif, kNumRxDesc, NULL, NULL);
            
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

void RTL8111::interruptOccurred(OSObject *client, IOInterruptEventSource *src, int count)
{
    UInt64 time, abstime;
    UInt32 packets;

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
    /* Rx interrupt */
    if (status & rxMask) {
        packets = rxInterrupt(netif, kNumRxDesc, NULL, NULL);
        
        if (packets)
            netif->flushInputQueue();
    }
    /* Tx interrupt */
    if (status & (TxOK | TxErr | TxDescUnavail))
        txInterrupt();

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
            DebugLog("Tx timeout. Lost interrupt?\n");
            etherStats->dot3TxExtraEntry.timeouts++;
            txInterrupt();
        } else if (deadlockWarn >= kTxDeadlockTreshhold) {
#ifdef DEBUG
            UInt32 i, index;
            
            for (i = 0; i < 10; i++) {
                index = ((txDirtyDescIndex - 1 + i) & kTxDescMask);
                IOLog("desc[%u]: opts1=0x%x, opts2=0x%x, addr=0x%llx.\n", index, txDescArray[index].opts1, txDescArray[index].opts2, txDescArray[index].addr);
            }
#endif
            IOLog("Tx stalled? Resetting chipset. ISR=0x%x, IMR=0x%x.\n", ReadReg16(IntrStatus), ReadReg16(IntrMask));
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

#pragma mark --- hardware specific methods ---

void RTL8111::getTso4Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags)
{
    if (revisionC) {
        *cmd1 = (GiantSendv4 | (kMinL4HdrOffsetV4 << GSendL4OffShift));
        *cmd2 = ((mssValue & MSSMask) << MSSShift_C);
    } else {
        *cmd1 = (LargeSend |((mssValue & MSSMask) << MSSShift));
    }
}

void RTL8111::getTso6Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags)
{
    *cmd1 = (GiantSendv6 | (kMinL4HdrOffsetV6 << GSendL4OffShift));
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
            *cmd2 = (TxTCPCS_C | TxIPV6F_C | ((kMinL4HdrOffsetV6 & L4OffMask) << MSSShift_C));
        else if (checksums & kChecksumUDPIPv6)
            *cmd2 = (TxUDPCS_C | TxIPV6F_C | ((kMinL4HdrOffsetV6 & L4OffMask) << MSSShift_C));
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
        IOLog("checksums applied: 0x%x, checksums valid: 0x%x\n", resultMask, validMask);

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

void RTL8111::setLinkUp()
{
    UInt64 mediumSpeed;
    UInt32 mediumIndex = MEDIUM_INDEX_AUTO;
    const char *speedName;
    const char *duplexName;
    const char *flowName;
    const char *eeeName;
    
    eeeName = eeeNames[kEEETypeNo];

    /* Get link speed, duplex and flow-control mode. */
    if (flowCtl == kFlowControlOn) {
        flowName = onFlowName;
    } else {
        flowName = offFlowName;
    }
    if (speed == SPEED_1000) {
        mediumSpeed = kSpeed1000MBit;
        speedName = speed1GName;
        duplexName = duplexFullName;
       
        if (flowCtl == kFlowControlOn) {
            if (eeeMode & kEEEMode1000) {
                mediumIndex = MEDIUM_INDEX_1000FDFCEEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MEDIUM_INDEX_1000FDFC;
            }
        } else {
            if (eeeMode & kEEEMode1000) {
                mediumIndex = MEDIUM_INDEX_1000FDEEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MEDIUM_INDEX_1000FD;
            }
        }
    } else if (speed == SPEED_100) {
        mediumSpeed = kSpeed100MBit;
        speedName = speed100MName;
        
        if (duplex == DUPLEX_FULL) {
            duplexName = duplexFullName;
            
            if (flowCtl == kFlowControlOn) {
                if (eeeMode & kEEEMode100) {
                    mediumIndex =  MEDIUM_INDEX_100FDFCEEE;
                    eeeName = eeeNames[kEEETypeYes];
                } else {
                    mediumIndex = MEDIUM_INDEX_100FDFC;
                }
            } else {
                if (eeeMode & kEEEMode100) {
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
        speedName = speed10MName;
        
        if (duplex == DUPLEX_FULL) {
            mediumIndex = MEDIUM_INDEX_10FD;
            duplexName = duplexFullName;
        } else {
            mediumIndex = MEDIUM_INDEX_10HD;
            duplexName = duplexHalfName;
        }
    }
    /* Enable receiver and transmitter. */
    WriteReg8(ChipCmd, CmdTxEnb | CmdRxEnb);

    linkUp = true;
    setLinkStatus(kIONetworkLinkValid | kIONetworkLinkActive, mediumTable[mediumIndex], mediumSpeed, NULL);

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
        DebugLog("pollIntervalTime: %lluus\n", (pollParams.pollIntervalTime / 1000));
    }
    netif->startOutputThread();

    IOLog("Link up on en%u, %s, %s, %s%s\n", netif->getUnitNumber(), speedName, duplexName, flowName, eeeName);
}

void RTL8111::setLinkDown()
{
    struct rtl8168_private *tp = &linuxData;

    deadlockWarn = 0;
    needsUpdate = false;

    /* Stop output thread and flush output queue. */
    netif->stopOutputThread();
    netif->flushOutputQueue();

    /* Update link status. */
    linkUp = false;
    setLinkStatus(kIONetworkLinkValid);

    rtl8168_nic_reset(&linuxData);

    /* Cleanup descriptor ring. */
    clearDescriptors();
    
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
    IOLog("Link down on en%u\n", netif->getUnitNumber());
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

#pragma mark --- RTL8111C specific methods ---

void RTL8111::timerActionRTL8111C(IOTimerEventSource *timer)
{
    if (!linkUp) {
        DebugLog("Timer fired while link down.\n");
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
            setLinkUp();
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

