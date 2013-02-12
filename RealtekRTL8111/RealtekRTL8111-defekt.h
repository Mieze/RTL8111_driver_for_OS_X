/* RealtekRTL8111.h -- RTL8111 driver class definition.
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
 * Driver for Realtek RTL8111x PCIe ethernet.
 *
 * This driver is based on Realtek's r8168 Linux driver.
 */

#include "RealtekRTL8111Linux.h"

#ifdef DEBUG
#define DebugLog(args...) IOLog(args)
#else
#define DebugLog(args...) 
#endif

#define	RELEASE(x)	if(x){(x)->release();(x)=NULL;}

#define WriteReg8(reg, val8)    _OSWriteInt8((baseAddr), (reg), (val8))
#define WriteReg16(reg, val16)  OSWriteLittleInt16((baseAddr), (reg), (val16))
#define WriteReg32(reg, val32)  OSWriteLittleInt32((baseAddr), (reg), (val32))
#define ReadReg8(reg)           _OSReadInt8((baseAddr), (reg))
#define ReadReg16(reg)          OSReadLittleInt16((baseAddr), (reg))
#define ReadReg32(reg)          OSReadLittleInt32((baseAddr), (reg))

#define super IOEthernetController

enum
{
	MEDIUM_INDEX_AUTO = 0,
	MEDIUM_INDEX_10HD,
	MEDIUM_INDEX_10FD,
	MEDIUM_INDEX_100HD,
	MEDIUM_INDEX_100FD,
	MEDIUM_INDEX_1000FD,
	MEDIUM_INDEX_COUNT
};

#define MBit 1000000

enum {
    kSpeed1000MBit = 1000*MBit,
    kSpeed100MBit = 100*MBit,
    kSpeed10MBit = 10*MBit,
};

typedef struct RtlDmaDesc {
    UInt32 opts1;
    UInt32 opts2;
    UInt64 addr;
} RtlDmaDesc;

typedef struct RtlStatData {
	UInt64	tx_packets;
	UInt64	rx_packets;
	UInt64	tx_errors;
	UInt32	rx_errors;
	UInt16	rx_missed;
	UInt16	align_errors;
	UInt32	tx_one_collision;
	UInt32	tx_multi_collision;
	UInt64	rx_unicast;
	UInt64	rx_broadcast;
	UInt32	rx_multicast;
	UInt16	tx_aborted;
	UInt16	tx_underun;
} RtlStatData;

#define kTransmitQueueCapacity  1024

/* Tests have shown that the network stack sends packets of up to 20 segments. */
#define kMaxSegs 24

/* Don't forget to adjust the masks in case you reduce the number of descriptors. */
#define kNumTxDesc	1024	/* Number of Tx descriptors */
#define kNumRxDesc	1024	/* Number of Rx descriptors */
#define kTxLastDesc    (kNumTxDesc - 1)
#define kRxLastDesc    (kNumRxDesc - 1)
#define kTxDescMask    (kNumTxDesc - 1)
#define kRxDescMask    (kNumRxDesc - 1)
#define kTxDescSize    (kNumTxDesc*sizeof(struct RtlDmaDesc))
#define kRxDescSize    (kNumRxDesc*sizeof(struct RtlDmaDesc))

/* This is the receive buffer size (must be large engough to hold a packet). */
#define kRxBufferPktSize    2000
#define kMCFilterLimit  32

/* Statitics timer period in ms. */
#define kTimeoutMS 1000

/* transmitter deadlock treshhold in seconds. */
#define kTxDeadlockTreshhold 3

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

extern const struct RTLChipInfo rtl_chip_info[];

class RTL8111 : public super
{
	
	OSDeclareDefaultStructors(RTL8111)
	
public:
	/* IOService (or its superclass) methods. */
	virtual bool start(IOService *provider);
	virtual void stop(IOService *provider);
	virtual bool init(OSDictionary *properties);
	virtual void free();
	
	/* Power Management Support */
	virtual IOReturn registerWithPolicyMaker(IOService *policyMaker);
    virtual IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker );
	virtual void systemWillShutdown(IOOptionBits specifier);

	/* IONetworkController methods. */	
	virtual IOReturn enable(IONetworkInterface *netif);
	virtual IOReturn disable(IONetworkInterface *netif);
	
	virtual UInt32 outputPacket(mbuf_t m, void *param);
	
	virtual void getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const;
	
	virtual IOOutputQueue* createOutputQueue();
	
	virtual const OSString* newVendorString() const;
	virtual const OSString* newModelString() const;
	
	virtual IOReturn selectMedium(const IONetworkMedium *medium);
	virtual bool configureInterface(IONetworkInterface *interface);
	
	virtual bool createWorkLoop();
	virtual IOWorkLoop* getWorkLoop() const;
	
	/* Methods inherited from IOEthernetController. */	
	virtual IOReturn getHardwareAddress(IOEthernetAddress *addr);
	virtual IOReturn setHardwareAddress(const IOEthernetAddress *addr);
	virtual IOReturn setPromiscuousMode(bool active);
	virtual IOReturn setMulticastMode(bool active);
	virtual IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count);
	virtual IOReturn getChecksumSupport(UInt32 *checksumMask, UInt32 checksumFamily, bool isOutput);
	virtual IOReturn setMaxPacketSize(UInt32 maxSize);
	virtual IOReturn getMaxPacketSize(UInt32 *maxSize) const;
	virtual IOReturn getMinPacketSize(UInt32 *minSize) const;
    virtual IOReturn setWakeOnMagicPacket(bool active);
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const;
    
    virtual UInt32 getFeatures() const;
    
private:
    bool initPCIConfigSpace(IOPCIDevice *provider);
    bool setupMediumDict();
    bool initEventSources(IOService *provider);
    void interruptOccurred(OSObject *client, IOInterruptEventSource *src, int count);
    void timerAction(IOTimerEventSource *timer);
    void txInterrupt();
    void rxInterrupt();
    bool setupDMADescriptors();
    void freeDMADescriptors();
    void txClear();
    void checkLinkStatus();
    void updateStatitics();
    
    /* Hardware initialization methods. */
    bool initChip(struct rtl8168_private *tp);
    bool enableChip();
    void disableChip();
    void startChip();
    void setOffset79(UInt8 setting);
    void fillDescriptorAddr();
    
private:
	IOWorkLoop *workLoop;
	IOPCIDevice *pciDevice;
	OSDictionary *mediumDict;
	IONetworkMedium *mediumTable[MEDIUM_INDEX_COUNT];
	IOBasicOutputQueue *txQueue;
	
	IOInterruptEventSource *interruptSource;
	IOTimerEventSource *timerSource;
	IOLock *txLock;
	IOEthernetInterface *netif;
	IOMemoryMap *baseMap;
    volatile void *baseAddr;
    
    /* transmitter data */
    mbuf_t txMbufArray[kNumTxDesc];
    IOBufferMemoryDescriptor *txBufDesc;
    IOPhysicalAddress64 txPhyAddr;
    struct RtlDmaDesc *txDescArray;
    IOMbufNaturalMemoryCursor *txMbufCursor;
    UInt32 txNextDescIndex;
    UInt32 txDirtyDescIndex;
    SInt32 txNumFreeDesc;
    UInt32 txTimeoutValue;

    /* receiver data */
    mbuf_t rxMbufArray[kNumRxDesc];
    IOBufferMemoryDescriptor *rxBufDesc;
    IOPhysicalAddress64 rxPhyAddr;
    struct RtlDmaDesc *rxDescArray;
	IOMbufNaturalMemoryCursor *rxMbufCursor;
    UInt64 txReqDoneCount;
    UInt64 txReqDoneLast;
    UInt64 multicastFilter;
    UInt32 rxNextDescIndex;
    UInt32 rxConfigReg;
    UInt32 rxConfigMask;
    
    /* statistics data */
    UInt32 deadlockWarn;
    IONetworkStats *netStats;
	IOEthernetStats *etherStats;
    IOBufferMemoryDescriptor *statBufDesc;
    IOPhysicalAddress64 statPhyAddr;
    struct RtlStatData *statData;

    /* miscellaneous data */
    const char *name;
    UInt32 unitNumber;
    UInt32 mtu;
	UInt32 powerState;
    UInt32 speed;
    UInt32 duplex;
    UInt32 autoneg;
    struct pci_dev pciDeviceData;
    struct rtl8168_private linuxData;
    struct IOEthernetAddress currMacAddr;
    struct IOEthernetAddress origMacAddr;
    
    /* flags */
    bool isEnabled;
	bool promiscusMode;
	bool multicastMode;
    bool linkUp;
    bool stalled;
    bool useMSI;
    bool updateStats;
    
    /* debug data */
};
