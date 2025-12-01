/* RealtekRTL8111.hpp -- RTL8111 driver class definition.
 *
 * Copyright (c) 2013-2025 Laura Müller <laura-mueller@uni-duesseldorf.de>
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

#include "RealtekRTL8111Linux-804704.hpp"
#include "RealtekRxPool.hpp"

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
    MEDIUM_INDEX_100FDFC,
    MEDIUM_INDEX_1000FD,
    MEDIUM_INDEX_1000FDFC,
    MEDIUM_INDEX_100FDEEE,
    MEDIUM_INDEX_100FDFCEEE,
    MEDIUM_INDEX_1000FDEEE,
    MEDIUM_INDEX_1000FDFCEEE,
	MEDIUM_INDEX_COUNT
};

#define MBit 1000000

enum {
    kSpeed1000MBit = 1000*MBit,
    kSpeed100MBit = 100*MBit,
    kSpeed10MBit = 10*MBit,
};

enum {
    kFlowControlOff = 0,
    kFlowControlOn = 0x01
};

enum {
    kEEEMode100 = 0x0002,
    kEEEMode1000 = 0x0004
};

enum {
    kEEETypeNo = 0,
    kEEETypeYes = 1,
    kEEETypeCount
};

/* RTL8111's dma descriptor. */
typedef union RtlDmaDesc {
    struct {
        UInt32 opts1;
        UInt32 opts2;
        UInt64 addr;
    } cmd;
    struct {
        UInt64 blen;
        UInt64 addr;
    } buf;
} RtlDmaDesc;

/* RTL8111's statistics dump data structure */
typedef struct RtlStatData {
	UInt64	txPackets;
	UInt64	rxPackets;
	UInt64	txErrors;
	UInt32	rxErrors;
	UInt16	rxMissed;
	UInt16	alignErrors;
	UInt32	txOneCollision;
	UInt32	txMultiCollision;
	UInt64	rxUnicast;
	UInt64	rxBroadcast;
	UInt32	rxMulticast;
	UInt16	txAborted;
	UInt16	txUnderun;
} RtlStatData;

#define kTransmitQueueCapacity  1024

/* With up to 32 segments we should be on the save side. */
#define kMaxSegs 32

/* The number of descriptors must be a power of 2. */
#define kNumTxDesc	512	/* Number of Tx descriptors */
#define kNumRxDesc	512 /* Number of Rx descriptors */
#define kTxLastDesc    (kNumTxDesc - 1)
#define kRxLastDesc    (kNumRxDesc - 1)
#define kTxDescMask    (kNumTxDesc - 1)
#define kRxDescMask    (kNumRxDesc - 1)
#define kTxDescSize    (kNumTxDesc * sizeof(union RtlDmaDesc))
#define kRxDescSize    (kNumRxDesc * sizeof(union RtlDmaDesc))
#define kRxBufArraySize (kNumRxDesc * sizeof(rtlRxBufferInfo))
#define kTxBufArraySize (kNumTxDesc * sizeof(mbuf_t))

/* Numbers of IOMemoryDescriptors and IORanges for tx */
#define kNumTxMemDesc       (kNumTxDesc / 2)
#define kTxMemDescMask      (kNumTxMemDesc - 1)
#define kNumTxRanges        (kNumTxDesc + kMaxSegs)
#define kTxRangeMask        kTxDescMask
#define kTxMapMemSize       sizeof(struct rtlTxMapInfo)

/* Numbers of IOMemoryDescriptors and batch size for rx */
#define kRxMemBaseShift 4
#define kNumRxMemDesc   (kNumRxDesc >> kRxMemBaseShift)
#define kRxMapMemSize   (sizeof(struct rtlRxMapInfo))
#define kRxMemBatchSize (kNumRxDesc / kNumRxMemDesc)
#define kRxMemDescMask  (kRxMemBatchSize - 1)
#define kRxMemBaseMask  ~kRxMemDescMask


/* This is the receive buffer size (must be large enough to hold a packet). */
#define kRxBufferSize   PAGE_SIZE
#define kMCFilterLimit  32
#define kMaxMtu         9000
#define kMaxPacketSize (kMaxMtu + ETH_HLEN + ETH_FCS_LEN)
#define kJumboFrameSupport CFG_METHOD_16

/* RealtekRxPool capacities */
#define kRxPoolClstCap   100    /* mbufs with 4k cluster*/
#define kRxPoolMbufCap   50     /* mbufs without clusters */

/* statitics timer period in ms. */
#define kTimeoutMS 1000

/* Treshhold value in ns for the modified interrupt sequence. */
#define kFastIntrTreshhold 200000

/* Treshhold value to wake a stalled queue */
#define kTxQueueWakeTreshhold (kNumTxDesc / 8)

/* transmitter deadlock treshhold in seconds. */
#define kTxDeadlockTreshhold 3
#define kTxCheckTreshhold (kTxDeadlockTreshhold - 1)

/* IPv4 specific stuff */
#define kMinL4HdrOffsetV4 34

/* IPv6 specific stuff */
#define kMinL4HdrOffsetV6 54

/* This definitions should have been in IOPCIDevice.h. */
enum
{
    kIOPCIPMCapability = 2,
    kIOPCIPMControl = 4,
};

enum
{
    kIOPCIELinkCapability = 12,
    kIOPCIELinkControl = 16,
};

enum
{
    kIOPCIELinkCtlASPM = 0x0003,    /* ASPM Control */
    kIOPCIELinkCtlL0s = 0x0001,     /* L0s Enable */
    kIOPCIELinkCtlL1 = 0x0002,      /* L1 Enable */
    kIOPCIELinkCtlCcc = 0x0040,     /* Common Clock Configuration */
    kIOPCIELinkCtlClkReqEn = 0x100, /* Enable clkreq */
};

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

#define kParamName "Driver Parameters"
#define kEnableEeeName "enableEEE"
#define kEnableCSO6Name "enableCSO6"
#define kEnableTSO4Name "enableTSO4"
#define kEnableTSO6Name "enableTSO6"
#define kDisableASPMName "disableASPM"
#define kDriverVersionName "DriverVersion"
#define kFallbackName "fallbackMAC"
#define kNameLenght 64

#define kChipsetName "Chipset"

/*
 * Indicates if a tx IOMemoryDescriptor is in the prepared
 * (active) or completed state (inactive).
 */
enum
{
    kIOMemoryInactive = 0,
    kIOMemoryActive = 1
};

typedef struct rtlTxMapInfo {
    UInt16 txNextMem2Use;
    UInt16 txNextMem2Free;
    SInt16 txNumFreeMem;
    IOMemoryDescriptor *txMemIO[kNumTxMemDesc];
    IOAddressRange txMemRange[kNumTxRanges];
    IOAddressRange txSCRange[kMaxSegs];
} rtlTxMapInfo;

typedef struct rtlRxMapInfo {
    IOMemoryDescriptor *rxMemIO[kNumRxMemDesc];
    IOAddressRange rxMemRange[kNumRxDesc];
} rtlRxMapInfo;

typedef struct rtlRxBufferInfo {
    mbuf_t mbuf;
    IOPhysicalAddress64 phyAddr;
} rtlRxBufferInfo;

/**
 *  Known kernel versions
 */
enum KernelVersion {
    Tiger         = 8,
    Leopard       = 9,
    SnowLeopard   = 10,
    Lion          = 11,
    MountainLion  = 12,
    Mavericks     = 13,
    Yosemite      = 14,
    ElCapitan     = 15,
    Sierra        = 16,
    HighSierra    = 17,
    Mojave        = 18,
    Catalina      = 19,
    BigSur        = 20,
    Monterey      = 21,
    Ventura       = 22,
    Sonoma        = 23,
    Sequoia       = 24,
    Tahoe         = 25,
};

/**
 *  Kernel version major
 */
extern const int version_major;

extern const struct RTLChipInfo rtl_chip_info[];

class RTL8111 : public super
{
	
	OSDeclareDefaultStructors(RTL8111)
	
public:
	/* IOService (or its superclass) methods. */
	virtual bool start(IOService *provider) override;
	virtual void stop(IOService *provider) override;
	virtual bool init(OSDictionary *properties) override;
	virtual void free() override;
	
	/* Power Management Support */
	virtual IOReturn registerWithPolicyMaker(IOService *policyMaker) override;
    virtual IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker ) override;
	virtual void systemWillShutdown(IOOptionBits specifier) override;

	/* IONetworkController methods. */	
	virtual IOReturn enable(IONetworkInterface *netif) override;
	virtual IOReturn disable(IONetworkInterface *netif) override;
	
    virtual IOReturn outputStart(IONetworkInterface *interface, IOOptionBits options) override;
    virtual IOReturn setInputPacketPollingEnable(IONetworkInterface *interface, bool enabled) override;
    virtual void pollInputPackets(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context) override;
	
	virtual void getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const override;
	
	virtual IOOutputQueue* createOutputQueue() override;
	
	virtual const OSString* newVendorString() const override;
	virtual const OSString* newModelString() const override;
	
	virtual IOReturn selectMedium(const IONetworkMedium *medium) override;
	virtual bool configureInterface(IONetworkInterface *interface) override;
	
	virtual bool createWorkLoop() override;
	virtual IOWorkLoop* getWorkLoop() const override;
	
	/* Methods inherited from IOEthernetController. */	
	virtual IOReturn getHardwareAddress(IOEthernetAddress *addr) override;
	virtual IOReturn setHardwareAddress(const IOEthernetAddress *addr) override;
	virtual IOReturn setPromiscuousMode(bool active) override;
	virtual IOReturn setMulticastMode(bool active) override;
	virtual IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count) override;
	virtual IOReturn getChecksumSupport(UInt32 *checksumMask, UInt32 checksumFamily, bool isOutput) override;
    virtual IOReturn setWakeOnMagicPacket(bool active) override;
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    
    virtual UInt32 getFeatures() const override;
    virtual IOReturn getMaxPacketSize(UInt32 * maxSize) const override;
    virtual IOReturn setMaxPacketSize(UInt32 maxSize) override;

private:
    bool initPCIConfigSpace(IOPCIDevice *provider);
    static IOReturn setPowerStateWakeAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4);
    static IOReturn setPowerStateSleepAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4);
    void getParams();
    bool setupMediumDict();
    bool initEventSources(IOService *provider);
    void pciErrorInterrupt();
    void txInterrupt();
    
    UInt32 txMapPacket(mbuf_t packet, IOPhysicalSegment *vector, UInt32 maxSegs);
    void txUnmapPacket();

    void interruptOccurredPoll(OSObject *client, IOInterruptEventSource *src, int count);
    void interruptOccurredVTD(OSObject *client, IOInterruptEventSource *src, int count);

    UInt32 rxInterrupt(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context);
    UInt32 rxInterruptVTD(IONetworkInterface *interface, uint32_t maxCount, IOMbufQueue *pollQueue, void *context);

    UInt16 rxMapBuffers(UInt16 index, UInt16 count);
    
    bool setupRxResources();
    bool setupTxResources();
    bool setupStatResources();
    void freeRxResources();
    void freeTxResources();
    void freeStatResources();
    void clearDescriptors();
    void checkLinkStatus();
    void updateStatitics();
    void setLinkUp();
    void setLinkDown();
    bool checkForDeadlock();

    bool setupRxMap();
    void freeRxMap();
    bool setupTxMap();
    void freeTxMap();

    /* Jumbo frame support methods */
    void discardPacketFragment();

    /* Hardware initialization methods. */
    bool initRTL8111();
    void enableRTL8111();
    void disableRTL8111();
    void setupRTL8111(UInt16 newIntrMitigate, bool enableInterrupts);
    void setOffset79(UInt8 setting);
    void restartRTL8111();
    void setPhyMedium();
    UInt8 csiFun0ReadByte(UInt32 addr);
    void csiFun0WriteByte(UInt32 addr, UInt8 value);
    void enablePCIOffset99();
    void disablePCIOffset99();
    void initPCIOffset99();
    void setPCI99_180ExitDriverPara();
    void hardwareD3Para();
    void sleepRxEnable();
    UInt16 getEEEMode();
    void exitOOB();
    
    /* Hardware specific methods */
    inline void getChecksumCommand(UInt32 *cmd1, UInt32 *cmd2, mbuf_csum_request_flags_t checksums);
    inline void getTso4Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags);
    inline void getTso6Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags);
    void getChecksumResult(mbuf_t m, UInt32 status1, UInt32 status2);
    
    /* RTL8111C specific methods */
    void timerActionRTL8111C(IOTimerEventSource *timer);

    /* RTL8111B/8168B specific methods */
    void timerActionRTL8111B(IOTimerEventSource *timer);
    
private:
	IOWorkLoop *workLoop;
    IOCommandGate *commandGate;
	IOPCIDevice *pciDevice;
	OSDictionary *mediumDict;
	IONetworkMedium *mediumTable[MEDIUM_INDEX_COUNT];
	IOBasicOutputQueue *txQueue;
	
	IOInterruptEventSource *interruptSource;
	IOTimerEventSource *timerSource;
	IOEthernetInterface *netif;
	IOMemoryMap *baseMap;
    IOMapper *mapper;
    volatile void *baseAddr;
    
    /* transmitter data */
    mbuf_t txNext2FreeMbuf;
    IOBufferMemoryDescriptor *txBufDesc;
    IOPhysicalAddress64 txPhyAddr;
    IODMACommand *txDescDmaCmd;
    RtlDmaDesc *txDescArray;
    IOMbufNaturalMemoryCursor *txMbufCursor;
    mbuf_t *txMbufArray;
    void *txBufArrayMem;
    rtlTxMapInfo *txMapInfo;
    void *txMapMem;
    UInt64 txDescDoneCount;
    UInt64 txDescDoneLast;
    UInt32 txNextDescIndex;
    UInt32 txDirtyDescIndex;
    SInt32 txNumFreeDesc;

    /* receiver data */
    IOBufferMemoryDescriptor *rxBufDesc;
    IOPhysicalAddress64 rxPhyAddr;
    IODMACommand *rxDescDmaCmd;
    RtlDmaDesc *rxDescArray;
    RealtekRxPool *rxPool;
    rtlRxBufferInfo *rxBufArray;
    void *rxBufArrayMem;
    void *rxMapMem;
    rtlRxMapInfo *rxMapInfo;
    mbuf_t rxPacketHead;
    mbuf_t rxPacketTail;
    UInt32 rxPacketSize;
    UInt64 multicastFilter;
    UInt32 rxConfigReg;
    UInt32 rxConfigMask;
    UInt16 rxNextDescIndex;
    UInt16 rxMapNextIndex;

    /* power management data */
    unsigned long powerState;
    
    /* statistics data */
    UInt32 deadlockWarn;
    IONetworkStats *netStats;
	IOEthernetStats *etherStats;
    IOBufferMemoryDescriptor *statBufDesc;
    IOPhysicalAddress64 statPhyAddr;
    IODMACommand *statDescDmaCmd;
    struct RtlStatData *statData;

    UInt32 mtu;
    UInt32 speed;
    UInt32 duplex;
    UInt16 flowCtl;
    UInt16 autoneg;
    UInt16 eeeCap;
    UInt16 eeeMode;
    struct pci_dev pciDeviceData;
    struct rtl8168_private linuxData;
    struct IOEthernetAddress currMacAddr;
    struct IOEthernetAddress origMacAddr;
    struct IOEthernetAddress fallBackMacAddr;

    UInt64 lastIntrTime;
    UInt16 intrMask;
    UInt16 intrMitigateValue;
    
    UInt16 intrMaskRxTx;
    UInt16 intrMaskPoll;

    IONetworkPacketPollingParameters pollParams;

    bool polling;

    /* flags */
    bool isEnabled;
	bool promiscusMode;
	bool multicastMode;
    bool linkUp;
    
    bool needsUpdate;
    bool wolCapable;
    bool wolActive;
    bool revisionC;
    bool enableTSO4;
    bool enableTSO6;
    bool enableCSO6;
    bool disableASPM;
    bool useAppleVTD;

    UInt8 pciPMCtrlOffset;
};
