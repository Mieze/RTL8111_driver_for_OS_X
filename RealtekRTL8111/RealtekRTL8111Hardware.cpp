//
//  RealtekRTL8111Hardware.cpp
//  RealtekRTL8111
//
//  Created by Laura Müller on 06.08.19.
//  Copyright © 2019 Laura Müller. All rights reserved.
//

#include "RealtekRTL8111.hpp"

#pragma mark --- hardware initialization methods ---

bool RTL8111::initPCIConfigSpace(IOPCIDevice *provider)
{
    UInt32 pcieLinkCap;
    UInt16 pcieLinkCtl;
    UInt16 cmdReg;
    UInt16 pmCap;
    UInt8 pcieCapOffset;
    UInt8 pmCapOffset;
    bool result = false;
    
    /* Get vendor and device info. */
    pciDeviceData.vendor = provider->configRead16(kIOPCIConfigVendorID);
    pciDeviceData.device = provider->configRead16(kIOPCIConfigDeviceID);
    pciDeviceData.subsystem_vendor = provider->configRead16(kIOPCIConfigSubSystemVendorID);
    pciDeviceData.subsystem_device = provider->configRead16(kIOPCIConfigSubSystemID);
    
    /* Setup power management. */
    if (provider->findPCICapability(kIOPCIPowerManagementCapability, &pmCapOffset)) {
        pmCap = provider->extendedConfigRead16(pmCapOffset + kIOPCIPMCapability);
        DebugLog("[RealtekRTL8111]: PCI power management capabilities: 0x%x.\n", pmCap);
        
        if (pmCap & kPCIPMCPMESupportFromD3Cold) {
            wolCapable = true;
            DebugLog("[RealtekRTL8111]: PME# from D3 (cold) supported.\n");
        }
        pciPMCtrlOffset = pmCapOffset + kIOPCIPMControl;
    } else {
        IOLog("[RealtekRTL8111]: PCI power management unsupported.\n");
    }
    provider->enablePCIPowerManagement(kPCIPMCSPowerStateD0);
    
    /* Get PCIe link information. */
    if (provider->findPCICapability(kIOPCIPCIExpressCapability, &pcieCapOffset)) {
        pcieLinkCap = provider->configRead32(pcieCapOffset + kIOPCIELinkCapability);
        pcieLinkCtl = provider->configRead16(pcieCapOffset + kIOPCIELinkControl);
        DebugLog("[RealtekRTL8111]: PCIe link capabilities: 0x%08x, link control: 0x%04x.\n", pcieLinkCap, pcieLinkCtl);
        
        if (disableASPM) {
            IOLog("[RealtekRTL8111]: Disable PCIe ASPM.\n");
            provider->setASPMState(this, 0);
        } else {
            IOLog("[RealtekRTL8111]: Warning: Enable PCIe ASPM.\n");
            provider->setASPMState(this, kIOPCIELinkCtlASPM);
            linuxData.aspm = 1;
        }
    }
    /* Enable the device. */
    cmdReg    = provider->configRead16(kIOPCIConfigCommand);
    cmdReg  &= ~kIOPCICommandIOSpace;
    cmdReg    |= (kIOPCICommandBusMaster | kIOPCICommandMemorySpace | kIOPCICommandMemWrInvalidate);
    provider->configWrite16(kIOPCIConfigCommand, cmdReg);
    provider->configWrite8(kIOPCIConfigLatencyTimer, 0x40);
    
    //baseMap = provider->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
    baseMap = provider->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2, kIOMapInhibitCache);
    
    if (!baseMap) {
        IOLog("[RealtekRTL8111]: region #2 not an MMIO resource, aborting.\n");
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
    IOPCIDevice *dev;
    UInt16 val16;
    UInt8 offset;
    
    if (ethCtlr && ethCtlr->pciPMCtrlOffset) {
        dev = ethCtlr->pciDevice;
        offset = ethCtlr->pciPMCtrlOffset;
        
        val16 = dev->extendedConfigRead16(offset);
        
        val16 &= ~(kPCIPMCSPowerStateMask | kPCIPMCSPMEStatus | kPCIPMCSPMEEnable);
        val16 |= kPCIPMCSPowerStateD0;
        
        dev->extendedConfigWrite16(offset, val16);
    }
    return kIOReturnSuccess;
}

IOReturn RTL8111::setPowerStateSleepAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4)
{
    RTL8111 *ethCtlr = OSDynamicCast(RTL8111, owner);
    IOPCIDevice *dev;
    UInt16 val16;
    UInt8 offset;

    if (ethCtlr && ethCtlr->pciPMCtrlOffset) {
        dev = ethCtlr->pciDevice;
        offset = ethCtlr->pciPMCtrlOffset;
        
        val16 = dev->extendedConfigRead16(offset);
        
        val16 &= ~(kPCIPMCSPowerStateMask | kPCIPMCSPMEStatus | kPCIPMCSPMEEnable);

        if (ethCtlr->wolActive)
            val16 |= (kPCIPMCSPMEStatus | kPCIPMCSPMEEnable | kPCIPMCSPowerStateD3);
        else
            val16 |= kPCIPMCSPowerStateD3;
        
        dev->extendedConfigWrite16(offset, val16);
    }
    return kIOReturnSuccess;
}

/*
 * These functions have to be rewritten after every update
 * of the underlying Linux sources.
 */

bool RTL8111::initRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    OSNumber *chipsetNumber;
    UInt32 i, csi_tmp;
    UInt16 macAddr[4];
    UInt8 options1, options2;
    bool result = false;
    bool wol;
    
    /* Identify chip attached to board. */
    rtl8168_get_mac_version(tp, baseAddr);
    
    if (tp->mcfg == CFG_METHOD_DEFAULT) {
        DebugLog("[RealtekRTL8111]: Retry chip recognition.\n");
        
        /* In case chip recognition failed clear corresponding bits... */
        WriteReg32(TxConfig, ReadReg32(TxConfig) & ~0x7CF00000);
        
        /* ...and try again. */
        rtl8168_get_mac_version(tp, baseAddr);
    }
    if (tp->mcfg >= CFG_METHOD_MAX) {
        DebugLog("[RealtekRTL8111]: Unsupported chip found. Aborting...\n");
        goto done;
    }
    tp->chipset =  tp->mcfg;
    
    chipsetNumber = OSNumber::withNumber(tp->chipset, 32);
    
    if (chipsetNumber) {
        setProperty(kChipsetName, chipsetNumber);
        chipsetNumber->release();
    }

    /* Setup EEE support. */
    if ((tp->mcfg >= CFG_METHOD_14) && (linuxData.eee_enabled != 0)) {
        linuxData.eee_adv_t = eeeCap = (kEEEMode100 | kEEEMode1000);
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            tp->HwSuppDashVer = 3;
            break;
        default:
            tp->HwSuppDashVer = 0;
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            tp->HwPkgDet = rtl8168_mac_ocp_read(tp, 0xDC00);
            tp->HwPkgDet = (tp->HwPkgDet >> 3) & 0x0F;
            break;
    }
    
    if (HW_DASH_SUPPORT_TYPE_3(tp) && tp->HwPkgDet == 0x06)
        tp->eee_enabled = 0;
    
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            tp->HwSuppNowIsOobVer = 1;
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            tp->HwPcieSNOffset = 0x16C;
            break;
        case CFG_METHOD_DEFAULT:
            tp->HwPcieSNOffset = 0;
            break;
        default:
            tp->HwPcieSNOffset = 0x164;
            break;
    }
    tp->DASH = 0;
    
    if (tp->aspm) {
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
            case CFG_METHOD_31:
            case CFG_METHOD_32:
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
            case CFG_METHOD_31:
            case CFG_METHOD_32:
                tp->org_pci_offset_180 = csiFun0ReadByte(0x214);
                break;
        }
    }
    tp->org_pci_offset_80 = pciDevice->configRead8(0x80);
    tp->org_pci_offset_81 = pciDevice->configRead8(0x81);
    
    if (tp->mcfg == CFG_METHOD_30) {
        u16 ioffset_p3, ioffset_p2, ioffset_p1, ioffset_p0;
        u16 TmpUshort;
        
        rtl8168_mac_ocp_write( tp, 0xDD02, 0x807D);
        TmpUshort = rtl8168_mac_ocp_read( tp, 0xDD02 );
        ioffset_p3 = ( (TmpUshort & BIT_7) >>7 );
        ioffset_p3 <<= 3;
        TmpUshort = rtl8168_mac_ocp_read( tp, 0xDD00 );
        
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
    switch (tp->mcfg) {
        case CFG_METHOD_29:
        case CFG_METHOD_30:
        case CFG_METHOD_31:
        case CFG_METHOD_32: {
            u16 rg_saw_cnt;
            
            rtl8168_mdio_write(tp, 0x1F, 0x0C42);
            rg_saw_cnt = rtl8168_mdio_read(tp, 0x13);
            rg_saw_cnt &= ~(BIT_15|BIT_14);
            rtl8168_mdio_write(tp, 0x1F, 0x0000);
            
            if ( rg_saw_cnt > 0) {
                tp->SwrCnt1msIni = 16000000/rg_saw_cnt;
                tp->SwrCnt1msIni &= 0x0FFF;
                
                tp->RequireAdjustUpsTxLinkPulseTiming = TRUE;
            }
        }
            break;
    }
    if (pciDeviceData.subsystem_vendor == 0x144d) {
        if (pciDeviceData.subsystem_device == 0xc098 ||
            pciDeviceData.subsystem_device == 0xc0b1 ||
            pciDeviceData.subsystem_device == 0xc0b8)
            tp->hwoptimize |= HW_PATCH_SAMSUNG_LAN_DONGLE;
    }
    
    if (tp->hwoptimize & HW_PATCH_SAMSUNG_LAN_DONGLE) {
        switch (tp->mcfg) {
            case CFG_METHOD_14:
            case CFG_METHOD_15:
            case CFG_METHOD_16:
            case CFG_METHOD_17:
            case CFG_METHOD_18:
            case CFG_METHOD_19:
            case CFG_METHOD_20:
            case CFG_METHOD_30:
                tp->RequiredSecLanDonglePatch = TRUE;
                break;
        }
    }
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            tp->HwSuppMagicPktVer = WAKEUP_MAGIC_PACKET_V2;
            break;
        case CFG_METHOD_DEFAULT:
            tp->HwSuppMagicPktVer = WAKEUP_MAGIC_PACKET_NOT_SUPPORT;
            break;
        default:
            tp->HwSuppMagicPktVer = WAKEUP_MAGIC_PACKET_V1;
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_16:
        case CFG_METHOD_17:
            tp->HwSuppCheckPhyDisableModeVer = 1;
            break;
        case CFG_METHOD_18:
        case CFG_METHOD_19:
        case CFG_METHOD_21:
        case CFG_METHOD_22:
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            tp->HwSuppCheckPhyDisableModeVer = 2;
            break;
        case CFG_METHOD_23:
        case CFG_METHOD_27:
        case CFG_METHOD_28:
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            tp->HwSuppCheckPhyDisableModeVer = 3;
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            tp->HwSuppGigaForceMode = TRUE;
            break;
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_31;
            break;
    }
    
    if (tp->HwIcVerUnknown) {
        tp->NotWrRamCodeToMicroP = TRUE;
        tp->NotWrMcuPatchCode = TRUE;
    }
    
    tp->NicCustLedValue = ReadReg16(CustomLED);
    
    exitOOB();
    rtl8168_hw_init(tp);
    rtl8168_nic_reset(tp);
    
    /* Get production from EEPROM */
    if (((tp->mcfg == CFG_METHOD_21 || tp->mcfg == CFG_METHOD_22 ||
          tp->mcfg == CFG_METHOD_25 || tp->mcfg == CFG_METHOD_29 ||
          tp->mcfg == CFG_METHOD_30) && (rtl8168_mac_ocp_read(tp, 0xDC00) & BIT_3)) ||
        ((tp->mcfg == CFG_METHOD_26) && (rtl8168_mac_ocp_read(tp, 0xDC00) & BIT_4)))
        tp->eeprom_type = EEPROM_TYPE_NONE;
    else
        rtl8168_eeprom_type(tp);
    
    if (tp->eeprom_type == EEPROM_TYPE_93C46 || tp->eeprom_type == EEPROM_TYPE_93C56)
        rtl8168_set_eeprom_sel_low(baseAddr);
    
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
        tp->mcfg == CFG_METHOD_30 ||
        tp->mcfg == CFG_METHOD_31 ||
        tp->mcfg == CFG_METHOD_32) {

        *(UInt32*)&macAddr[0] = rtl8168_eri_read(baseAddr, 0xE0, 4, ERIAR_ExGMAC);
        *(UInt16*)&macAddr[2] = rtl8168_eri_read(baseAddr, 0xE4, 2, ERIAR_ExGMAC);
        
        macAddr[3] = 0;
        rtl8168_rar_set(tp, (UInt8 *)macAddr);
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
                tp->mcfg == CFG_METHOD_30 ||
                tp->mcfg == CFG_METHOD_31 ||
                tp->mcfg == CFG_METHOD_32) {
                macAddr[0] = rtl8168_eeprom_read_sc(tp, 1);
                macAddr[1] = rtl8168_eeprom_read_sc(tp, 2);
                macAddr[2] = rtl8168_eeprom_read_sc(tp, 3);
            } else {
                macAddr[0] = rtl8168_eeprom_read_sc(tp, 7);
                macAddr[1] = rtl8168_eeprom_read_sc(tp, 8);
                macAddr[2] = rtl8168_eeprom_read_sc(tp, 9);
            }
            macAddr[3] = 0;
            rtl8168_rar_set(tp, (UInt8 *)macAddr);
        }
    }
    if (!is_valid_ether_addr((UInt8 *) macAddr)) {
        IOLog("[RealtekRTL8111]: Using fallback MAC.\n");
        rtl8168_rar_set(tp, fallBackMacAddr.bytes);
    }
    for (i = 0; i < MAC_ADDR_LEN; i++) {
        currMacAddr.bytes[i] = ReadReg8(MAC0 + i);
        origMacAddr.bytes[i] = currMacAddr.bytes[i]; /* keep the original MAC address */
    }
    IOLog("[RealtekRTL8111]: %s: (Chipset %d), %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
          rtl_chip_info[tp->chipset].name, tp->chipset,
          origMacAddr.bytes[0], origMacAddr.bytes[1],
          origMacAddr.bytes[2], origMacAddr.bytes[3],
          origMacAddr.bytes[4], origMacAddr.bytes[5]);
    
    tp->cp_cmd = ReadReg16(CPlusCmd);
    
    if (revisionC) {
        intrMaskRxTx = (SYSErr | LinkChg | RxDescUnavail | TxErr | TxOK | RxErr | RxOK);
        intrMaskPoll = (SYSErr | LinkChg);
    } else {
        intrMaskRxTx = (SYSErr | RxDescUnavail | TxErr | TxOK | RxErr | RxOK);
        intrMaskPoll = SYSErr;
    }
    intrMask = intrMaskRxTx;
    
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        IOLog("[RealtekRTL8111]: Device is WoL capable.\n");
    
#endif
    
    result = true;
    
done:
    return result;
}

void RTL8111::enableRTL8111()
{
    struct rtl8168_private *tp = &linuxData;
    
    setLinkStatus(kIONetworkLinkValid);
    
    intrMask = intrMaskRxTx;
    polling = false;
    
    exitOOB();
    rtl8168_hw_init(tp);
    rtl8168_nic_reset(tp);
    rtl8168_powerup_pll(tp);
    rtl8168_hw_ephy_config(tp);
    rtl8168_hw_phy_config(tp);
    setupRTL8111(intrMitigateValue, true);
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
    sleepRxEnable();
    hardwareD3Para();
    rtl8168_powerdown_pll(tp);
    
    if (linkUp) {
        linkUp = false;
        setLinkStatus(kIONetworkLinkValid);
        IOLog("[RealtekRTL8111]: Link down on en%u\n", netif->getUnitNumber());
    }
}

/* Reset the NIC in case a tx deadlock or a pci error occurred. timerSource and txQueue
 * are stopped immediately but will be restarted by checkLinkStatus() when the link has
 * been reestablished.
 */

void RTL8111::restartRTL8111()
{
    /* Stop output thread and flush txQueue */
    netif->stopOutputThread();
    netif->flushOutputQueue();
    
    linkUp = false;
    setLinkStatus(kIONetworkLinkValid);
    
    /* Reset NIC and cleanup both descriptor rings. */
    rtl8168_nic_reset(&linuxData);
    clearDescriptors();
        
    rxNextDescIndex = 0;
    deadlockWarn = 0;
    
    /* Reinitialize NIC. */
    enableRTL8111();
}

void RTL8111::setupRTL8111(UInt16 newIntrMitigate, bool enableInterrupts)
{
    struct rtl8168_private *tp = &linuxData;
    UInt32 csi_tmp;
    UInt16 mac_ocp_data;
    UInt8 deviceControl;
    
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            WriteReg8(Config3, ReadReg8(Config3) & ~BIT_1);
            break;
    }
    //keep magic packet only
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
        case CFG_METHOD_30:
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            csi_tmp = rtl8168_eri_read(baseAddr, 0xDE, 1, ERIAR_ExGMAC);
            csi_tmp &= ~BIT_0;
            rtl8168_eri_write(baseAddr, 0xDE, 1, csi_tmp, ERIAR_ExGMAC);
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
        
        WriteReg8(Config1, ReadReg8(Config1) & ~0x10);
    } else if (tp->mcfg == CFG_METHOD_16 || tp->mcfg == CFG_METHOD_17) {
        set_offset70F(tp, 0x27);
        setOffset79(0x50);
        
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xC8, 4, 0x00100002, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xE8, 4, 0x00100006, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD4, 4, ERIAR_ExGMAC);
        csi_tmp |= (BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12);
        rtl8168_eri_write(baseAddr, 0xD4, 4, csi_tmp, ERIAR_ExGMAC);
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
        
        if (mtu > ETH_DATA_LEN)
            WriteReg8(MTPS, 0x27);

        /* disable clock request. */
        pciDevice->configWrite8(0x81, 0x00);
        
    } else if (tp->mcfg == CFG_METHOD_18 || tp->mcfg == CFG_METHOD_19) {
        set_offset70F(tp, 0x27);
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
        
        if (mtu > ETH_DATA_LEN)
            WriteReg8(MTPS, 0x27);

        WriteReg8(TDFNR, 0x8);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD4, 4, ERIAR_ExGMAC);
        csi_tmp |= (BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12);
        rtl8168_eri_write(baseAddr, 0xD4, 4, csi_tmp, ERIAR_ExGMAC);
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
        set_offset70F(tp, 0x27);
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
        
        if (mtu > ETH_DATA_LEN)
            WriteReg8(MTPS, 0x27);

        WriteReg8(TDFNR, 0x8);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD4, 4, ERIAR_ExGMAC);
        csi_tmp |= BIT_10 | BIT_11;
        rtl8168_eri_write(baseAddr, 0xD4, 4, csi_tmp, ERIAR_ExGMAC);
        
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
        set_offset70F(tp, 0x27);
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
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD3C0);
            mac_ocp_data &= ~(BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
            mac_ocp_data |= 0x03A9;
            rtl8168_mac_ocp_write(tp, 0xD3C0, mac_ocp_data);
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD3C2);
            mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
            rtl8168_mac_ocp_write(tp, 0xD3C2, mac_ocp_data);
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD3C4);
            mac_ocp_data |= BIT_0;
            rtl8168_mac_ocp_write(tp, 0xD3C4, mac_ocp_data);
        } else if (tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) {
            
            if (tp->RequireAdjustUpsTxLinkPulseTiming) {
                mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD412);
                mac_ocp_data &= ~(0x0FFF);
                mac_ocp_data |= tp->SwrCnt1msIni;
                rtl8168_mac_ocp_write(tp, 0xD412, mac_ocp_data);
            }
            
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xE056);
            mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4);
            mac_ocp_data |= (BIT_6 | BIT_5 | BIT_4);
            rtl8168_mac_ocp_write(tp, 0xE056, mac_ocp_data);
            
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xE052);
            mac_ocp_data &= ~( BIT_14 | BIT_13);
            mac_ocp_data |= BIT_15;
            mac_ocp_data |= BIT_3;
            rtl8168_mac_ocp_write(tp, 0xE052, mac_ocp_data);
            
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD420);
            mac_ocp_data &= ~(BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
            mac_ocp_data |= 0x47F;
            rtl8168_mac_ocp_write(tp, 0xD420, mac_ocp_data);
            
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xE0D6);
            mac_ocp_data &= ~(BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
            mac_ocp_data |= 0x17F;
            rtl8168_mac_ocp_write(tp, 0xE0D6, mac_ocp_data);
        }
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg8(0x1B, ReadReg8(0x1B) & ~0x07);
        
        WriteReg8(TDFNR, 0x4);
        
        WriteReg8(Config2, ReadReg8(Config2) & ~PMSTS_En);
        
        if (tp->aspm)
            WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7);
        
        if (mtu > ETH_DATA_LEN)
            WriteReg8(MTPS, 0x27);
        
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
            rtl8168_mac_ocp_write(tp, 0xC140, 0xFFFF);
        } else if (tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30) {
            rtl8168_mac_ocp_write(tp, 0xC140, 0xFFFF);
            rtl8168_mac_ocp_write(tp, 0xC142, 0xFFFF);
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
        set_offset70F(tp, 0x27);
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
        
        if (mtu > ETH_DATA_LEN)
            WriteReg8(MTPS, 0x27);

        if (tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28) {
            rtl8168_oob_mutex_lock(tp);
            rtl8168_eri_write(baseAddr, 0x5F0, 2, 0x4F87, ERIAR_ExGMAC);
            rtl8168_oob_mutex_unlock(tp);
        }
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD4, 4, ERIAR_ExGMAC);
        csi_tmp  |= ( BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12 );
        rtl8168_eri_write(baseAddr, 0xD4, 4, csi_tmp, ERIAR_ExGMAC);
        
        rtl8168_mac_ocp_write(tp, 0xC140, 0xFFFF);
        rtl8168_mac_ocp_write(tp, 0xC142, 0xFFFF);
        
        if (tp->mcfg == CFG_METHOD_28) {
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD3E2);
            mac_ocp_data &= 0xF000;
            mac_ocp_data |= 0x3A9;
            rtl8168_mac_ocp_write(tp, 0xD3E2, mac_ocp_data);
            
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD3E4);
            mac_ocp_data &= 0xFF00;
            rtl8168_mac_ocp_write(tp, 0xD3E4, mac_ocp_data);
            
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xE860);
            mac_ocp_data |= BIT_7;
            rtl8168_mac_ocp_write(tp, 0xE860, mac_ocp_data);
        }
        
        rtl8168_set_dash_other_fun_dev_pci_cmd_register(tp, 0x07, 0x0E);
        rtl8168_set_dash_other_fun_dev_aspm_clkreq(tp, 3, 1, 0x0E);
        rtl8168_set_dash_other_fun_dev_state_change(tp, 0, 0x0E);
    } else if (tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) {
        set_offset70F(tp, 0x27);
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
        
        if (tp->RequireAdjustUpsTxLinkPulseTiming) {
            mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD412);
            mac_ocp_data &= ~(0x0FFF);
            mac_ocp_data |= tp->SwrCnt1msIni;
            rtl8168_mac_ocp_write(tp, 0xD412, mac_ocp_data);
        }
        
        mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xE056);
        mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4);
        mac_ocp_data |= (BIT_6 | BIT_5 | BIT_4);
        rtl8168_mac_ocp_write(tp, 0xE056, mac_ocp_data);
        rtl8168_mac_ocp_write(tp, 0xEA80, 0x0003);
        
        rtl8168_oob_mutex_lock(tp);
        mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xE052);
        mac_ocp_data |= BIT_0;
        if (tp->mcfg == CFG_METHOD_32)
            mac_ocp_data |= BIT_3;
        else
            mac_ocp_data &= ~BIT_3;
        rtl8168_mac_ocp_write(tp, 0xE052, mac_ocp_data);
        rtl8168_oob_mutex_unlock(tp);
        
        mac_ocp_data = rtl8168_mac_ocp_read(tp, 0xD420);
        mac_ocp_data &= ~(BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
        mac_ocp_data |= 0x47F;
        rtl8168_mac_ocp_write(tp, 0xD420, mac_ocp_data);
        
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        WriteReg8(0x1B, ReadReg8(0x1B) & ~0x07);
        
        WriteReg8(TDFNR, 0x4);
        
        WriteReg8(Config2, ReadReg8(Config2) & ~PMSTS_En);
        
        if (tp->aspm)
            WriteReg8(0xF1, ReadReg8(0xF1) | BIT_7);
        
        if (mtu > ETH_DATA_LEN)
            WriteReg8(MTPS, 0x27);

        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_6);
        WriteReg8(0xF2, ReadReg8(0xF2) | BIT_6);
        
        WriteReg8(0xD0, ReadReg8(0xD0) | BIT_7);
        
        rtl8168_eri_write(baseAddr, 0xC0, 2, 0x0000, ERIAR_ExGMAC);
        rtl8168_eri_write(baseAddr, 0xB8, 4, 0x00000000, ERIAR_ExGMAC);
        
        rtl8168_oob_mutex_lock(tp);
        rtl8168_eri_write(baseAddr, 0x5F0, 2, 0x4F87, ERIAR_ExGMAC);
        rtl8168_oob_mutex_unlock(tp);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0xD4, 4, ERIAR_ExGMAC);
        csi_tmp |= (BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12);
        
        if (tp->mcfg == CFG_METHOD_32) csi_tmp|= BIT_4;
        rtl8168_eri_write(baseAddr, 0xD4, 4, csi_tmp, ERIAR_ExGMAC);
        
        rtl8168_mac_ocp_write(tp, 0xC140, 0xFFFF);
        rtl8168_mac_ocp_write(tp, 0xC142, 0xFFFF);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1B0, 4, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_12;
        rtl8168_eri_write(baseAddr, 0x1B0, 4, csi_tmp, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x2FC, 1, ERIAR_ExGMAC);
        csi_tmp &= ~(BIT_0 | BIT_1);
        csi_tmp |= BIT_0;
        rtl8168_eri_write(baseAddr, 0x2FC, 1, csi_tmp, ERIAR_ExGMAC);
        
        csi_tmp = rtl8168_eri_read(baseAddr, 0x1D0, 1, ERIAR_ExGMAC);
        csi_tmp &= ~BIT_1;
        rtl8168_eri_write(baseAddr, 0x1D0, 1, csi_tmp, ERIAR_ExGMAC);
        
        rtl8168_set_dash_other_fun_dev_aspm_clkreq(tp, 2, 1, 0xED);
        rtl8168_set_dash_other_fun_dev_state_change(tp, 3, 0x78);
        
        if (tp->DASH) {
            rtl8168_set_dash_other_fun_dev_state_change(tp, 0, 0x85);
            rtl8168_set_dash_other_fun_dev_pci_cmd_register(tp, 0x07, 0x85);
        } else {
            rtl8168_set_dash_other_fun_dev_state_change(tp, 3, 0x85);
        }
    } else if (tp->mcfg == CFG_METHOD_1) {
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        deviceControl = pciDevice->configRead8(0x69);
        deviceControl &= ~0x70;
        deviceControl |= 0x58;
        pciDevice->configWrite8(0x69, deviceControl);
    } else if (tp->mcfg == CFG_METHOD_2) {
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        deviceControl = pciDevice->configRead8(0x69);
        deviceControl &= ~0x70;
        deviceControl |= 0x58;
        pciDevice->configWrite8(0x69, deviceControl);

        WriteReg8(Config4, ReadReg8(Config4) & ~(1 << 0));
    } else if (tp->mcfg == CFG_METHOD_3) {
        WriteReg8(Config3, ReadReg8(Config3) & ~Beacon_en);
        
        deviceControl = pciDevice->configRead8(0x69);
        deviceControl &= ~0x70;
        deviceControl |= 0x58;
        pciDevice->configWrite8(0x69, deviceControl);

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
            
            rtl8168_mdio_write(tp, 0x1F, 0x0007);
            rtl8168_mdio_write(tp, 0x1E, 0x002C);
            gphy_val = rtl8168_mdio_read(tp, 0x16);
            gphy_val |= BIT_10;
            rtl8168_mdio_write(tp, 0x16, gphy_val);
            rtl8168_mdio_write(tp, 0x1F, 0x0005);
            rtl8168_mdio_write(tp, 0x05, 0x8B80);
            gphy_val = rtl8168_mdio_read(tp, 0x06);
            gphy_val |= BIT_7;
            rtl8168_mdio_write(tp, 0x06, gphy_val);
            rtl8168_mdio_write(tp, 0x1F, 0x0000);
        }
    }
    switch (tp->mcfg) {
        case CFG_METHOD_25:
            rtl8168_mac_ocp_write(tp, 0xD3C0, 0x0B00);
            rtl8168_mac_ocp_write(tp, 0xD3C2, 0x0000);
            break;
        case CFG_METHOD_29:
        case CFG_METHOD_30:
            rtl8168_mac_ocp_write(tp, 0xE098, 0x0AA2);
            break;
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            rtl8168_mac_ocp_write(tp, 0xE098, 0xC302);
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            if (tp->aspm) {
                rtl8168_init_pci_offset_180(tp);
            }
            break;
    }
    tp->cp_cmd &= ~(EnableBist | Macdbgo_oe | Force_halfdup | Force_rxflow_en | Force_txflow_en | Cxpl_dbg_sel | ASF | Macdbgo_sel);
    tp->cp_cmd |= (RxChkSum | RxVlan);
    WriteReg16(CPlusCmd, tp->cp_cmd);
    ReadReg16(CPlusCmd);
    
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
        case CFG_METHOD_30:
        case CFG_METHOD_31:
        case CFG_METHOD_32: {
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
    WriteReg16(RxMaxSize, mtu + (ETH_HLEN + ETH_FCS_LEN));
    
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
    int use_default = 0;

    if (tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30 ||
        tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) {
        /* Disable Giga Lite. */
        rtl8168_mdio_write(tp, 0x1F, 0x0A42);
        rtl8168_clear_eth_phy_bit(tp, 0x14, BIT_9);
        
        if (tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32)
                rtl8168_clear_eth_phy_bit(tp, 0x14, BIT_7);

        rtl8168_mdio_write(tp, 0x1F, 0x0A40);
        rtl8168_mdio_write(tp, 0x1F, 0x0000);
    }
    if ((speed != SPEED_1000) && (speed != SPEED_100) && (speed != SPEED_10)) {
        speed = SPEED_1000;
        duplex = DUPLEX_FULL;
        autoneg = AUTONEG_ENABLE;
        use_default = 1;
    }
    autoNego = rtl8168_mdio_read(tp, MII_ADVERTISE);
    autoNego &= ~(ADVERTISE_10HALF | ADVERTISE_10FULL | ADVERTISE_100HALF | ADVERTISE_100FULL | ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);
    
    gigaCtrl = rtl8168_mdio_read(tp, MII_CTRL1000);
    gigaCtrl &= ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL);
    
    if (tp->HwHasWrRamCodeToMicroP == TRUE) {
        if ((tp->eee_enabled) && (linuxData.eee_adv_t != 0)) {
            rtl8168_enable_EEE(tp);
            DebugLog("Enable EEE support.\n");
        } else {
            rtl8168_disable_EEE(tp);
            DebugLog("Disable EEE support.\n");
        }
    }
    if (autoneg == AUTONEG_ENABLE) {
        /* n-way force */
        if (speed == SPEED_1000) {
            if (use_default) {
                /* The default medium has been selected. */
                gigaCtrl |= ADVERTISE_1000HALF | ADVERTISE_1000FULL;
                autoNego |= ADVERTISE_100HALF | ADVERTISE_100FULL | ADVERTISE_10HALF | ADVERTISE_10FULL;
            } else {
                if (duplex == DUPLEX_HALF) {
                    gigaCtrl |= ADVERTISE_1000HALF;
                } else {
                    gigaCtrl |= ADVERTISE_1000FULL;
                }
            }
        } else if (speed == SPEED_100) {
            if (duplex == DUPLEX_HALF) {
                autoNego |= ADVERTISE_100HALF;
            } else {
                autoNego |=  ADVERTISE_100FULL;
            }
        } else { /* speed == SPEED_10 */
            if (duplex == DUPLEX_HALF) {
                autoNego |= ADVERTISE_10HALF;
            } else {
                autoNego |= ADVERTISE_10FULL;
            }
        }
        
        /* Set flow control support. */
        if (flowCtl == kFlowControlOn)
            autoNego |= ADVERTISE_PAUSE_CAP|ADVERTISE_PAUSE_ASYM;
        
        tp->phy_auto_nego_reg = autoNego;
        tp->phy_1000_ctrl_reg = gigaCtrl;
        
        /* Setup EEE advertisement. */
        if (eeeCap) {
            if ((tp->mcfg >= CFG_METHOD_14) && (tp->mcfg < CFG_METHOD_21)) {
                rtl8168_mdio_write(&linuxData, 0x0D, 0x0007);
                rtl8168_mdio_write(&linuxData, 0x0E, 0x003C);
                rtl8168_mdio_write(&linuxData, 0x0D, 0x4007);
                rtl8168_mdio_write(&linuxData, 0x0E, linuxData.eee_adv_t);
                rtl8168_mdio_write(tp, 0x1F, 0x0000);
            }
        }
        rtl8168_mdio_write(tp, MII_ADVERTISE, autoNego);
        rtl8168_mdio_write(tp, MII_CTRL1000, gigaCtrl);
        rtl8168_mdio_write(tp, MII_BMCR, BMCR_RESET | BMCR_ANENABLE | BMCR_ANRESTART);
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
        
        rtl8168_mdio_write(tp, 0x1f, 0x0000);
        rtl8168_mdio_write(tp, MII_BMCR, force);
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
    struct rtl8168_private *tp = &linuxData;
    UInt8 retVal = 0;
    
    if (tp->mcfg == CFG_METHOD_20 || tp->mcfg == CFG_METHOD_26 ||
        tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) {
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
    struct rtl8168_private *tp = &linuxData;

    if (tp->mcfg == CFG_METHOD_20 || tp->mcfg == CFG_METHOD_26 ||
        tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) {
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            csi_tmp = rtl8168_eri_read(baseAddr, 0x3F2, 2, ERIAR_ExGMAC);
            csi_tmp &= ~( BIT_8 | BIT_9  | BIT_10 | BIT_11  | BIT_12  | BIT_13  | BIT_14 | BIT_15 );
            csi_tmp |= ( BIT_9 | BIT_10 | BIT_13  | BIT_14 | BIT_15 );
            rtl8168_eri_write(baseAddr, 0x3F2, 2, csi_tmp, ERIAR_ExGMAC);
            csi_tmp = rtl8168_eri_read(baseAddr, 0x3F5, 1, ERIAR_ExGMAC);
            csi_tmp |= BIT_6 | BIT_7;
            rtl8168_eri_write(baseAddr, 0x3F5, 1, csi_tmp, ERIAR_ExGMAC);
            rtl8168_mac_ocp_write(tp, 0xE02C, 0x1880);
            rtl8168_mac_ocp_write(tp, 0xE02E, 0x4880);
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_26:
            rtl8168_eri_write(baseAddr, 0x5C0, 1, 0xFA, ERIAR_ExGMAC);
            break;
    }
    
    switch (tp->mcfg) {
        case CFG_METHOD_26:
            if (tp->org_pci_offset_99 & BIT_2) {
                csi_tmp = rtl8168_eri_read(baseAddr, 0x5C8, 1, ERIAR_ExGMAC);
                csi_tmp |= BIT_0;
                rtl8168_eri_write(baseAddr, 0x5C8, 1, csi_tmp, ERIAR_ExGMAC);
            }
            break;
        case CFG_METHOD_29:
        case CFG_METHOD_30:
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            if (tp->org_pci_offset_99 & BIT_2)
                rtl8168_mac_ocp_write(tp, 0xE0A2,  rtl8168_mac_ocp_read(tp, 0xE0A2) | BIT_0);
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
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
        tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28 ||
        tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) {
        rtl8168_eri_write(baseAddr, 0x2F8, 2, 0x0064, ERIAR_ExGMAC);
    }
    
    if (tp->bios_setting & BIT_28) {
        if (tp->mcfg == CFG_METHOD_18 || tp->mcfg == CFG_METHOD_19 ||
            tp->mcfg == CFG_METHOD_20) {
            u32 gphy_val;
            
            rtl8168_mdio_write(tp, 0x1F, 0x0000);
            rtl8168_mdio_write(tp, 0x04, 0x0061);
            rtl8168_mdio_write(tp, 0x09, 0x0000);
            rtl8168_mdio_write(tp, 0x00, 0x9200);
            rtl8168_mdio_write(tp, 0x1F, 0x0005);
            rtl8168_mdio_write(tp, 0x05, 0x8B80);
            gphy_val = rtl8168_mdio_read(tp, 0x06);
            gphy_val &= ~BIT_7;
            rtl8168_mdio_write(tp, 0x06, gphy_val);
            mdelay(1);
            rtl8168_mdio_write(tp, 0x1F, 0x0007);
            rtl8168_mdio_write(tp, 0x1E, 0x002C);
            gphy_val = rtl8168_mdio_read(tp, 0x16);
            gphy_val &= ~BIT_10;
            rtl8168_mdio_write(tp, 0x16, gphy_val);
            rtl8168_mdio_write(tp, 0x1F, 0x0000);
        }
    }
    if (tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32) {
        rtl8168_set_dash_other_fun_dev_state_change(tp, 3, 0xFD);
    }
    setPCI99_180ExitDriverPara();
    
    /*disable ocp phy power saving*/
    if (tp->mcfg == CFG_METHOD_25 || tp->mcfg == CFG_METHOD_26 ||
        tp->mcfg == CFG_METHOD_27 || tp->mcfg == CFG_METHOD_28 ||
        tp->mcfg == CFG_METHOD_29 || tp->mcfg == CFG_METHOD_30 ||
        tp->mcfg == CFG_METHOD_31 || tp->mcfg == CFG_METHOD_32)
        if (!tp->dash_printer_enabled)
            rtl8168_disable_ocp_phy_power_saving(tp);

    rtl8168_disable_rxdvgate(tp);
}

void RTL8111::sleepRxEnable()
{
    struct rtl8168_private *tp = &linuxData;

    if ((tp->mcfg == CFG_METHOD_1) || (tp->mcfg == CFG_METHOD_2)) {
        WriteReg8(ChipCmd, CmdReset);
        WriteReg8(ChipCmd, CmdRxEnb);
    } else if (tp->mcfg == CFG_METHOD_14 || tp->mcfg == CFG_METHOD_15) {
        rtl8168_ephy_write(baseAddr, 0x19, 0xFF64);
        WriteReg32(RxConfig, ReadReg32(RxConfig) | AcceptBroadcast | AcceptMulticast | AcceptMyPhys);
    }
}

UInt16 RTL8111::getEEEMode()
{
    struct rtl8168_private *tp = &linuxData;
    UInt16 eee = 0;
    UInt16 sup, adv, lpa, ena;

    if (eeeCap) {
        if (tp->mcfg >= CFG_METHOD_27) {
            rtl8168_mdio_write(tp, 0x1F, 0x0A5C);
            sup = rtl8168_mdio_read(tp, 0x12);
            DebugLog("EEE supported: %u\n", sup);

            rtl8168_mdio_write(tp, 0x1F, 0x0A5D);
            adv = rtl8168_mdio_read(tp, 0x10);
            DebugLog("EEE advertised: %u\n", adv);

            lpa = rtl8168_mdio_read(tp, 0x11);
            DebugLog("EEE link partner: %u\n", lpa);

            ena = rtl8168_eri_read(baseAddr, 0x1B0, 2, ERIAR_ExGMAC);
            ena &= BIT_1 | BIT_0;
            DebugLog("EEE enabled: %u\n", ena);

            rtl8168_mdio_write(tp, 0x1F, 0x0000);
            
            eee = (sup & adv & lpa);
        } else {
            rtl8168_mdio_write(&linuxData, 0x0D, 0x0007);
            rtl8168_mdio_write(&linuxData, 0x0E, 0x003D);
            rtl8168_mdio_write(&linuxData, 0x0D, 0x4007);
            eee = (rtl8168_mdio_read(&linuxData, 0x0E) & linuxData.eee_adv_t);
            rtl8168_mdio_write(tp, 0x0D, 0x0000);
        }
    }
    return eee;
}
void RTL8111::exitOOB()
{
    struct rtl8168_private *tp = &linuxData;
    u16 data16;
    
    WriteReg32(RxConfig, ReadReg32(RxConfig) & ~(AcceptErr | AcceptRunt | AcceptBroadcast | AcceptMulticast | AcceptMyPhys |  AcceptAllPhys));
    
    //Disable realwow  function
    switch (tp->mcfg) {
        case CFG_METHOD_18:
        case CFG_METHOD_19:
            WriteReg32(MACOCP, 0xE5A90000);
            WriteReg32(MACOCP, 0xF2100010);
            break;
        case CFG_METHOD_20:
            WriteReg32(MACOCP, 0xE5A90000);
            WriteReg32(MACOCP, 0xE4640000);
            WriteReg32(MACOCP, 0xF2100010);
            break;
        case CFG_METHOD_21:
        case CFG_METHOD_22:
            WriteReg32(MACOCP, 0x605E0000);
            WriteReg32(MACOCP, (0xE05E << 16) | (ReadReg32(MACOCP) & 0xFFFE));
            WriteReg32(MACOCP, 0xE9720000);
            WriteReg32(MACOCP, 0xF2140010);
            break;
        case CFG_METHOD_26:
            WriteReg32(MACOCP, 0xE05E00FF);
            WriteReg32(MACOCP, 0xE9720000);
            rtl8168_mac_ocp_write(tp, 0xE428, 0x0010);
            break;
    }
    
#ifdef ENABLE_REALWOW_SUPPORT
    rtl8168_realwow_hw_init(dev);
#else
    switch (tp->mcfg) {
        case CFG_METHOD_21:
        case CFG_METHOD_22:
            rtl8168_eri_write(baseAddr, 0x174, 2, 0x0000, ERIAR_ExGMAC);
            rtl8168_mac_ocp_write(tp, 0xE428, 0x0010);
            break;
        case CFG_METHOD_24:
        case CFG_METHOD_25:
        case CFG_METHOD_26:
        case CFG_METHOD_28:
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            rtl8168_eri_write(baseAddr, 0x174, 2, 0x00FF, ERIAR_ExGMAC);
            rtl8168_mac_ocp_write(tp, 0xE428, 0x0010);
            break;
        case CFG_METHOD_29:
        case CFG_METHOD_30: {
            u32 csi_tmp;
            csi_tmp = rtl8168_eri_read(baseAddr, 0x174, 2, ERIAR_ExGMAC);
            csi_tmp &= ~(BIT_8);
            csi_tmp |= (BIT_15);
            rtl8168_eri_write(baseAddr, 0x174, 2, csi_tmp, ERIAR_ExGMAC);
            rtl8168_mac_ocp_write(tp, 0xE428, 0x0010);
        }
            break;
    }
#endif //ENABLE_REALWOW_SUPPORT
    
    rtl8168_nic_reset(tp);
    
    switch (tp->mcfg) {
        case CFG_METHOD_20:
            rtl8168_wait_ll_share_fifo_ready(tp);
            
            data16 = rtl8168_mac_ocp_read(tp, 0xD4DE) | BIT_15;
            rtl8168_mac_ocp_write(tp, 0xD4DE, data16);
            
            rtl8168_wait_ll_share_fifo_ready(tp);
            break;
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
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            rtl8168_disable_now_is_oob(tp);
            
            data16 = rtl8168_mac_ocp_read(tp, 0xE8DE) & ~BIT_14;
            rtl8168_mac_ocp_write(tp, 0xE8DE, data16);
            rtl8168_wait_ll_share_fifo_ready(tp);
            
            data16 = rtl8168_mac_ocp_read(tp, 0xE8DE) | BIT_15;
            rtl8168_mac_ocp_write(tp, 0xE8DE, data16);
            
            rtl8168_wait_ll_share_fifo_ready(tp);
            break;
    }
    
    //wait ups resume (phy state 2)
    switch (tp->mcfg) {
        case CFG_METHOD_29:
        case CFG_METHOD_30:
        case CFG_METHOD_31:
        case CFG_METHOD_32:
            if (rtl8168_is_ups_resume(tp)) {
                rtl8168_wait_phy_ups_resume(tp, 2);
                rtl8168_clear_ups_resume_bit(tp);
            }
            break;
    };
    tp->phy_reg_anlpar = 0;
}


