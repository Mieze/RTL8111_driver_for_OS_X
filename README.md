RTL8111 Driver for OS X
=======================

OS X open source driver for the Realtek RTL8111/8168 family


Due to the lack of an OS X driver that makes use of the advanced features of the Realtek RTL81111/8168 series I started a new project with the aim to create a state of the art driver that gets the most out of those NICs which can be found on virtually any cheap board on the market today. Based on Realtek's Linux driver (version 8.035.0) I have written a driver that is optimized for performance while making efficient use of system resources and keeping the CPU usage down under heavy load.

<b>Key Features of the Driver</b>
- Supports Realtek RTL8111/8168 B/C/D/E/F/G/H found on recent boards.
- Support for multisegment packets relieving the network stack of unnecessary copy operations when assembling packets for transmission.
- No-copy receive and transmit. Only small packets are copied on reception because creating a copy is more efficient than allocating a new buffer.
TCP, UDP and IPv4 checksum offload (receive and transmit).
- TCP segmentation offload over IPv4 and IPv6.
- Support for TCP/IPv6 and UDP/IPv6 checksum offload.
- Fully optimized for Mountain Lion (64bit architecture) but should work with Lion too. Snow Leopard requies some changes.
- Supports Wake on LAN.
- Support for Energy Efficient Ethernet (EEE) which can be disabled by setting enableEEE to NO in the drivers Info.plist without rebuild. The default is YES.
- The driver is published under GPLv2.

<b>Limitations</b>
- As checksum offload doesn't work with jumbo frames on older versions of the RTL8111, jumbo frames are only supported on chiset 16 (RTL8111E-VL) and above.
- No support for 32bit kernels.

<b>Support</b>

In case you have questions, need support or want to submit a problem report, please refer to the driver's thread on insanelymac.com: https://www.insanelymac.com/forum/topic/287161-new-driver-for-realtek-rtl8111/

<b>Support requests here on Github will be ignored!</b>


<b>Installation</b>

Before you install the driver you have to remove any installed driver for RTL8111/8168.

- Goto /S/L/E and delete the old driver (Lnx2mac, AppleRealtekRTL8169, etc.).
    
- Recreate the kernel cache.
    
- Open System Preferences and delete the corresponding network interface, e. g. en0. If you forget this step you might experience strange problems with certain Apple domains, iTunes and iCloud later.
    
- Reboot.
    
- Install the new driver and recreate the kernel cache.
    
- Reboot
    
- Open System Preferences again, select Network and check if the new network interface has been created automatically or create it manually now.
    
- Configure the interface.

<b>Current status</b>

The driver has been successfully tested under 10.8.2 - 11.3 with serveral versions of the RTL8111 and is known to work stable on these devices but you'll have to consider that there are more than 30 different revisions of the RTL8111. The RTL8111B/8168B chips have been reported to work since version 1.0.2 too.

<b>Changelog</b>

- Version 2.3.0 (2020-08-14)
    - Reworked medium section and EEE support to resolve problems with connection establishment and stability.
    - Added option to supply a fallback MAC.
    - Updated Linux sources to 8.047.04 and added support for new family members
    - Requires 10.14 or newer.
- Version 2.2.2 (2018-01-21)
    - Force ASPM state to disabled/enabled according to the config parameter setting.
    - Requires 10.12 or newer.
- Version 2.2.1 (2016-03-12):
    - Updated underlying linux sources from Realtek to 8.041.00.
    - Added support for RTL8111H.
    - Implemented Apple’s polled receive driver model (RXPOLL).
    - Requires 10.11 or newer. Support for older versions of OS X has been dropped.
- Version 2.2.0d0 (2016-02-06):
    - Improved media selection and reporting (flow control and EEE).
    - Updated Linux sources to 8.041.000.
- Version 2.0.0 (2015-07-14):
    - Replaced Apple headers with those from IONetworkingFamily-85.2 to fix compatibility issues with Mountain Lion.
- Version 2.0.0 (2015-06-21):
    - Uses Apple's private driver interface introduced with 10.8.
    - Supports packet scheduling with QFQ.
    - Please note that 2.0.0 is identical to 2.0.0d2. Only the version number has changed.
- Version 1.2.3 (2014-08-23):
    - Reworked TSO4 and added support for TSO6.
- Version 1.2.2 (2014-08-14):
    - Added an option to disable ASPM (default disabled) as it seems to result in unstable operation of some chipsets.
    - Resolved a problem with Link Aggregation after reboot.
    - Added a workaround for the Multicast filter bug of chipset 17 (RTL8111F) which prevented Bonjour from working properly.
- Version 1.0.1 (2013-03-31):
    - Improved behavior when rx checksum offload isn't working properly.
    - Adds the chipset's model name to IORegistry so that it will show up in System Profiler.
- Version 1.0.2 (2013-04-22):
    - Added support for rx checksum offload of TCP and UDP over IPv6.
- Version 1.0.3 (2013-04-25):
    - The issue after a reboot from Windows has been eliminated.
- Version 1.0.4 (2013-05-04)
    - Moved setLinkStatus(kIONetworkLinkValid) from start() to enable(). Cleaned up getDescCommand().
- Version 1.1.0 (2013-06-08):
    - Support for TCP/IPv6 and UDP/IPv6 checksum offload added (can be disabled in Info.plist).
    - Maximum size of the scatter-gather-list has been increased from 24 to 40 segments to resolve performance issues with TSO4 when offloading large packets which are highly fragmented.
    - TSO4 can be disabled in Info.plist without rebuild.
    - Statistics gathering has been improved to deliver more detailed information (resource shortages, transmitter resets, transmitter interrupt count).
    - The interrupt mitigate settings has been changed to improve performance with SMB and to reduce CPU load.
    - Configuration option added to allow for user defined interrupt mitigate settings without rebuild (see above).
- Version 1.1.1 (2013-06-29):
    - Remove ethernet CRC from received packets to fix rx checksum offload.
- Version 1.1.2 (2013-08-03):
    - Improved SMB performance in certain configurations.
    - Faster browsing of large shares.
- Version 1.1.3 (2013-11-29):
    - Improved transmit queue handling made it possible to reduce CPU load during packet transmission.
    - Improved deadlock detection logic in order to avoid false positives due to lost interrupts.
- Version 1.2.0 (2014-04-23):
    - Updated underlying linux sources from Realtek to 8.037.00. Improved interrupt mitigate to use a less aggressive value for 10/100 MBit connections.

<b>Troubleshooting</b>
- Make sure you have followed the installation instructions especially when you have issues with certain domains while the others are working fine.
- Use the debug version to collect log data when trying to track down problems. The kernel log messages can be found in /var/log/system.log. For Sierra and above use "log show --predicate "processID == 0" --debug" in order to retrieve kernel logs. Include the log data when asking for support or giving feedback. I'm an engineer, not a clairvoyant.
- Check your BIOS settings. You might want to disable Network Boot and the UEFI Network Stack as these can interfere with the driver.
- Double check that you have removed any other Realtek kext from your system because they could prevent the driver from working properly.
- Verify your bootloader configuration, in particular the kernel flags. Avoid using npci=0x2000 or npci=0x3000. 
- In Terminal run netstat -s in order to display network statistics. Carefully examine the data for any unusual activity like a high number of packets with bad IP header checksums, etc.
- In case auto-configuration of the link layer connection doesn't work it might be necessary to select the medium manually in System Preferences under Network for the interface.
- Use Wireshark to create a packet dump in order to collect diagnostic information.
- Keep in mind that there are many manufacturers of network equipment. Although Ethernet is an IEEE standard different implementations may show different behavior causing incompatibilities. In case you are having trouble try a different switch or a different cable.

<b>Help, I'm getting kernel panics!</b>
- Well, before you start complaining about bugs after you upgraded macOS and ask me to publish a driver update, you should first try to resolve the issue on your own by cleaning the system caches.
As the driver uses macOS's private network driver interface, which is supposed to be used by Apple provided drivers only, you might run into problems after an OS update because the linker may fail to recognize that IONetworking.kext has been updated and that the driver needs to be linked against the new version (Apple provided drivers avoid this problem because they are always updated together with IONetworking.kext). As a result, the linking process produces garbage and the driver may call arbitrary code when trying to call functions from IONetworking.kext. This usually results in unpredicted behavior or a kernel panic. In order to recover from such a situation, you should clean the System Caches forcing the linker to recreate it's caches:
    1. Delete all the files in /System/Library/Caches and it's subdirectories but leave the directories and the symbolic links intact. This is very important!
    2. Reboot.
    3. Recreate the kernel cache.
    4. Reboot again.
    
<b>FAQ</b>
- How can I retrieve the kernel logs?
    - In Terminal type "grep kernel /var/log/system.log".
- WoL from S5 doesn't work with this driver but under Windows it's working. Is this a driver bug?
    - No it isn't, the driver is working as it should because OS X doesn't support WoL from S5.
 
<b>Known Issues</b>
- There are still performance problems with regard to SMB in certain configurations. My tests indicate that Apple's Broadcom driver shows the same behavior with those configurations. Obviously it's a more general problem that is not limited to my driver.
- WoL refuses to work on some machines.
- Old systems with 3 and 4 series chipsets exhibit performance issues in recent versions of macOS because there is no optimized power management for these systems in macOS anymore as Apple dropped support for the underlying hardware a long time ago. In case you are affected, please upgrade your hardware or find an alternative solution because I have no plans for a workaround. Sorry, but I don't think that it's worth the effort.

<b>Building from Source</b>

I'm always using the latest version of XCode for development. You can get a free copy of XCode after becoming a member of the Apple develop﻿er program. The free membership is sufficient in order to get access to development tools and documentation.

