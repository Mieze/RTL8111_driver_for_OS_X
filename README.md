RTL8111 Driver for OS X
=======================

OS X open source driver for the Realtek RTL8111/8168 family

*** Please note that this driver isn't maintained by Realtek! ***

Due to the lack of an OS X driver that makes use of the advanced features of the Realtek RTL81111/8168 series I started a new project with the aim to create a state of the art driver that gets the most out of those NICs which can be found on virtually any cheap board on the market today. Based on Realtek's Linux driver (version 8.035.0) I have written a driver that is optimized for performance while making efficient use of system resources and keeping the CPU usage down under heavy load.

Key Features of the Driver
- Supports Realtek RTL8111/8168 B/C/D/E/F/G found on recent boards.
- Support for multisegment packets relieving the network stack of unnecessary copy operations when assembling packets for transmission.
- No-copy receive and transmit. Only small packets are copied on reception because creating a copy is more efficient than allocating a new buffer.
TCP, UDP and IPv4 checksum offload (receive and transmit).
- TCP segmentation offload over IPv4 and IPv6.
- Support for TCP/IPv6 and UDP/IPv6 checksum offload.
- Fully optimized for Mountain Lion (64bit architecture) but should work with Lion too. Snow Leopard requies some changes.
- Supports Wake on LAN.
- Support for Energy Efficient Ethernet (EEE) which can be disabled by setting enableEEE to NO in the drivers Info.plist without rebuild. The default is YES.
- The driver is published under GPLv2.

Limitations
- As checksum offload doesn't work with jumbo frames they are currently unsupported and will probably never be.
- No support for 32bit kernels.

Installation

Before you install the driver you have to remove any installed driver for RTL8111/8168.

- Goto /S/L/E and delete the old driver (Lnx2mac, AppleRealtekRTL8169, etc.).
    
- Recreate the kernel cache.
    
- Open System Preferences and delete the corresponding network interface, e. g. en0. If you forget this step you might experience strange problems with certain Apple domains, iTunes and iCloud later.
    
- Reboot.
    
- Install the new driver and recreate the kernel cache.
    
- Reboot
    
- Open System Preferences again, select Network and check if the new network interface has been created automatically or create it manually now.
    
- Configure the interface.

Current status

The driver has been successfully tested under 10.8.2 - 10.8.5 and 10.9 with the D (chipset 9), E (chipset 16) and F (chipset 17) versions of the RTL8111 and is known to work stable on these devices but you'll have to consider that there are 25 different revisions of the RTL8111. The RTL8111B/8168B chips have been reported to work since version 1.0.2 too.

Changelog

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

Known Issues
- There are still performance problems with regard to SMB in certain configurations. My tests indicate that Apple's Broadcom driver shows the same behavior with those configurations. Obviously it's a more general problem that is not limited to my driver.
- WoL refuses to work on some machines.

Building from Source

I'm using XCode 4.6.3 for development. You can get a free copy of XCode after becoming a member of the Apple developer program. The free membership is sufficient in order to get access to development tools and documentation.
