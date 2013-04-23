RTL8111_driver_for_OS_X
=======================

OS X open source driver for the Realtek RTL8111/8168 family

*** Please note that this driver isn't maintained by Realtek! ***

Due to the lack of an OS X driver that makes use of the advanced features of the Realtek RTL81111/8168 series I started a new project with the aim to create a state of the art driver that gets the most out of those NICs which can be found on virtually any cheap board on the market today. Based on Realtek's Linux driver (version 8.035.0) I have written a driver that is optimized for performance while making efficient use of system resources and keeping the CPU usage down under heavy load.

Key Features of the Driver
- Supports Realtek RTL8111/8168 C/D/E/F/G found on recent boards.
- Support for multisegment packets relieving the network stack of unnecessary copy operations when assembling packets for transmission.
- No-copy receive and transmit. Only small packets are copied on reception because creating a copy is more efficient than allocating a new buffer.
TCP, UDP and IPv4 checksum offload (receive and transmit).
- TCP segmentation offload under IPv4.
- Fully optimized for Mountain Lion (64bit architecture) but should work with Lion too. Snow Leopard requies some changes.
- Supports Wake on LAN.
- Support for Energy Efficient Ethernet (EEE) which can be disabled by setting enableEEE to NO in the drivers Info.plist without rebuild. The default is YES.
- The driver is published under GPLv2.

Limitations
- Support for the Realtek RTL8111B/8168B is still experimental and might not work at all. Therefore it is only included in debug builds and has never been tested successfully because I don't have access to a board with one of these outdated chips.
- As checksum offload doesn't work with jumbo frames they are currently unsupported and will probably never be.
- No support for 32bit kernels.

Installation

Before you install the driver you have to remove any installed driver for RTL8111/8168.

- Goto /S/L/E and delete the old driver (Lnx2mac, AppleRealtekRTL8169, etc.).
    
- Recreate the kernel cache.
    
- Open System Preferences and delete the corresponding network interface, e. g. en0. If you forget this step you might experience strange problems with certain Apple domains, iTunes and iCloud later.
    
- Shutdown, wait for 30 seconds and reboot.
    
- Install the new driver and recreate the kernel cache.
    
- Reboot
    
- Open System Preferences again, select Network and check if the new network interface has been created automatically or create it manually now.
    
- Configure the interface.

Current status

The driver has been successfully tested under 10.8.2 and 10.8.3 with the D (chipset 9), E (chipset 16) and F (chipset 17) versions of the RTL8111 and is known to work stable on these devices but you'll have to consider that there are 25 different revisions of the RTL8111.

Changelog
- Version 1.0.1 (2013-03-31):
  - Improved behavior when rx checksum offload isn't working properly.
  - Adds the chipset's model name to IORegistry so that it will show up in System Profiler.

Known Issues
- The code for RTL8111B/8168B NICs is untested and will probably not work as expected.
- Eventually you might find a "Ethernet [RealtekRTL8111]: replaceOrCopyPacket() failed." message in the log file. This is nothing to worry about and means that a single packet has been dropped because the driver failed to allocate a new packet buffer. Packet buffers are allocated from a buffer pool which is dynamically sized by the network stack. When the pool is exhausted the OS increases it's size making the error a self-healing issue.

Building from Source

I'm using XCode 4.4.1 for development. You can get a free copy of XCode after becoming a member of the Apple developer program. The free membership is sufficient in order to get access to development tools and documentation.
