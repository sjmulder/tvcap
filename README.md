tvcap
=====
Capture and dump multicast IPTV streams. (Or, technically, any UDP
stream to a given port.)

**tvdump** [-p *port*] [*interface*]

![Screenshot](https://sjmulder.nl/i/tvcap.png)

My TV provider KPN uses multicast for live TV on their set top box.
This stream can be captured with a packet sniffer and stored or piped
to a video player:

    sudo ./tvdump | mpv -

By default UDP port 7252 is captured on the `any` pcap interface. A
different port or interface may be provided, e.g. to capture UDP packets
on port 1234 on network interface `enp0`:

    ./tvdump -p 1234 enp0

May require tweaks to work with other set ups.

Building
--------
Requires libpcap.

    make
    make install   [DESTDIR=] [PREFIX=/usr/local]
    make uninstall [DESTDIR=] [PREFIX=/usr/local]

Troubleshooting
---------------
If you're not getting any output, first make sure your TV box is tuned
to a live channel and that you're connected with ethernet (not WiFi!)
on the same network.

Then try using Wireshark to see if you're getting packets and on what
interface and port. KPN TV streams are about 1 MB/s so not easy to
miss.

If your box is turned on, and you are connected to ethernet, but you're
still not seeing traffic in Wireshark a switch may be doing smart
routing on the multicast signal with IGMP sniffing. Try connecting
directly to the KPN router.

Author
------
Sijmen J. Mulder (<ik@sjmulder.nl>)
