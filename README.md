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
different port or interface (e.g. `enp0`) may be provided, e.g. to
capture UDP packets on port 1234 on network interface `enp0`:

    ./tvdump -p 1234 enp0

May require tweaks to work with other set ups.

Building
--------
Requires libpcap.

    make
    make install   [DESTDIR=] [PREFIX=/usr/local]
    make uninstall [DESTDIR=] [PREFIX=/usr/local]

Author
------
Sijmen J. Mulder (<ik@sjmulder.nl>)
