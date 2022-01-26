tvcap
=====
Capture and dump multicast IPTV streams.

My TV provider KPN uses multicast for live TV on their set top box.
This stream can be captured with a packet sniffer and stored or piped
to a video player:

    sudo ./tvdump | mpv -

May require tweaks to work with other set ups.

Building
--------
Requires libpcap.

    make

Author
------
Sijmen J. Mulder (<ik@sjmulder.nl>)
