# can2tcp

A simple gateway for bridging local virtual CAN interface with remote CAN bus connected through an IP gateway,
like [Waveshare 2-ch-can-to-eth](https://www.waveshare.com/2-ch-can-to-eth.htm).

```
usage: can2tcp [-h] [-i INTERFACE] [--host HOST] [--port PORT]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        CAN interface name
  --host HOST           TCP gateway hostname/IP
  --port PORT           TCP gateway port
```
