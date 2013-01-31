# pcap-socket

Mock TCP socket based on pcap file data.

This module is a pure JavaScript implementation built on top of the
[pcap-parser][] module.

[![Build Status](https://travis-ci.org/wanderview/node-pcap-socket.png)](https://travis-ci.org/wanderview/node-pcap-socket)

## Example

```javascript
var PcapSocket = require('pcap-socket');

// Pretend to be 192.168.1.1 and receive packets from pcapFileName destined
// for that address.
var psock = new PcapSocket(pcapFileName, '192.168.1.1');

// Based on streams2 API
psock.on('readable', function() {
  var chunk = psock.read();

  // Perform your processing on TCP data stream
});
psock.read(0);

// Bytes written to psock will appear on a response stream
psock.response.on('readable', function() {
  var chunk = psock.response.read();

  // Validate response is correct
});
psock.response.read(0);
```

## TODO

* Implement various other net.Socket() features like `localAddress`,
  `localPort`, etc.  Pretty much this only provides the stream API at the
  moment.
* Do something more intelligent with duplicate and out-of-order TCP packets.
* Develop better example showing bi-directional interactions.

[pcap-parser]: http://www.github.com/nearinfinity/node-pcap-parser
