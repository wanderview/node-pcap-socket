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

## Class PcapSocket

The PcapSocket class inherits from `Duplex`.  Therefore it provides
both streaming `Readable` and `Writable` interfaces.

### new PcapSocket(pcapSource, address, opts)

* `pcapSource` {String | Stream} If a String, pcapSource is interpreted as
  the name of a pcap file to read from.  Otherwise `pcapSource` is treated
  as a stream providing pcap data.
* `address` {String} An IP address used in the pcap file.  The socket will
  act as that IP address.  Packets sent to this address will be available
  on the socket's `read()` method.
* `opts` {Object | null} Optional parameters
  * `autoHalt` {Boolean} If set to true the socket will automatically `halt()`
    when it sees TCP data sent from the configured local address.  This is
    intended to allow test code the opportunity to read from the `response`
    stream.  Once the response has been verified correct, call `proceed()`
    to restart the flow of data.  Defaults to false.

### psocket.halt()

Stop the flow of data.  While halted, no new data will be buffered to be
returned by the `read()` function.  To start the flow of data again, use
`proceed()`.

The term halt is used since `pause()` is associated with the old style
`stream` API.

### psocket.resume()

Start the flow of data again after `halt()` has been used to stop it.

The term proceed is used since `resume()` is associated with the old style
`stream` API.
