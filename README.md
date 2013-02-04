# pcap-socket

Mock TCP socket based on pcap file data.

This module is a pure JavaScript implementation built on top of the
[pcap-parser][] module.

[![Build Status](https://travis-ci.org/wanderview/node-pcap-socket.png)](https://travis-ci.org/wanderview/node-pcap-socket)

## Example

Here is an example test case using a recorded HTTP request to verify that
the typical node.js hello world server responds correctly.

```javascript
'use strict';

var PcapSocket = require('pcap-socket');

var http = require('http');
var path = require('path');

module.exports.http = function(test) {
  test.expect(3);

  var msg = 'Hello World\n';

  // Setup an HTTP server to test
  var server = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(msg);
  });

  // Configure the pcap socket to provide real, recorded network data
  var file = path.join(__dirname, 'data', 'http-session-winxp.pcap');
  var psocket = new PcapSocket(file, '10.0.1.6');

  // When the server sends back a packet, validate that it makes sense
  psocket.output.on('readable', function() {
    var chunk = psocket.output.read();
    if (chunk) {
      var str = chunk.toString();

      test.ok(str.match(/HTTP\/1.1 200 OK/));
      test.ok(str.match(/Content-Type: text\/plain/));
      test.ok(str.match(new RegExp(msg)));

      test.done();
    }
  });
  psocket.output.read(0);

  // Supply the pcap socket to the HTTP server as a new connection
  server.emit('connection', psocket);
};
```

## Limitations / TODO

* Only supports IPv4 at the moment.
* Do something more intelligent with duplicate and out-of-order TCP packets.
  Currently packets are delivered as they are seen by pcap.  No attempt is
  made to de-duplicate or re-order packets.

## Class PcapSocket

The PcapSocket class inherits from `Duplex`.  Therefore it provides
both streaming `Readable` and `Writable` interfaces.

Calling `read()` will return bytes sent to the configured address in the
pcap file.

Calling `write()` will direct bytes to the `output` stream.  This allows
your test code to monitor the `output` stream to validate that your
code is sending the correct values.

Note, while PcapSocket uses the new streams2 API provided in node 0.9.6
and greater, this class should still work in older versions of node.  This
backward compatibility is implemented using the [readable-stream][] module.

### var psock = new PcapSocket(pcapSource, address, opts)

* `pcapSource` {String | Stream} If a String, pcapSource is interpreted as
  the name of a pcap file to read from.  Otherwise `pcapSource` is treated
  as a stream providing pcap data.
* `address` {String} An IPv4 address used in the pcap file.  The socket will
  act as that IP address.  Packets sent to this address will be available
  on the socket's `read()` method.
* `opts` {Object | null} Optional parameters
  * `localPort` {Number | null} The TCP port associated with the `address`
    passed as the second argument.  Packets sent to this port at the given
    address wil be available on the socket's `read()` method.  If not
    provided then the port will be automatically set to the port used on
    the first TCP packet with data.
  * `remoteAddress` {String | null}  The IPv4 address of the remote peer in
    the pcap file's TCP session.  Only packets originating from this address
    will be available via `read()`.  If not set, then the address will be
    automatically configured based on the first TCP packet with data.
  * `remotePort` {Number | null}  The TCP port number of the remote pper in
    the pcap file's TCP session.  Only packets originating from this port
    will be available via `read()`.  If not set, then port will be
    automatically configured based on the first TCP packet with data.

### psock.output

The `output` property provides a `PassThrough` stream.  All data passed to
the `write()` function will be directed into this stream.  This allows test
code to validate that the code using the socket writes out the correct
values.

### psock.address(), psock.localAddress, psock.localPort, psock.remoteAddress, psock.remotePort

These properties are provided in order to maintain compatibility with the
[net.Socket][] API.

If the `localPort`, `remoteAddress`, or `remotePort` are not set via the
constructor options, then they will default to either the address `'0.0.0.0'`
or port `0`.  Once a packet is processed they will then represent the
selected TCP session addresses and ports.

If the properties changing is a problem for your code or tests, then make
sure to set the addresses and ports via the constructor options.

### psock.bytesRead, psock.bytesWritten

These properties are provided in order to maintain compatibility with the
[net.Socket][] API.  They should work as expected.

### pcock.setTimeout(), psock.setNoDelay(), psock.setKeepAlive(), psock.unref(), psock.ref()

These functions are provided in order to maintain compatibility with the
[net.Socket][] API.  They are only stubs and effectively do nothing.

[readable-stream]: https://github.com/isaacs/readable-stream
[net.Socket]: http://nodejs.org/api/net.html#net_class_net_socket
[pcap-parser]: http://www.github.com/nearinfinity/node-pcap-parser
