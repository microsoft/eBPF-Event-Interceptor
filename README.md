# eBPF Event Interceptor
Network Event Tracers for Linux using eBPF (BCC).

## Requirements
* BPF Compiler Collection ([BCC](https://github.com/iovisor/bcc))<br>
  The included `Cmake` sets up `BCC` for Ubuntu 20.04, 18.04 etc. If your distro is another flavor, [install BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md) as appropriate to your setup. 
 * `cmake`, setup on Ubuntu 20.04 as:
```bash 
sudo apt install -y build-essential cmake 
```
## Install and Compile


```bash 
git clone https://github.com/microsoft/eBPF-Event-Interceptor.git
mkdir ebpfInterceptor/build && cd ebpfInterceptor/build 
cmake ../
make -j`nproc --ignore=1`
sudo make install
```


Available build options:

    -DSETUP_TESTS=ON         Setup Tests. [default=OFF]

### Test builds:
```
$  cmake -DSETUP_TESTS=ON ../ && make -j`nproc --ignore=1` && sudo make install
Found BCC
tcp Interceptor
Setting up Tests
test tcp Interceptor
udp Interceptor
Setting up Tests for UDP Tracer
test udp Interceptor
-- Configuring done
-- Generating done
-- Build files have been written to: /home/anu/git/msft/eBPF-Event-Interceptor/build
[ 50%] Built target tcpEvent
[ 50%] Built target udpEvent
[100%] Built target udpEventTest
[100%] Built target tcpEventTest
[ 25%] Built target tcpEvent
[ 50%] Built target tcpEventTest
[ 75%] Built target udpEvent
[100%] Built target udpEventTest
Install the project...
-- Install configuration: ""
-- Up-to-date: /opt/RealTimeKql/lib/libtcpEvent.so
-- Up-to-date: /tmp/tcpEventTest
-- Up-to-date: /opt/RealTimeKql/lib/libudpEvent.so
-- Up-to-date: /tmp/udpEventTest
```
Running Tests:
```bash 
$ sudo /tmp/tcpEventTest
<snip>
 ---> PID: 1177932
 ---> UID: 1000
 ---> rx_b: 2988
 ---> tx_b: 3301
 ---> tcpi_segs_out: 20
 ---> tcpi_segs_in: 18
 ---> Command: ssh
 ---> SADDR: 2001:aaa:fff:eee:ccc:a627:f45f:9c0c
 ---> DADDR: 2601:xxx:yyy:zzz:aaa:db60:46cd:971c
 ---> SPT: 58532
 ---> DPT: 22
 ---> EventTime: 1628184562000000000
<snip>

$ sudo /tmp/udpEventTest
<snip>
 ---> PID: 1180210
 ---> UID: 1000
 ---> family: 10
 ---> rx_b: 0
 ---> tx_b: 32
 ---> rxPkts: 0
 ---> txPkts: 1
 ---> Command: udpTraffic.sh
 ---> SADDR: 2001:xxx:f0:5e:aaa:a627:f45f:9c0c
 ---> DADDR: 2001:xxx:f0:5e:bbb:8d6f:32ef:6180
 ---> SPT: 42486
 ---> DPT: 53
 ---> EventTime: 1628185427077225859
<snip>
```
## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
