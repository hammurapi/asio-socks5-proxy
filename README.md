# BOOST_SOCKS5 Proxy Server

## Description
This is simple realization of socks5 proxy server according to the [RFC 1928](https://www.ietf.org/rfc/rfc1928.txt) using `asio` library. The server uses async socket calls for data forwarding and io_context for message processing. Currently, boost_socks5 proxy server works only in `NO AUTHENTICATION REQUIRED` mode.

## Build
The proxy server build was tested with boost version 1.58. However, earlier versions of boost will probably work as well.

### Linux
To build on Linux install Boost library and run the following command:
```bash
g++ -Wall -std=c++11 boost_socks5.cpp -o boost_socks5 -lboost_system -lboost_thread -lpthread
```
### Windows 

#### To build on Windows (mingw-w64)
Run the following command:
```bash
g++ -Wall -std=c++11 -I <Path_to_Boost_Include> boost_socks5.cpp -o boost_socks5 -static -L <Path_to_Boost_Libs> -lboost_system -lboost_thread -lwsock32 -lws2_32
```
Ignore Boost std::auto_ptr warnings if any.

#### To build on Windows (MS Visual Studio)
Run ‘Developer Command Prompt for VS2015’ and use the following command:
```bat
cl /EHsc /MD /I <Path_to_Boost_Include> /Feboost_socks5.exe boost_socks5.cpp /link /LIBPATH:<Path_to_Boost_Libs>
```

## Config file
Currently, configuration file contains the following settings:
* port – which the server listens for incoming client connections 
* buffer_size – size of data transferring buffers. Do not make this value too small because it will greatly increase the number of read/write calls when forwarding huge amount of data
* verbose - verbosity level (0 – errors only, 1 - connect/disconnect, 2 - traffic packets size)
* 

## Testing

Setup chrome to use the socks proxy from localhost

```bat
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --proxy-server="socks5://localhost:1088"
```
