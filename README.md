<div align="center">

  <h1 align="center">DNS Server in C#</h1>

  <p align="center">
    A lightweight DNS server built from scratch in C#, capable of authoritative responses and DNS forwarding.
</div>

---

## Table of Contents

1.  [About The Project](#about-the-project)
    *   [Features](#key-features)
    *   [Tech Stack](#tech-stack)
    *   [Architecture](#architecture)
2.  [Getting Started](#getting-started)
    *   [Prerequisites](#prerequisites)
    *   [Installation](#installation)
    *   [Running the Application](#running-the-application)
3.  [Usage](#usage)
    *   [Testing with `dig`](#testing-with-dig)
4.  [Contact](#contact)
5.  [Acknowledgements](#acknowledgements)

---

## About The Project

This project is a complete, from-scratch implementation of a Domain Name System (DNS) server written entirely in C# on the .NET 9.0 platform. The primary goal is to demystify the DNS protocol by building a server that correctly handles raw UDP packets, parses DNS messages according to RFC 1035, and implements core DNS server functionality.

The server can operate in two modes:
1.  **Authoritative Mode:** Responds to any query with a hardcoded IP address.
2.  **Forwarding Mode:** Acts as a DNS forwarder, relaying queries to a real, upstream DNS resolver (like Google's `8.8.8.8` or Cloudflare's `1.1.1.1`) and returning the actual response to the client.

### Features

*   ✨ **Full DNS Packet Serialization/Deserialization:** Converts between raw byte arrays and structured C# objects, handling all header flags, sections, and big-endian byte order.
*   🔒 **DNS Name Compression Parsing:** Correctly parses domain names that use the DNS compression scheme (pointers) to reduce packet size.
*   🚀 **Dual-Mode Operation:** Can function as a simple authoritative server or a powerful forwarding server via a command-line flag.
*   ⚡ **Asynchronous Networking:** Built with modern `async/await` patterns for high-performance, non-blocking I/O using `UdpClient`.

### Tech Stack

This project uses no external dependencies.

*   **Language:** [![CSharp][CSharp-badge]][CSharp-url]
*   **Framework:** [![DotNet][DotNet-badge]][DotNet-url]

### Architecture

The application is a single command-line executable with a clean, object-oriented design.

*   **`Program.cs`:** The main entry point. Responsible for parsing command-line arguments, setting up the `UdpClient`, and running the main server loop.
*   **Data Models (`DnsMessage`, `DnsHeader`, etc.):** A set of plain C# classes that directly model the structures defined in the DNS protocol.
*   **`DnsPacketSerializer`:** A static utility class that contains all the logic for byte-level manipulation. It handles the conversion from `byte[]` to `DnsMessage` (deserialization) and from `DnsMessage` back to `byte[]` (serialization), including domain name encoding/decoding and pointer handling.

The flow is:
1. The server receives a UDP packet on port 2053.
2. The raw `byte[]` is passed to `DnsPacketSerializer` to create a `DnsMessage` object.
3. Based on the operating mode (authoritative or forwarding), a response `DnsMessage` is created.
4. The response object is serialized back into a `byte[]`.
5. The resulting UDP packet is sent back to the original client.

---

## Getting Started

Follow these instructions to get the server running on your local machine.

### Prerequisites

Ensure you have the .NET 9.0 SDK installed.

*   **.NET 9.0 SDK**
    ```sh
    dotnet --version
    ```
    You can download it from the official [.NET website](https://dotnet.microsoft.com/download/dotnet/9.0).

### Installation

1.  **Clone the repository**
    ```sh
    git clone https://github.com/QuanHoangAnh/DNS-Server-Practice.git
    cd DNS-Server-Practice
    ```

2.  **Build the project**
    This command will restore dependencies and compile the source code.
    ```sh
    dotnet build --configuration Release
    ```

### Running the Application

You can run the application directly using the `dotnet run` command.

**Authoritative Mode:**
In this mode, the server will respond to all "A" record queries with `8.8.8.8`.```sh
dotnet run --configuration Release
```
**Forwarding Mode:**
Use the `--resolver` flag to specify an upstream DNS server.
```sh
# Forward to Google's DNS
dotnet run --configuration Release -- --resolver 8.8.8.8:53

# Forward to Cloudflare's DNS
dotnet run --configuration Release -- --resolver 1.1.1.1:53
```
> **Note:** The `--` is important to separate the application's arguments from `dotnet`'s arguments.

---

## Usage

The primary way to interact with the server is using a DNS lookup tool like `dig` or `nslookup`.

### Testing with `dig`

Open a new terminal window while the server is running.

**1. Test Authoritative Mode:**
Start the server without any arguments. Then, run `dig` to query it.
```bash
# Query for any domain; the server will respond with 8.8.8.8
dig @localhost -p 2053 google.com

# Expected output will include:
# ;; ANSWER SECTION:
# google.com.		60	IN	A	8.8.8.8
```

**2. Test Forwarding Mode:**
Start the server with a resolver. Then, run `dig` again.
```bash
# Start the server in forwarding mode
dotnet run --configuration Release -- --resolver 8.8.8.8:53
``````bash
# In another terminal, query for a domain
dig @localhost -p 2053 codecrafters.io

# Expected output will include the REAL IP address for codecrafters.io
# ;; ANSWER SECTION:
# codecrafters.io.	300	IN	A	104.26.2.33
# codecrafters.io.	300	IN	A	104.26.3.33
# codecrafters.io.	300	IN	A	172.67.73.49
```

---

## Contact

[Hoang Anh Quan]- [quan.anh.hoang@protonmail.com]

Project Link: [https://github.com/QuanHoangAnh/DNS-Server-Practice](https://github.com/QuanHoangAnh/DNS-Server-Practice)

## Acknowledgements

*   [RFC 1035 - Domain Names - Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
*   [.NET Documentation](https://docs.microsoft.com/en-us/dotnet/)

<!-- MARKDOWN LINKS & IMAGES -->
[CSharp-badge]: https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white
[CSharp-url]: https://docs.microsoft.com/en-us/dotnet/csharp/
[DotNet-badge]: https://img.shields.io/badge/.NET-512BD4?style=for-the-badge&logo=dotnet&logoColor=white
[DotNet-url]: https://dotnet.microsoft.com/