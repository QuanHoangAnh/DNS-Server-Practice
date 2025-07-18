// File: Program.cs

using System.Net;
using System.Net.Sockets;
using System.Text;

// Check if we should run tests
if (args.Length > 0 && args[0] == "test")
{
    await RunTests();
    return;
}

// Main program entry point and server logic
await StartServer();

// Test functions for Stage 5
async Task RunTests()
{
    Console.WriteLine("=== Stage 5 Tests: Parse Header Section ===\n");

    try
    {
        TestBasicHeaderParsing();
        TestFlagExtraction();
        TestNetworkByteOrder();
        TestEdgeCases();
        TestRoundTripSerialization();
        await TestActualServerBehavior();

        Console.WriteLine("🎉 ALL TESTS PASSED! Stage 5 implementation is working correctly.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ TEST FAILED: {ex.Message}");
        Console.WriteLine($"Stack trace: {ex.StackTrace}");
        Environment.Exit(1);
    }

    void TestBasicHeaderParsing()
    {
        Console.WriteLine("Test 1: Basic Header Parsing");

        // Create a test DNS header packet
        var testPacket = new byte[]
        {
            // Packet ID: 0x1234 (4660)
            0x12, 0x34,
            // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0 (0x0100)
            0x01, 0x00,
            // QDCOUNT: 1
            0x00, 0x01,
            // ANCOUNT: 0
            0x00, 0x00,
            // NSCOUNT: 0
            0x00, 0x00,
            // ARCOUNT: 0
            0x00, 0x00
        };

        var message = DnsPacketSerializer.FromByteArray(testPacket);

        // Verify parsing
        Assert(message.Header.PacketIdentifier == 0x1234, "Packet ID should be 0x1234");
        Assert(message.Header.QueryResponse == false, "QR should be false (query)");
        Assert(message.Header.OpCode == 0, "OPCODE should be 0");
        Assert(message.Header.RecursionDesired == true, "RD should be true");
        Assert(message.Header.QuestionCount == 1, "Question count should be 1");
        Assert(message.Header.AnswerRecordCount == 0, "Answer count should be 0");

        Console.WriteLine("✓ Basic header parsing test passed\n");
    }

    void TestFlagExtraction()
    {
        Console.WriteLine("Test 2: Flag Extraction");

        // Let's manually calculate the correct flags
        // QR=1 (bit 15), OPCODE=1 (bits 14-11), AA=1 (bit 10), TC=1 (bit 9), RD=0 (bit 8), RA=1 (bit 7), RCODE=4 (bits 3-0)
        // Binary: 1000 1110 1000 0100 = 0x8E84
        ushort expectedFlags = 0;
        expectedFlags |= (1 << 15);  // QR=1
        expectedFlags |= (1 << 11);  // OPCODE=1 (shift by 11)
        expectedFlags |= (1 << 10);  // AA=1
        expectedFlags |= (1 << 9);   // TC=1
        // RD=0 (bit 8) - leave as 0
        expectedFlags |= (1 << 7);   // RA=1
        expectedFlags |= 4;          // RCODE=4

        Console.WriteLine($"Expected flags: 0x{expectedFlags:X4}");

        var testPacket = new byte[]
        {
            // Packet ID: 0x5678
            0x56, 0x78,
            // Flags: calculated above
            (byte)(expectedFlags >> 8), (byte)(expectedFlags & 0xFF),
            // Counts (all zeros for this test)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        var message = DnsPacketSerializer.FromByteArray(testPacket);

        Console.WriteLine($"Parsed flags: QR={message.Header.QueryResponse}, OPCODE={message.Header.OpCode}, AA={message.Header.AuthoritativeAnswer}, TC={message.Header.Truncation}, RD={message.Header.RecursionDesired}, RA={message.Header.RecursionAvailable}, RCODE={message.Header.ResponseCode}");

        Assert(message.Header.PacketIdentifier == 0x5678, "Packet ID should be 0x5678");
        Assert(message.Header.QueryResponse == true, "QR should be true (response)");
        Assert(message.Header.OpCode == 1, "OPCODE should be 1");
        Assert(message.Header.AuthoritativeAnswer == true, "AA should be true");
        Assert(message.Header.Truncation == true, "TC should be true");
        Assert(message.Header.RecursionDesired == false, "RD should be false");
        Assert(message.Header.RecursionAvailable == true, "RA should be true");
        Assert(message.Header.ResponseCode == 4, "RCODE should be 4");

        Console.WriteLine("✓ Flag extraction test passed\n");
    }

    void TestNetworkByteOrder()
    {
        Console.WriteLine("Test 3: Network Byte Order Conversion");

        // Test with different byte orders
        var testPacket = new byte[]
        {
            // Packet ID: 0xABCD (big-endian)
            0xAB, 0xCD,
            // Flags: 0x0000
            0x00, 0x00,
            // QDCOUNT: 0x0102 (258 in big-endian)
            0x01, 0x02,
            // ANCOUNT: 0x0304 (772 in big-endian)
            0x03, 0x04,
            // NSCOUNT: 0x0506 (1286 in big-endian)
            0x05, 0x06,
            // ARCOUNT: 0x0708 (1800 in big-endian)
            0x07, 0x08
        };

        var message = DnsPacketSerializer.FromByteArray(testPacket);

        Assert(message.Header.PacketIdentifier == 0xABCD, "Packet ID should be 0xABCD");
        Assert(message.Header.QuestionCount == 0x0102, "Question count should be 258");
        Assert(message.Header.AnswerRecordCount == 0x0304, "Answer count should be 772");
        Assert(message.Header.AuthorityRecordCount == 0x0506, "Authority count should be 1286");
        Assert(message.Header.AdditionalRecordCount == 0x0708, "Additional count should be 1800");

        Console.WriteLine("✓ Network byte order test passed\n");
    }

    void TestEdgeCases()
    {
        Console.WriteLine("Test 4: Edge Cases");

        // Test minimum packet (12 bytes)
        var minPacket = new byte[12];
        var message1 = DnsPacketSerializer.FromByteArray(minPacket);
        Assert(message1.Header.PacketIdentifier == 0, "Empty packet should have ID 0");

        // Test maximum values
        var maxPacket = new byte[]
        {
            0xFF, 0xFF, // Max packet ID
            0xFF, 0xFF, // All flags set
            0xFF, 0xFF, // Max question count
            0xFF, 0xFF, // Max answer count
            0xFF, 0xFF, // Max authority count
            0xFF, 0xFF  // Max additional count
        };

        var message2 = DnsPacketSerializer.FromByteArray(maxPacket);
        Assert(message2.Header.PacketIdentifier == 0xFFFF, "Max packet ID should be 0xFFFF");
        Assert(message2.Header.ResponseCode == 15, "Max RCODE should be 15");

        Console.WriteLine("✓ Edge cases test passed\n");
    }

    void TestRoundTripSerialization()
    {
        Console.WriteLine("Test 5: Round-trip Serialization");

        // Create a message, serialize it, then deserialize and compare
        var originalMessage = new DnsMessage();
        originalMessage.Header.PacketIdentifier = 0x9ABC;
        originalMessage.Header.QueryResponse = true;
        originalMessage.Header.OpCode = 2;
        originalMessage.Header.AuthoritativeAnswer = true;
        originalMessage.Header.RecursionDesired = false;
        originalMessage.Header.RecursionAvailable = true;
        originalMessage.Header.ResponseCode = 3;
        originalMessage.Header.QuestionCount = 1;
        originalMessage.Header.AnswerRecordCount = 1;

        originalMessage.Questions.Add(new DnsQuestion { Name = "test.com", Type = 1, Class = 1 });
        originalMessage.Answers.Add(new DnsResourceRecord
        {
            Name = "test.com", Type = 1, Class = 1, Ttl = 300, RdLength = 4,
            Rdata = new byte[] { 192, 168, 1, 1 }
        });

        // Serialize
        var serialized = DnsPacketSerializer.ToByteArray(originalMessage);

        // Deserialize header only (since we only parse header in Stage 5)
        var deserializedMessage = DnsPacketSerializer.FromByteArray(serialized);

        // Compare headers
        Assert(deserializedMessage.Header.PacketIdentifier == originalMessage.Header.PacketIdentifier, "Packet ID mismatch");
        Assert(deserializedMessage.Header.QueryResponse == originalMessage.Header.QueryResponse, "QR flag mismatch");
        Assert(deserializedMessage.Header.OpCode == originalMessage.Header.OpCode, "OpCode mismatch");
        Assert(deserializedMessage.Header.AuthoritativeAnswer == originalMessage.Header.AuthoritativeAnswer, "AA flag mismatch");
        Assert(deserializedMessage.Header.RecursionDesired == originalMessage.Header.RecursionDesired, "RD flag mismatch");
        Assert(deserializedMessage.Header.RecursionAvailable == originalMessage.Header.RecursionAvailable, "RA flag mismatch");
        Assert(deserializedMessage.Header.ResponseCode == originalMessage.Header.ResponseCode, "ResponseCode mismatch");
        Assert(deserializedMessage.Header.QuestionCount == originalMessage.Header.QuestionCount, "Question count mismatch");
        Assert(deserializedMessage.Header.AnswerRecordCount == originalMessage.Header.AnswerRecordCount, "Answer count mismatch");

        Console.WriteLine("✓ Round-trip serialization test passed\n");
    }

    async Task TestActualServerBehavior()
    {
        Console.WriteLine("Test 6: Actual Server Behavior");

        // Test different packet IDs and OpCodes
        var testCases = new[]
        {
            new { PacketId = (ushort)0x1234, OpCode = (byte)0, ExpectedRCode = (byte)0 },
            new { PacketId = (ushort)0x5678, OpCode = (byte)1, ExpectedRCode = (byte)4 },
            new { PacketId = (ushort)0x9ABC, OpCode = (byte)2, ExpectedRCode = (byte)4 },
            new { PacketId = (ushort)0xDEF0, OpCode = (byte)0, ExpectedRCode = (byte)0 }
        };

        foreach (var testCase in testCases)
        {
            // Create test query packet
            var queryPacket = new byte[]
            {
                (byte)(testCase.PacketId >> 8), (byte)(testCase.PacketId & 0xFF), // Packet ID
                (byte)(testCase.OpCode << 3 | 0x01), 0x00, // OpCode in bits 14-11, RD=1
                0x00, 0x01, // 1 question
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // No answers
            };

            // Simulate server processing
            var requestMessage = DnsPacketSerializer.FromByteArray(queryPacket);

            // Verify request parsing
            Assert(requestMessage.Header.PacketIdentifier == testCase.PacketId,
                   $"Request packet ID should be {testCase.PacketId:X4}");
            Assert(requestMessage.Header.OpCode == testCase.OpCode,
                   $"Request OpCode should be {testCase.OpCode}");
            Assert(requestMessage.Header.RecursionDesired == true, "RD should be true");

            // Create response using server logic
            var responseMessage = new DnsMessage();
            responseMessage.Header.PacketIdentifier = requestMessage.Header.PacketIdentifier;
            responseMessage.Header.RecursionDesired = requestMessage.Header.RecursionDesired;
            responseMessage.Header.OpCode = requestMessage.Header.OpCode;
            responseMessage.Header.QueryResponse = true;
            responseMessage.Header.RecursionAvailable = false;

            if (requestMessage.Header.OpCode == 0)
                responseMessage.Header.ResponseCode = 0;
            else
                responseMessage.Header.ResponseCode = 4;

            // Verify response
            Assert(responseMessage.Header.PacketIdentifier == testCase.PacketId,
                   $"Response packet ID should match request: {testCase.PacketId:X4}");
            Assert(responseMessage.Header.ResponseCode == testCase.ExpectedRCode,
                   $"Response code should be {testCase.ExpectedRCode} for OpCode {testCase.OpCode}");
            Assert(responseMessage.Header.QueryResponse == true, "Response should have QR=1");
            Assert(responseMessage.Header.RecursionDesired == true, "Response should preserve RD flag");

            Console.WriteLine($"  ✓ Test case: ID={testCase.PacketId:X4}, OpCode={testCase.OpCode}, RCode={testCase.ExpectedRCode}");
        }

        Console.WriteLine("✓ Actual server behavior test passed\n");
    }

    void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception($"ASSERTION FAILED: {message}");
        }
    }
}

async Task StartServer()
{
    using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 2053));
    Console.WriteLine("DNS server listening on port 2053...");

    try
    {
        while (true)
        {
            UdpReceiveResult receiveResult = await udpClient.ReceiveAsync();
            Console.WriteLine($"Received packet from {receiveResult.RemoteEndPoint}");

            // 1. Parse the incoming request packet
            DnsMessage requestMessage = DnsPacketSerializer.FromByteArray(receiveResult.Buffer);
            Console.WriteLine($"Request ID: {requestMessage.Header.PacketIdentifier}, OpCode: {requestMessage.Header.OpCode}");

            // 2. Create the response message
            var responseMessage = new DnsMessage();

            // 3. Build the response header based on the request header
            responseMessage.Header.PacketIdentifier = requestMessage.Header.PacketIdentifier;
            responseMessage.Header.RecursionDesired = requestMessage.Header.RecursionDesired;
            responseMessage.Header.OpCode = requestMessage.Header.OpCode;

            responseMessage.Header.QueryResponse = true; // This is a response
            responseMessage.Header.RecursionAvailable = false; // We don't support recursion

            // Set ResponseCode based on OpCode
            if (requestMessage.Header.OpCode == 0) // Standard Query
            {
                responseMessage.Header.ResponseCode = 0; // No Error
            }
            else
            {
                responseMessage.Header.ResponseCode = 4; // Not Implemented
            }

            // For now, we still use a hardcoded question and answer
            // This will change in the next stage
            responseMessage.Header.QuestionCount = 1;
            responseMessage.Header.AnswerRecordCount = 1;
            responseMessage.Questions.Add(new DnsQuestion { Name = "codecrafters.io", Type = 1, Class = 1 });
            responseMessage.Answers.Add(new DnsResourceRecord
            {
                Name = "codecrafters.io",
                Type = 1, // A Record
                Class = 1, // IN (Internet)
                Ttl = 60, // A reasonable TTL
                RdLength = 4, // Length of an IPv4 address
                Rdata = new byte[] { 8, 8, 8, 8 }
            });

            // 4. Serialize and send the response
            byte[] responseBytes = DnsPacketSerializer.ToByteArray(responseMessage);
            await udpClient.SendAsync(responseBytes, responseBytes.Length, receiveResult.RemoteEndPoint);
            Console.WriteLine($"Sent response for ID: {responseMessage.Header.PacketIdentifier} to {receiveResult.RemoteEndPoint}");
        }
    }
    catch (SocketException e)
    {
        Console.WriteLine($"SocketException: {e.Message}");
    }
}

/// <summary>
/// Represents the 12-byte header of a DNS message.
/// </summary>
public class DnsHeader
{
    public ushort PacketIdentifier { get; set; } // 16 bits
    public bool QueryResponse { get; set; }      // 1 bit (0 for query, 1 for response)
    public byte OpCode { get; set; }             // 4 bits (0 for standard query)
    public bool AuthoritativeAnswer { get; set; }// 1 bit
    public bool Truncation { get; set; }         // 1 bit
    public bool RecursionDesired { get; set; }   // 1 bit
    public bool RecursionAvailable { get; set; }// 1 bit
    public byte ResponseCode { get; set; }       // 4 bits (0 for no error)
    public ushort QuestionCount { get; set; }    // 16 bits
    public ushort AnswerRecordCount { get; set; }// 16 bits
    public ushort AuthorityRecordCount { get; set; } // 16 bits
    public ushort AdditionalRecordCount { get; set; } // 16 bits
}

/// <summary>
/// Represents a question in the DNS message's question section.
/// </summary>
public class DnsQuestion
{
    public string Name { get; set; } = string.Empty;
    public ushort Type { get; set; }
    public ushort Class { get; set; }
}

/// <summary>
/// Represents a Resource Record (RR) in the answer, authority, or additional sections.
/// </summary>
public class DnsResourceRecord
{
    public string Name { get; set; } = string.Empty;
    public ushort Type { get; set; }
    public ushort Class { get; set; }
    public uint Ttl { get; set; }
    public ushort RdLength { get; set; }
    public byte[] Rdata { get; set; } = Array.Empty<byte>();
}

/// <summary>
/// Represents a full DNS message.
/// </summary>
public class DnsMessage
{
    public DnsHeader Header { get; set; } = new();
    public List<DnsQuestion> Questions { get; set; } = new();
    public List<DnsResourceRecord> Answers { get; set; } = new();
}

/// <summary>
/// Handles serialization and deserialization of DNS message objects.
/// </summary>
public static class DnsPacketSerializer
{
    public static byte[] ToByteArray(DnsMessage message)
    {
        var stream = new MemoryStream();
        // Using a BinaryWriter helps, but we must manage endianness manually for network order.
        using (var writer = new BinaryWriter(stream))
        {
            // --- Header Section (12 bytes) ---

            // Packet Identifier (ID) - 16 bits
            writer.Write(IPAddress.HostToNetworkOrder((short)message.Header.PacketIdentifier));

            // Flags - 16 bits total, split into two bytes
            // Format: QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
            ushort flags = 0;
            if (message.Header.QueryResponse) flags |= (1 << 15);        // QR bit 15
            flags |= (ushort)(message.Header.OpCode << 11);              // OPCODE bits 14-11
            if (message.Header.AuthoritativeAnswer) flags |= (1 << 10);  // AA bit 10
            if (message.Header.Truncation) flags |= (1 << 9);            // TC bit 9
            if (message.Header.RecursionDesired) flags |= (1 << 8);      // RD bit 8
            if (message.Header.RecursionAvailable) flags |= (1 << 7);    // RA bit 7
            // Z bits 6-4 are reserved and should be 0
            flags |= (ushort)(message.Header.ResponseCode & 0x0F);       // RCODE bits 3-0
            writer.Write(IPAddress.HostToNetworkOrder((short)flags));

            // Question Count (QDCOUNT) - 16 bits
            writer.Write(IPAddress.HostToNetworkOrder((short)message.Header.QuestionCount));

            // Answer Record Count (ANCOUNT) - 16 bits
            writer.Write(IPAddress.HostToNetworkOrder((short)message.Header.AnswerRecordCount));

            // Authority Record Count (NSCOUNT) - 16 bits
            writer.Write(IPAddress.HostToNetworkOrder((short)message.Header.AuthorityRecordCount));

            // Additional Record Count (ARCOUNT) - 16 bits
            writer.Write(IPAddress.HostToNetworkOrder((short)message.Header.AdditionalRecordCount));

            // --- Question Section ---
            foreach (var question in message.Questions)
            {
                EncodeDomainName(writer, question.Name);
                writer.Write(IPAddress.HostToNetworkOrder((short)question.Type));
                writer.Write(IPAddress.HostToNetworkOrder((short)question.Class));
            }

            // --- Answer Section ---
            foreach (var answer in message.Answers)
            {
                EncodeDomainName(writer, answer.Name);
                writer.Write(IPAddress.HostToNetworkOrder((short)answer.Type));
                writer.Write(IPAddress.HostToNetworkOrder((short)answer.Class));
                writer.Write(IPAddress.HostToNetworkOrder((int)answer.Ttl));
                writer.Write(IPAddress.HostToNetworkOrder((short)answer.RdLength));
                writer.Write(answer.Rdata);
            }
        }
        return stream.ToArray();
    }

    /// <summary>
    /// Encodes a domain name like "google.com" into the DNS label format:
    /// 6, 'g','o','o','g','l','e', 3, 'c','o','m', 0
    /// </summary>
    private static void EncodeDomainName(BinaryWriter writer, string domainName)
    {
        if (string.IsNullOrEmpty(domainName) || domainName == ".")
        {
            writer.Write((byte)0); // Null terminator for root domain
            return;
        }

        var labels = domainName.Split('.');
        foreach (var label in labels)
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);
            writer.Write((byte)labelBytes.Length);
            writer.Write(labelBytes);
        }
        writer.Write((byte)0); // Null terminator for the entire name
    }

    /// <summary>
    /// Deserializes a byte array into a DnsMessage object.
    /// Currently only parses the header section.
    /// </summary>
    public static DnsMessage FromByteArray(byte[] data)
    {
        var message = new DnsMessage();
        var stream = new MemoryStream(data);
        using (var reader = new BinaryReader(stream))
        {
            // --- Header Section (12 bytes) ---

            // Packet Identifier (ID) - 16 bits
            message.Header.PacketIdentifier = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());

            // Flags - 16 bits total
            ushort flags = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());

            // Extract individual flags using bitwise operations
            message.Header.QueryResponse = (flags & 0b1000_0000_0000_0000) != 0;        // QR bit 15
            message.Header.OpCode = (byte)((flags >> 11) & 0b0000_1111);               // OPCODE bits 14-11
            message.Header.AuthoritativeAnswer = (flags & 0b0000_0100_0000_0000) != 0; // AA bit 10
            message.Header.Truncation = (flags & 0b0000_0010_0000_0000) != 0;          // TC bit 9
            message.Header.RecursionDesired = (flags & 0b0000_0001_0000_0000) != 0;    // RD bit 8
            message.Header.RecursionAvailable = (flags & 0b0000_0000_1000_0000) != 0;  // RA bit 7
            // Z bits 6-4 are reserved and ignored
            message.Header.ResponseCode = (byte)(flags & 0b0000_0000_0000_1111);       // RCODE bits 3-0

            // Question Count (QDCOUNT) - 16 bits
            message.Header.QuestionCount = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());

            // Answer Record Count (ANCOUNT) - 16 bits
            message.Header.AnswerRecordCount = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());

            // Authority Record Count (NSCOUNT) - 16 bits
            message.Header.AuthorityRecordCount = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());

            // Additional Record Count (ARCOUNT) - 16 bits
            message.Header.AdditionalRecordCount = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());
        }

        // Parsing of Question and Answer sections will be added in future stages
        return message;
    }
}
