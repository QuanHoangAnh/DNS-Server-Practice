// File: Program.cs

using System.Net;
using System.Net.Sockets;
using System.Text;

// Main program entry point and server logic
await StartServer();

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

            // Parse the incoming query to extract the ID
            var queryData = receiveResult.Buffer;
            ushort queryId = 1234; // Default fallback

            if (queryData.Length >= 2)
            {
                // Extract ID from the first 2 bytes (network byte order)
                queryId = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(queryData, 0));
            }

            // Construct a full response with header, question, and answer.
            var responseMessage = new DnsMessage
            {
                Header = new DnsHeader
                {
                    PacketIdentifier = queryId, // Use the ID from the query
                    QueryResponse = true,
                    OpCode = 0,
                    ResponseCode = 0,
                    QuestionCount = 1,
                    // Set AnswerRecordCount to 1.
                    AnswerRecordCount = 1,
                },
                Questions = new List<DnsQuestion>
                {
                    new() { Name = "codecrafters.io", Type = 1, Class = 1 }
                },
                Answers = new List<DnsResourceRecord>
                {
                    new()
                    {
                        Name = "codecrafters.io",
                        Type = 1, // A Record
                        Class = 1, // IN (Internet)
                        Ttl = 60, // A reasonable TTL
                        RdLength = 4, // Length of an IPv4 address
                        Rdata = new byte[] { 8, 8, 8, 8 }
                    }
                }
            };

            // Serialize the DnsMessage object into a byte array.
            byte[] responseBytes = DnsPacketSerializer.ToByteArray(responseMessage);

            // Send the serialized response back to the client.
            await udpClient.SendAsync(responseBytes, responseBytes.Length, receiveResult.RemoteEndPoint);
            Console.WriteLine($"Sent full response to {receiveResult.RemoteEndPoint}");
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
/// Handles serialization of DNS message objects into byte arrays.
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
}
