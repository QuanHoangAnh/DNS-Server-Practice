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

            DnsMessage requestMessage = DnsPacketSerializer.FromByteArray(receiveResult.Buffer);
            if (requestMessage.Questions.Count == 0) continue;

            Console.WriteLine($"Received {requestMessage.Questions.Count} questions.");
            foreach(var q in requestMessage.Questions)
            {
                Console.WriteLine($"  - Query for: {q.Name}");
            }

            var responseMessage = new DnsMessage();
            responseMessage.Header.PacketIdentifier = requestMessage.Header.PacketIdentifier;
            responseMessage.Header.RecursionDesired = requestMessage.Header.RecursionDesired;
            responseMessage.Header.OpCode = requestMessage.Header.OpCode;
            responseMessage.Header.QueryResponse = true;
            responseMessage.Header.ResponseCode = requestMessage.Header.OpCode == 0 ? (byte)0 : (byte)4;

            // Copy all questions from request to response
            responseMessage.Questions.AddRange(requestMessage.Questions);
            responseMessage.Header.QuestionCount = (ushort)requestMessage.Questions.Count;

            // Create an answer for each question
            foreach (var question in requestMessage.Questions)
            {
                responseMessage.Answers.Add(new DnsResourceRecord
                {
                    Name = question.Name,
                    Type = 1, // A Record
                    Class = 1, // IN (Internet)
                    Ttl = 60,
                    RdLength = 4,
                    Rdata = new byte[] { 8, 8, 8, 8 } // Still a hardcoded IP
                });
            }
            responseMessage.Header.AnswerRecordCount = (ushort)responseMessage.Answers.Count;

            byte[] responseBytes = DnsPacketSerializer.ToByteArray(responseMessage);
            await udpClient.SendAsync(responseBytes, responseBytes.Length, receiveResult.RemoteEndPoint);
            Console.WriteLine($"Sent response with {responseMessage.Answers.Count} answers to {receiveResult.RemoteEndPoint}");
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
    /// Now parses both header and question sections.
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

            // --- Question Section ---
            for (int i = 0; i < message.Header.QuestionCount; i++)
            {
                message.Questions.Add(new DnsQuestion
                {
                    Name = DecodeDomainName(reader),
                    Type = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16()),
                    Class = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16())
                });
            }

            // --- Answer Section ---
            for (int i = 0; i < message.Header.AnswerRecordCount; i++)
            {
                var answer = new DnsResourceRecord
                {
                    Name = DecodeDomainName(reader),
                    Type = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16()),
                    Class = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16()),
                    Ttl = (uint)IPAddress.NetworkToHostOrder(reader.ReadInt32()),
                    RdLength = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16())
                };
                answer.Rdata = reader.ReadBytes(answer.RdLength);
                message.Answers.Add(answer);
            }
        }
        return message;
    }

    /// <summary>
    /// Decodes a domain name, handling compression pointers.
    /// </summary>
    private static string DecodeDomainName(BinaryReader reader)
    {
        var labels = new List<string>();
        byte length;

        while ((length = reader.ReadByte()) != 0)
        {
            // Check if the two most significant bits are set (11), indicating a pointer.
            if ((length & 0xC0) == 0xC0)
            {
                // It's a pointer. The offset is in the next 14 bits.
                // Mask out the top two bits from the first byte and combine with the second byte.
                int offset = ((length & 0x3F) << 8) | reader.ReadByte();

                // Save the current stream position
                long currentPosition = reader.BaseStream.Position;

                // Validate offset is within bounds
                if (offset >= reader.BaseStream.Length)
                    throw new InvalidOperationException($"Compression pointer offset {offset} is beyond stream length {reader.BaseStream.Length}");

                // Jump to the offset to read the pointed-to name
                reader.BaseStream.Position = offset;

                // Recursively decode the name from the new position
                string pointedName = DecodeDomainName(reader);

                // If we have existing labels, combine them with the pointed name
                if (labels.Count > 0)
                {
                    labels.Add(pointedName);
                    pointedName = string.Join('.', labels);
                }

                // Restore the stream position to continue parsing after the pointer
                reader.BaseStream.Position = currentPosition;

                // A name that ends in a pointer is complete.
                return pointedName;
            }
            else
            {
                // It's a standard length-prefixed label.
                labels.Add(Encoding.ASCII.GetString(reader.ReadBytes(length)));
            }
        }

        return string.Join('.', labels);
    }
}
