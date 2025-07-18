// File: Program.cs

using System.Net;
using System.Net.Sockets;

// The main entry point for the application.
// It will listen for UDP packets on port 2053 and respond.
await StartServer();

async Task StartServer()
{
    try
    {
        // A UdpClient is a high-level class for sending and receiving UDP datagrams.
        // We bind it to IPAddress.Any, meaning it will listen on all network interfaces,
        // and to port 2053, the port specified for this DNS server challenge.
        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 2053));
        Console.WriteLine("DNS server listening on port 2053...");

        // Enter an infinite loop to continuously listen for new client requests.
        while (true)
        {
            // Asynchronously wait for a UDP datagram to be received.
            // The `ReceiveAsync` method returns a `UdpReceiveResult` object which contains
            // the received data as a byte array and the remote endpoint (client's address and port).
            UdpReceiveResult receiveResult = await udpClient.ReceiveAsync();
            Console.WriteLine($"Received packet from {receiveResult.RemoteEndPoint}");

            // For this initial stage, the specification requires us to simply respond with a UDP packet.
            // The content is irrelevant, so we create an empty byte array.
            byte[] response = Array.Empty<byte>();

            // Send the response packet back to the client that sent the request.
            // `receiveResult.RemoteEndPoint` ensures the response goes to the correct source.
            await udpClient.SendAsync(response, response.Length, receiveResult.RemoteEndPoint);
            Console.WriteLine($"Sent empty response to {receiveResult.RemoteEndPoint}");
        }
    }
    catch (SocketException e)
    {
        // Handle potential socket errors, such as the port being in use.
        Console.WriteLine($"SocketException: {e.Message}");
    }
}
