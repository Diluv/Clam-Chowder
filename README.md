# Clam Chowder

Clam Chowder is a modern [ClamAV](https://www.clamav.net/) client written in Java. With this client you will be able to quickly implement ClamAV features such as malware scanning into your application. 

## Maven Info

Coming soon to a maven central near you! 🙃

## Getting Started

Implementing the ClamAV client is very simple. Simply create a new ClamClient using the connection information for your ClamAV server.

```java
final ClamClient client = new ClamClient("127.0.0.1", 3310);
```

After creating the client you can use it to send commands to the ClamAV server. Each command is sent using a separate connection and can be threaded. Built in methods are provided for several of the commands such as ping and scan. 

Scanning a file is as simple as passing a File object to the client. For advanced use cases you can also scan an InputStream instead.

```java
final ScanResult result = client.scan(new File("sketchy.zip"));
System.out.println("File Status is " + result.getStatus().name() + " Malware: " + result.getFound());
```