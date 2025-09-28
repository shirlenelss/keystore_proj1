import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.*;

public class SimpleSSLServer {
    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.ssl.keyStore", "server.keystore");
        System.setProperty("javax.net.ssl.keyStorePassword", "password123");
        System.setProperty("javax.net.ssl.trustStore", "server.keystore");
        System.setProperty("javax.net.ssl.trustStorePassword", "password123");

        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket s = (SSLServerSocket) ssf.createServerSocket(8443);
        System.out.println("SSL Server started on port 8443");
        SSLSocket c = (SSLSocket) s.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(c.getInputStream()));
        PrintWriter out = new PrintWriter(c.getOutputStream(), true);
        String line = in.readLine();
        System.out.println("Received from client: " + line);
        out.println("Hello from SSL Server!");
        c.close();
        s.close();
    }
}

