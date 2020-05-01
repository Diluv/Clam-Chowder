package com.diluv.clamchowder;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.*;
import java.net.URL;
import java.nio.charset.Charset;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Testcontainers
public class ClamClientTest {

    private static final GenericContainer CONTAINER;

    static {
        CONTAINER = new GenericContainer<>("diluv/clamav")
                .withImagePullPolicy(PullPolicy.alwaysPull())
                .withExposedPorts(3310)
                .waitingFor(Wait.forHealthcheck().withStartupTimeout(Duration.ofMinutes(5)));
        CONTAINER.start();
    }

    private static Map<File, ScanResult.Status> fileList = new HashMap<>();

    @BeforeAll
    public static void setup() {
        URL url = ClamClientTest.class.getClassLoader().getResource("oreo.png");
        if (url != null) {
            File oreo = new File(url.getFile());
            fileList.put(oreo, ScanResult.Status.OK);

            // "Virus" created to prevent issues with antivirus deleting it.
            File virus = new File(oreo.getParentFile(), "virus.txt");
            fileList.put(virus, ScanResult.Status.FOUND);
            try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(virus), Charset.defaultCharset()))) {
                writer.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @Test
    public void test() {
        ClamClient clamClient = new ClamClient(CONTAINER.getContainerIpAddress(), CONTAINER.getFirstMappedPort());
        try {
            Assertions.assertTrue(clamClient.ping());
            for (File file : fileList.keySet()) {
                ScanResult result = clamClient.scan(file);
                Assertions.assertSame(result.getStatus(), fileList.get(file));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}