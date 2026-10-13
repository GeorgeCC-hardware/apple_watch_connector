package dev.applewatchandroid.bridge;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public final class LinuxHciDiagnosticsTest {
    public static void main(String[] args) throws Exception {
        for (String line : new String[]{
                "HCI_BROKER_V1:TX ACL cid=0x0006 pb=0 opcode=0x01 bytes=16 elapsedMs=120",
                "HCI_BROKER_V1:RX ACL cid=0x0006 pb=2 opcode=none bytes=9 elapsedMs=121",
                "HCI_BROKER_V1:RX EVENT code=0x13 bytes=8 elapsedMs=122",
                "HCI_BROKER_V1:TX COMMAND opcode=0x2019 bytes=32 elapsedMs=123"}) {
            require(("LINUX " + line).equals(LinuxBluetoothController.brokerDiagnostic(line)));
        }
        for (String line : new String[]{
                "", "native crash /private/path", "HCI_BROKER_V1:TX raw=010203",
                "HCI_BROKER_V1:TX ACL cid=0x0006 pb=0 opcode=0x01 bytes=16 elapsedMs=120 key=deadbeef",
                "HCI_BROKER_V1:RX EVENT code=0x13 bytes=8 elapsedMs=122\nsecret",
                "x".repeat(1024)}) {
            require(LinuxBluetoothController.brokerDiagnostic(line) == null);
        }
        String valid = "HCI_BROKER_V1:RX EVENT code=0x08 bytes=7 elapsedMs=124";
        ByteArrayInputStream input = new ByteArrayInputStream(
                ("x".repeat(4096) + "\n" + valid + "\n" + "truncated").getBytes(StandardCharsets.UTF_8));
        require("".equals(LinuxBluetoothController.readBrokerLine(input)));
        require(valid.equals(LinuxBluetoothController.readBrokerLine(input)));
        require(LinuxBluetoothController.readBrokerLine(input) == null);
        System.out.println("Linux HCI diagnostics tests passed");
    }

    private static void require(boolean valid) {
        if (!valid) throw new AssertionError("Invalid broker metadata relay");
    }
}
