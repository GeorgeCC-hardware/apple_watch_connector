package dev.applewatchandroid.bridge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/** Synthetic ACL/event traces through the real IKE ACK and SMP wait loops. */
public final class PairingSmpHandoffTest {
    private static final int HANDLE = 0x0042;
    private static final byte[] RESPONSE = {2, 3, 1, 0x2d, 16, 7, 7};
    private static final byte[] SECURITY = {0x0b, 0x2d};
    private final FakeController controller = new FakeController();
    private final AtomicBoolean stopped = new AtomicBoolean();
    private final ByteArrayOutputStream output = new ByteArrayOutputStream();
    private PrintStream previousOutput;
    private HalTransportSession session;
    private BluetoothController.Callbacks callbacks;

    @Before public void setUp() throws Exception {
        previousOutput = System.out;
        System.setOut(new PrintStream(output, true, StandardCharsets.UTF_8));
        session = new HalTransportSession(controller, stopped,
                new LinkedBlockingQueue<>(), new LinkedBlockingQueue<>(),
                new LinkedBlockingQueue<>(), new LinkedBlockingQueue<>(),
                new LinkedBlockingQueue<>(), new LinkedBlockingQueue<>(),
                new LinkedBlockingQueue<>(), false, null);
        field("connectionHandle").set(session, HANDLE);
        HciAclCreditWindow credits = (HciAclCreditWindow) field("aclCredits").get(session);
        credits.configure(16);
        credits.connected(HANDLE);
        callbacks = (BluetoothController.Callbacks) field("callbacks").get(session);
        controller.callbacks = callbacks;
    }

    @After public void tearDown() throws Exception {
        try { invoke("clearDeferredSmpPdus"); }
        finally { System.setOut(previousOutput); }
    }

    @Test public void retainsSecurityAndResponseBeforeFinalAckInOrder() throws Exception {
        peer(BluetoothSmpCodec.FIXED_CID, SECURITY);
        peer(BluetoothSmpCodec.FIXED_CID, RESPONSE);
        peerAck();
        finalAck();
        List<byte[]> retained = new ArrayList<>(deferred());
        assertEquals(2, retained.size());
        sendRequest();
        assertArrayEquals(RESPONSE, await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertEquals(0, deferred().size());
        for (byte[] pdu : retained) assertArrayEquals(new byte[pdu.length], pdu);
        assertEquals(1, controller.smpRequests());
        assertTrue(logs().contains("SMP RX DEFERRED"));
        assertTrue(logs().contains("SMP HANDOFF: final IKE transport ACK received"));
    }

    @Test public void acceptsSecurityAfterAckWithoutResendingRequest() throws Exception {
        peerAck();
        finalAck();
        sendRequest();
        peer(BluetoothSmpCodec.FIXED_CID, SECURITY);
        peer(BluetoothSmpCodec.FIXED_CID, SECURITY);
        peer(BluetoothSmpCodec.FIXED_CID, RESPONSE);
        assertArrayEquals(RESPONSE, await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertEquals(1, controller.smpRequests());
        assertTrue(logs().contains("count=2"));
    }

    @Test public void preservesFollowingDeferredPublicKeyForNextPhase() throws Exception {
        byte[] key = new byte[64];
        Arrays.fill(key, (byte) 0x7e);
        byte[] keyPdu = BluetoothSmpCodec.pairingPublicKey(key);
        peer(BluetoothSmpCodec.FIXED_CID, RESPONSE);
        peer(BluetoothSmpCodec.FIXED_CID, keyPdu);
        peerAck();
        finalAck();
        sendRequest();
        assertArrayEquals(RESPONSE, await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertArrayEquals(keyPdu, await(BluetoothSmpCodec.PAIRING_PUBLIC_KEY, 500));
        assertFalse(logs().contains(HciCodec.toHex(key)));
        assertFalse(logs().contains(HciCodec.toHex(RESPONSE)));
    }

    @Test public void reassemblesEarlyFragmentedSmpBeforeAck() throws Exception {
        for (byte[] fragment : HciCodec.buildLeAclL2capFragments(
                HANDLE, BluetoothSmpCodec.FIXED_CID, RESPONSE, 5)) {
            callbacks.aclDataReceived(fragment);
        }
        peerAck();
        finalAck();
        sendRequest();
        assertArrayEquals(RESPONSE, await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertEquals(1, field("pairingSmpReceived").getInt(session));
    }

    @Test public void doesNotAdoptSmpFromAnotherHandle() throws Exception {
        for (byte[] packet : HciCodec.buildLeAclL2capFragments(
                HANDLE + 1, BluetoothSmpCodec.FIXED_CID, SECURITY, 256)) {
            callbacks.aclDataReceived(packet);
        }
        peerAck();
        finalAck();
        assertTrue(deferred().isEmpty());
        assertEquals(0, field("pairingSmpReceived").getInt(session));
    }

    @Test public void reportsEarlyPairingFailureRatherThanTimingOut() throws Exception {
        peer(BluetoothSmpCodec.FIXED_CID, new byte[]{5, 3});
        peerAck();
        finalAck();
        sendRequest();
        Exception failure = assertThrows(Exception.class,
                () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertTrue(failure.getMessage().contains("reason=0x03 (Authentication Requirements)"));
        assertFalse(failure.getMessage().contains("timed out"));
    }

    @Test public void reportsLivePairingFailure() throws Exception {
        sendRequest();
        peer(BluetoothSmpCodec.FIXED_CID, new byte[]{5, 9});
        Exception failure = assertThrows(Exception.class,
                () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertTrue(failure.getMessage().contains("Repeated Attempts"));
    }

    @Test public void rejectsMalformedSecurityRequest() throws Exception {
        sendRequest();
        peer(BluetoothSmpCodec.FIXED_CID, new byte[]{0x0b});
        Exception failure = assertThrows(Exception.class,
                () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertTrue(failure.getMessage().contains("Malformed SMP Security Request"));
        assertEquals(1, controller.smpRequests());
    }

    @Test public void doesNotRestartSecurityNegotiationDuringKeyExchange() throws Exception {
        peer(BluetoothSmpCodec.FIXED_CID, SECURITY);
        Exception failure = assertThrows(Exception.class,
                () -> await(BluetoothSmpCodec.PAIRING_PUBLIC_KEY, 500));
        assertTrue(failure.getMessage().contains("Unexpected SMP opcode=0x0B"));
        assertEquals(0, controller.smpRequests());
    }

    @Test(timeout = 2500) public void acceptsDelayedResponseAfterSecurityRequest() throws Exception {
        sendRequest();
        peer(BluetoothSmpCodec.FIXED_CID, SECURITY);
        ScheduledExecutorService delivery = Executors.newSingleThreadScheduledExecutor();
        try {
            delivery.schedule(() -> peer(BluetoothSmpCodec.FIXED_CID, RESPONSE), 30, TimeUnit.MILLISECONDS);
            assertArrayEquals(RESPONSE, await(BluetoothSmpCodec.PAIRING_RESPONSE, 1000));
        } finally { delivery.shutdownNow(); delivery.awaitTermination(1, TimeUnit.SECONDS); }
        assertEquals(1, controller.smpRequests());
    }

    @Test(timeout = 2500) public void securityTrafficCannotExtendResponseDeadline() throws Exception {
        sendRequest();
        ScheduledExecutorService delivery = Executors.newSingleThreadScheduledExecutor();
        try {
            delivery.scheduleAtFixedRate(() -> peer(BluetoothSmpCodec.FIXED_CID, SECURITY),
                    0, 30, TimeUnit.MILLISECONDS);
            Exception failure = assertThrows(Exception.class,
                    () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 150));
            assertTrue(failure.getMessage(), failure.getMessage().contains("timed out after 150 ms"));
        } finally { delivery.shutdownNow(); delivery.awaitTermination(1, TimeUnit.SECONDS); }
        assertEquals(1, controller.smpRequests());
    }

    @Test public void silentPeerTimeoutIncludesHandoffAndControllerState() throws Exception {
        peerAck();
        finalAck();
        sendRequest();
        Exception failure = assertThrows(Exception.class,
                () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 20));
        assertTrue(failure.getMessage().contains("received=0"));
        assertTrue(failure.getMessage().contains("requestSubmittedAgeMs="));
        assertTrue(failure.getMessage().contains("finalIkeAckAgeMs="));
        assertTrue(failure.getMessage().contains("completed=2"));
        assertTrue(logs().contains("peer receipt unconfirmed"));
    }

    @Test public void failsClosedOnEarlySmpQueueOverflow() throws Exception {
        for (int count = 0; count < 17; count++) peer(BluetoothSmpCodec.FIXED_CID, SECURITY);
        peerAck();
        Exception failure = assertThrows(Exception.class, this::finalAck);
        assertTrue(failure.getMessage().contains("SMP deferred queue overflow"));
        assertEquals(16, deferred().size());
        List<byte[]> retained = new ArrayList<>(deferred());
        invoke("clearDeferredSmpPdus");
        for (byte[] pdu : retained) assertArrayEquals(new byte[pdu.length], pdu);
        assertEquals(0, controller.smpRequests());
    }

    @Test public void disconnectBeforeAckClearsDeferredSmp() throws Exception {
        peer(BluetoothSmpCodec.FIXED_CID, SECURITY);
        controller.afterWrite = this::disconnect;
        Exception failure = assertThrows(Exception.class, this::finalAck);
        assertTrue(failure.getMessage().contains("reason=0x13"));
        assertTrue(deferred().isEmpty());
        assertEquals(-1, field("connectionHandle").getInt(session));
        assertEquals(0, controller.smpRequests());
    }

    @Test public void disconnectDuringSmpIsReportedWithoutWaitingForTimeout() throws Exception {
        sendRequest();
        disconnect();
        Exception failure = assertThrows(Exception.class,
                () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertTrue(failure.getMessage().contains("reason=0x13"));
        assertFalse(failure.getMessage().contains("timed out"));
    }

    @Test public void cancellationWinsOverDeferredResponse() throws Exception {
        peer(BluetoothSmpCodec.FIXED_CID, RESPONSE);
        peerAck();
        finalAck();
        stopped.set(true);
        assertThrows(HalTransportSession.StopRequested.class,
                () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
    }

    @Test public void controllerWriteFailureDoesNotClaimRequestSubmission() throws Exception {
        controller.failWrite = true;
        assertThrows(IOException.class, this::sendRequest);
        assertEquals(-1, field("smpRequestSubmittedAtMs").getLong(session));
        assertFalse(logs().contains("SMP REQUEST SUBMITTED"));
    }

    @Test public void controllerClosureWinsOverDeferredResponse() throws Exception {
        peer(BluetoothSmpCodec.FIXED_CID, RESPONSE);
        peerAck();
        finalAck();
        callbacks.transportFailed(new IOException("synthetic broker EOF"));
        Exception failure = assertThrows(Exception.class,
                () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertTrue(failure.getMessage().contains("controller transport failed"));
    }

    @Test public void boundsSecurityRequestFloodWithoutSendingAnotherRequest() throws Exception {
        sendRequest();
        for (int count = 0; count < 17; count++) peer(BluetoothSmpCodec.FIXED_CID, SECURITY);
        Exception failure = assertThrows(Exception.class,
                () -> await(BluetoothSmpCodec.PAIRING_RESPONSE, 500));
        assertTrue(failure.getMessage().contains("Too many SMP Security Requests"));
        assertEquals(1, controller.smpRequests());
    }

    @Test public void retainsIdentityDistributionThatArrivesBeforeEncryptionEvent() throws Exception {
        byte[] identity = BluetoothSmpCodec.identityInformation(new byte[16]);
        callbacks.hciEventReceived(new byte[]{0x0f, 4, 0, 1, 0x19, 0x20});
        peer(BluetoothSmpCodec.FIXED_CID, identity);
        callbacks.hciEventReceived(new byte[]{8, 4, 0, (byte) HANDLE, 0, 1});
        invoke("startLeEncryption", new byte[16]);
        assertEquals(1, deferred().size());
        assertArrayEquals(identity, await(BluetoothSmpCodec.IDENTITY_INFORMATION, 500));
    }

    @Test public void encryptionPhaseAlsoFailsOnDeferredQueueOverflow() throws Exception {
        byte[] identity = BluetoothSmpCodec.identityInformation(new byte[16]);
        for (int count = 0; count < 17; count++) peer(BluetoothSmpCodec.FIXED_CID, identity);
        Exception failure = assertThrows(Exception.class,
                () -> invoke("startLeEncryption", new byte[16]));
        assertTrue(failure.getMessage().contains("SMP deferred queue overflow"));
    }

    private void peer(int cid, byte[] pdu) {
        for (byte[] packet : HciCodec.buildLeAclL2capFragments(HANDLE, cid, pdu, 256)) {
            callbacks.aclDataReceived(packet);
        }
    }

    private void peerAck() {
        peer(HciCodec.TERMINUS_LOCAL_CID,
                L2capErtmCodec.encodeReceiverReady(HciCodec.TERMINUS_LOCAL_CID, 1, false, false));
    }

    private void disconnect() {
        callbacks.hciEventReceived(new byte[]{5, 4, 0, (byte) HANDLE, 0, 0x13});
    }

    private void finalAck() throws Exception {
        Class<?> type = Class.forName(HalTransportSession.class.getName() + "$PairingTransportCursor");
        Constructor<?> constructor = type.getDeclaredConstructor(int.class, int.class);
        constructor.setAccessible(true);
        invoke("sendPairingIkeOneWayAndAwaitAck", 0x0041, constructor.newInstance(0, 0),
                List.of(new byte[28]), "PAIRING PRIVATE-NOTIFIES WATCH-REQUEST ACK", 500L);
    }

    private void sendRequest() throws Exception {
        invoke("sendL2cap", BluetoothSmpCodec.FIXED_CID,
                BluetoothSmpCodec.createPairingRequest().encode(), "SMP PAIRING REQUEST");
    }

    private byte[] await(int opcode, long timeout) throws Exception {
        return (byte[]) invoke("awaitSmpPdu", opcode, timeout, "SMP test response");
    }

    @SuppressWarnings("unchecked") private BlockingQueue<byte[]> deferred() throws Exception {
        return (BlockingQueue<byte[]>) field("deferredSmpPdus").get(session);
    }

    private String logs() { return output.toString(StandardCharsets.UTF_8); }

    private Field field(String name) throws Exception {
        Field field = HalTransportSession.class.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private Object invoke(String name, Object... arguments) throws Exception {
        for (Method method : HalTransportSession.class.getDeclaredMethods()) {
            if (!method.getName().equals(name) || method.getParameterCount() != arguments.length) continue;
            method.setAccessible(true);
            try { return method.invoke(session, arguments); }
            catch (InvocationTargetException error) {
                if (error.getCause() instanceof Exception) throw (Exception) error.getCause();
                throw new AssertionError(error.getCause());
            }
        }
        throw new AssertionError("No method: " + name);
    }

    private static final class FakeController implements BluetoothController {
        private final List<byte[]> sent = new ArrayList<>();
        private Callbacks callbacks;
        private boolean failWrite;
        private Runnable afterWrite;
        @Override public void initialize(Callbacks callbacks) { this.callbacks = callbacks; }
        @Override public void sendHciCommand(byte[] bytes) { }
        @Override public void close() { }
        @Override public void sendAclData(byte[] bytes) throws IOException {
            if (failWrite) throw new IOException("synthetic controller write failure");
            sent.add(bytes.clone());
            callbacks.hciEventReceived(new byte[]{0x13, 5, 1, (byte) HANDLE, 0, 1, 0});
            if (afterWrite != null) afterWrite.run();
        }
        private int smpRequests() {
            HciCodec.AclReassembler decoder = new HciCodec.AclReassembler();
            int requests = 0;
            for (byte[] packet : sent) {
                HciCodec.L2capPdu pdu = decoder.accept(packet);
                if (pdu != null && pdu.destinationCid == BluetoothSmpCodec.FIXED_CID
                        && (pdu.payload[0] & 255) == BluetoothSmpCodec.PAIRING_REQUEST) requests++;
            }
            return requests;
        }
    }
}
