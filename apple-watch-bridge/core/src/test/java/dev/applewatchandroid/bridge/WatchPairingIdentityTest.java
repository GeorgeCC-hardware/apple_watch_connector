package dev.applewatchandroid.bridge;

import static org.junit.Assert.*;
import org.junit.Test;

public final class WatchPairingIdentityTest {
    private static WatchPairingIdentity target(int major, int minor) {
        return new WatchPairingIdentity(WatchSetupMetadataCodec.decodeExtendedMetadata(
                WatchSetupMetadataCodec.encodeExtendedMetadata(25, major, minor, false, 0x001a0200L, null)));
    }

    @Test public void knownAndFutureModelsBindTheirOwnAuthenticatedIdentity() {
        for (int[] model : new int[][]{{6, 18}, {7, 5}, {7, 1}, {99, 1}}) {
            var target = target(model[0], model[1]);
            String product = "Watch" + model[0] + "," + model[1];
            assertFalse(target.acceptSnapshot("Watch1,1", "Observed SKU", 0x8301));
            assertTrue(target.acceptSnapshot(product, "Observed SKU", 0x8301));
            assertTrue(target.acceptSnapshot(product, "Observed SKU", 0x8301));
            assertFalse(target.acceptSnapshot(product, "Observed SKU", 0x8310));
            assertFalse(target.acceptSnapshot(product, "Changed SKU", 0x8301));
        }
    }

    @Test public void malformedPropertiesCannotBindOrPoisonIdentity() {
        var target = target(6, 18);
        assertFalse(target.acceptSnapshot("Watch6,18", null, 0x8301));
        assertFalse(target.acceptSnapshot("Watch6,18", " ", 0x8301));
        for (long chip : new long[]{0, -1, 0x1_0000_0000L}) {
            assertFalse(target.acceptSnapshot("Watch6,18", "Observed SKU", chip));
        }
        assertFalse(target.acceptSnapshot(null, "Observed SKU", 0x8301));
        assertTrue(target.acceptSnapshot("Watch6,18", "Observed SKU", 0x8301));
    }

    @Test public void restoredIdentityCannotInventOrAcceptAnInvalidModel() {
        for (String product : new String[]{null, "", "iPhone18,1", "Watch0,1", "Watch06,18", "Watch128,1", "Watch6,128"}) {
            assertThrows(IllegalArgumentException.class, () -> new WatchPairingIdentity(product));
        }
        assertTrue(new WatchPairingIdentity("Watch6,18").acceptSnapshot("Watch6,18", "Observed SKU", 0x8301));
    }
}
