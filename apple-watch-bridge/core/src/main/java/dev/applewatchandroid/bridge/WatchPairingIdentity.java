package dev.applewatchandroid.bridge;

/** Binds authenticated Watch properties to selected discovery or sealed pair identity. */
final class WatchPairingIdentity {
    private final String expectedProductType;
    private String authenticatedModelNumber;
    private long authenticatedChipId;
    private boolean authenticated;

    WatchPairingIdentity(WatchSetupMetadataCodec.ExtendedMetadata metadata) {
        this(metadata == null ? null : metadata.productType());
    }

    WatchPairingIdentity(String productType) {
        if (productType == null || !productType.matches("Watch[1-9][0-9]*,(0|[1-9][0-9]*)")) {
            throw new IllegalArgumentException("Watch product identity is absent or malformed");
        }
        String[] versions = productType.substring(5).split(",");
        if (Integer.parseInt(versions[0]) > 127 || Integer.parseInt(versions[1]) > 127) {
            throw new IllegalArgumentException("Watch product identity exceeds the setup wire width");
        }
        expectedProductType = productType;
    }

    /** The caller supplies properties only from this generation's authenticated Class C lane. */
    boolean acceptSnapshot(String productType, String modelNumber, long chipId) {
        if (!expectedProductType.equals(productType)
                || modelNumber == null || modelNumber.isBlank()
                || chipId <= 0 || chipId > 0xffff_ffffL
                || (authenticated && (chipId != authenticatedChipId
                    || !authenticatedModelNumber.equals(modelNumber)))) {
            return false;
        }
        authenticatedModelNumber = modelNumber;
        authenticatedChipId = chipId;
        authenticated = true;
        return true;
    }
}
