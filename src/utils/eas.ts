// Chain IDs for EAS explorer URLs
const BASE_SEPOLIA_CHAIN_ID = 84532;
const BASE_MAINNET_CHAIN_ID = 8453;
const WORLD_CHAIN_MAINNET_CHAIN_ID = 480;

/**
 * Get explorer URL for an attestation UID
 * Note: Attestations are created client-side by users signing transactions
 * This function only generates the explorer URL for viewing attestations
 */
export function getAttestationExplorerUrl(attestationUid: string, chainId: number = BASE_SEPOLIA_CHAIN_ID): string {
  if (chainId === BASE_SEPOLIA_CHAIN_ID) {
    return `https://base-sepolia.easscan.org/attestation/view/${attestationUid}`;
  } else if (chainId === BASE_MAINNET_CHAIN_ID) {
    return `https://base.easscan.org/attestation/view/${attestationUid}`;
  } else if (chainId === WORLD_CHAIN_MAINNET_CHAIN_ID) {
    // World Chain EAS explorer (update URL when available)
    return `https://worldchain.easscan.org/attestation/view/${attestationUid}`;
  }
  return `https://easscan.org/attestation/view/${attestationUid}`;
}

