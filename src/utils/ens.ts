import { ethers, JsonRpcProvider, Contract } from 'ethers';

const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';
const ENS_RESOLVER_ABI = [
  'function resolver(bytes32 node) external view returns (address)',
  'function owner(bytes32 node) external view returns (address)',
  'function nameExpires(bytes32 node) external view returns (uint64)',
] as const;

/**
 * Get ENS name for an address (reverse lookup)
 */
export async function getEnsName(
  address: string,
  provider: JsonRpcProvider
): Promise<string | null> {
  try {
    const name = await provider.lookupAddress(address);
    return name || null;
  } catch (error) {
    console.error('Error getting ENS name:', error);
    return null;
  }
}

/**
 * Get owner address of an ENS name
 */
export async function getEnsOwner(
  ensName: string,
  provider: JsonRpcProvider
): Promise<string | null> {
  try {
    const registry = new Contract(ENS_REGISTRY, ENS_RESOLVER_ABI, provider);
    const namehash = ethers.namehash(ensName);
    const owner = await registry.owner(namehash);
    return owner !== ethers.ZeroAddress ? owner : null;
  } catch (error) {
    console.error('Error getting ENS owner:', error);
    return null;
  }
}

/**
 * Get expiry timestamp of an ENS name
 * Note: The ENS Registry doesn't have nameExpires. This would require
 * querying the Registrar Controller contract, which varies by TLD.
 * For hackathon purposes, we'll return null and skip expiry validation.
 */
export async function getEnsExpiry(
  ensName: string,
  provider: JsonRpcProvider
): Promise<Date | null> {
  try {
    // First check if the name exists by getting the owner
    const owner = await getEnsOwner(ensName, provider);
    if (!owner) {
      return null; // Name doesn't exist
    }

    // The ENS Registry contract doesn't have nameExpires function
    // For hackathon, we'll skip expiry checking and return null
    // In production, you'd need to query the appropriate Registrar Controller
    return null;
  } catch (error: any) {
    // Silently handle errors - expiry checking is optional for hackathon
    // Only log if it's not a contract call error
    if (error?.code !== 'CALL_EXCEPTION') {
      console.error('Error getting ENS expiry:', error);
    }
    return null;
  }
}

