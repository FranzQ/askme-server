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
 */
export async function getEnsExpiry(
  ensName: string,
  provider: JsonRpcProvider
): Promise<Date | null> {
  try {
    const registry = new Contract(ENS_REGISTRY, ENS_RESOLVER_ABI, provider);
    const namehash = ethers.namehash(ensName);
    const expirySeconds = await registry.nameExpires(namehash);
    
    if (expirySeconds === 0n) {
      return null; // No expiry (old ENS or not found)
    }
    
    // Convert to Date (expirySeconds is Unix timestamp)
    return new Date(Number(expirySeconds) * 1000);
  } catch (error) {
    console.error('Error getting ENS expiry:', error);
    return null;
  }
}

