import { ethers, JsonRpcProvider, Contract } from 'ethers';

// Base Names Registry (Base mainnet)
// For Base Sepolia testnet, this would be different
const BASENAME_REGISTRY_MAINNET = '0x4fFCC1b1475135D8A27c7081C8306F99F356E7E4';
const BASENAME_REGISTRY_SEPOLIA = '0x4fFCC1b1475135D8A27c7081C8306F99F356E7E4'; // Update with actual Base Sepolia address

const BASENAME_REGISTRY_ABI = [
  'function ownerOf(uint256 tokenId) external view returns (address)',
  'function namehash(string memory name) external pure returns (bytes32)',
  'function getExpiry(bytes32 node) external view returns (uint64)',
  'function resolver(bytes32 node) external view returns (address)',
] as const;

/**
 * Check if a name is a Base Name (.base.eth)
 */
export function isBaseName(name: string): boolean {
  return name.toLowerCase().endsWith('.base.eth');
}

/**
 * Check if a name is an ENS name (.eth)
 */
export function isEnsName(name: string): boolean {
  return name.toLowerCase().endsWith('.eth') && !isBaseName(name);
}

/**
 * Get Base Name for an address (reverse lookup on Base)
 */
export async function getBaseName(
  address: string,
  provider: JsonRpcProvider
): Promise<string | null> {
  try {
    // Base Names use reverse resolution similar to ENS
    // This is a simplified version - actual implementation may vary
    const reverseNode = ethers.namehash(`${address.slice(2).toLowerCase()}.addr.reverse`);
    // Would need to query Base Names resolver
    // For now, return null - implement based on Base Names API
    return null;
  } catch (error) {
    console.error('Error getting Base Name:', error);
    return null;
  }
}

/**
 * Get owner address of a Base Name
 */
export async function getBaseNameOwner(
  baseName: string,
  provider: JsonRpcProvider
): Promise<string | null> {
  try {
    const network = await provider.getNetwork();
    const registryAddress = network.chainId === 8453n 
      ? BASENAME_REGISTRY_MAINNET 
      : BASENAME_REGISTRY_SEPOLIA;
    
    const registry = new Contract(registryAddress, BASENAME_REGISTRY_ABI, provider);
    const namehash = ethers.namehash(baseName);
    
    // Base Names might use different methods - adjust based on actual contract
    // This is a placeholder implementation
    try {
      const owner = await registry.owner(namehash);
      return owner !== ethers.ZeroAddress ? owner : null;
    } catch {
      // Try alternative method if owner() doesn't work
      return null;
    }
  } catch (error) {
    console.error('Error getting Base Name owner:', error);
    return null;
  }
}

/**
 * Get expiry timestamp of a Base Name
 */
export async function getBaseNameExpiry(
  baseName: string,
  provider: JsonRpcProvider
): Promise<Date | null> {
  try {
    const network = await provider.getNetwork();
    const registryAddress = network.chainId === 8453n 
      ? BASENAME_REGISTRY_MAINNET 
      : BASENAME_REGISTRY_SEPOLIA;
    
    const registry = new Contract(registryAddress, BASENAME_REGISTRY_ABI, provider);
    const namehash = ethers.namehash(baseName);
    
    try {
      const expirySeconds = await registry.getExpiry(namehash);
      if (expirySeconds === 0n) {
        return null;
      }
      return new Date(Number(expirySeconds) * 1000);
    } catch {
      return null;
    }
  } catch (error) {
    console.error('Error getting Base Name expiry:', error);
    return null;
  }
}

/**
 * Get any name (ENS or Base Name) for an address
 * Tries ENS first, then Base Name
 */
export async function getNameForAddress(
  address: string,
  ensProvider: JsonRpcProvider,
  baseProvider: JsonRpcProvider | null
): Promise<{ name: string; type: 'ens' | 'basename' } | null> {
  // Try ENS first
  try {
    const ensName = await ensProvider.lookupAddress(address);
    if (ensName) {
      return { name: ensName, type: 'ens' };
    }
  } catch (error) {
    console.error('Error looking up ENS:', error);
  }

  // Try Base Name if provider available
  if (baseProvider) {
    try {
      const baseName = await getBaseName(address, baseProvider);
      if (baseName) {
        return { name: baseName, type: 'basename' };
      }
    } catch (error) {
      console.error('Error looking up Base Name:', error);
    }
  }

  return null;
}

