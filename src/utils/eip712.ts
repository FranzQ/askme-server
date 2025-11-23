import { ethers, TypedDataDomain } from 'ethers';

const DOMAIN_NAME = 'VerifyENS';
const DOMAIN_VERSION = '1';

export interface VerificationMessage {
  verifierAddress: string;
  verifiedEns: string;
  field: string;
  valueHash: string;
  methodUrl?: string;
  expiresAt?: string;
}

// EIP-712 domain and types for verification attestation
// Domain must be: name=VerifyENS, version=1, chainId=84532 (Base Sepolia), verifyingContract=0x0
const BASE_SEPOLIA_CHAIN_ID = 84532;

const getDomain = (chainId: number): TypedDataDomain => {
  // Only accept Base Sepolia
  if (chainId !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error(`Only chainId ${BASE_SEPOLIA_CHAIN_ID} (Base Sepolia) is supported`);
  }
  return {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId: BASE_SEPOLIA_CHAIN_ID, // Always use Base Sepolia
    verifyingContract: ethers.ZeroAddress, // Must be zero address
  };
};

const VERIFICATION_TYPES = {
  Verification: [
    { name: 'verifierAddress', type: 'address' },
    { name: 'verifiedEns', type: 'string' },
    { name: 'field', type: 'string' },
    { name: 'valueHash', type: 'bytes32' },
    { name: 'methodUrl', type: 'string' },
    { name: 'expiresAt', type: 'uint256' },
  ],
};

/**
 * Verify an EIP-712 signature for a verification
 */
export async function verifyVerification(
  message: VerificationMessage,
  signature: string
): Promise<boolean> {
  try {
    // Convert valueHash to bytes32 if it's a hex string
    const valueHashBytes = ethers.isHexString(message.valueHash, 32)
      ? message.valueHash
      : ethers.keccak256(ethers.toUtf8Bytes(message.valueHash));

    const types = VERIFICATION_TYPES;
    
    // Handle expiresAt - it can be a Date string, number (timestamp), BigInt, or undefined
    // The client sends it as a timestamp string or ISO date string
    let expiresAtValue: bigint;
    if (message.expiresAt === undefined || message.expiresAt === null || message.expiresAt === '') {
      expiresAtValue = BigInt(0);
    } else if (typeof message.expiresAt === 'bigint') {
      expiresAtValue = message.expiresAt;
    } else if (typeof message.expiresAt === 'number') {
      expiresAtValue = BigInt(message.expiresAt);
    } else if (typeof message.expiresAt === 'string') {
      // Try to parse as ISO date string first
      const date = new Date(message.expiresAt);
      if (!isNaN(date.getTime())) {
        expiresAtValue = BigInt(Math.floor(date.getTime() / 1000));
      } else {
        // Try as timestamp string (seconds)
        const timestamp = parseInt(message.expiresAt, 10);
        if (!isNaN(timestamp)) {
          expiresAtValue = BigInt(timestamp);
        } else {
          expiresAtValue = BigInt(0);
        }
      }
    } else {
      expiresAtValue = BigInt(0);
    }
    
    console.log('Parsed expiresAt:', expiresAtValue, 'from:', message.expiresAt);

    const value = {
      verifierAddress: message.verifierAddress,
      verifiedEns: message.verifiedEns,
      field: message.field,
      valueHash: valueHashBytes,
      methodUrl: message.methodUrl || '',
      expiresAt: expiresAtValue,
    };

    // Verify signature with Base Sepolia only
    const domain = getDomain(BASE_SEPOLIA_CHAIN_ID);
    console.log('Verifying signature with domain:', domain);
    console.log('Message value:', value);
    console.log('Signature:', signature);
    
    const recoveredAddress = ethers.verifyTypedData(
      domain,
      types,
      value,
      signature
    );

    console.log('Recovered address:', recoveredAddress);
    console.log('Expected address:', message.verifierAddress);
    const matches = recoveredAddress.toLowerCase() === message.verifierAddress.toLowerCase();
    console.log('Signature matches:', matches);

    // Check if recovered address matches verifierAddress
    return matches;
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

export interface TypedData {
  domain: TypedDataDomain;
  types: typeof VERIFICATION_TYPES;
  primaryType: 'Verification';
  message: {
    verifierAddress: string;
    verifiedEns: string;
    field: string;
    valueHash: string;
    methodUrl: string;
    expiresAt: bigint;
  };
}

/**
 * Generate EIP-712 typed data for signing (used by client)
 */
export function getVerificationTypedData(
  message: VerificationMessage,
  chainId: number = BASE_SEPOLIA_CHAIN_ID
): TypedData {
  const domain = getDomain(BASE_SEPOLIA_CHAIN_ID); // Always use Base Sepolia
  const types = VERIFICATION_TYPES;

  const valueHashBytes = ethers.isHexString(message.valueHash, 32)
    ? message.valueHash
    : ethers.keccak256(ethers.toUtf8Bytes(message.valueHash));

  const value = {
    verifierAddress: message.verifierAddress,
    verifiedEns: message.verifiedEns,
    field: message.field,
    valueHash: valueHashBytes,
    methodUrl: message.methodUrl || '',
    expiresAt: message.expiresAt 
      ? BigInt(Math.floor(new Date(message.expiresAt).getTime() / 1000))
      : BigInt(0),
  };

  return {
    domain,
    types,
    primaryType: 'Verification',
    message: value,
  };
}

