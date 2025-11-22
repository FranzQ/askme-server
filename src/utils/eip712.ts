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
// Domain must be: name=VerifyENS, version=1, chainId=11155111 (Sepolia), verifyingContract=0x0
const getDomain = (chainId: number): TypedDataDomain => {
  if (chainId !== 11155111) {
    throw new Error('Only chainId 11155111 (Sepolia) is supported');
  }
  return {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId: 11155111, // Sepolia testnet
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

    const domain = getDomain(11155111); // Sepolia chainId
    const types = VERIFICATION_TYPES;
    
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

    // Recover address from signature
    const recoveredAddress = ethers.verifyTypedData(
      domain,
      types,
      value,
      signature
    );

    // Check if recovered address matches verifierAddress
    return recoveredAddress.toLowerCase() === message.verifierAddress.toLowerCase();
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
  chainId: number = 11155111
): TypedData {
  const domain = getDomain(chainId);
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

