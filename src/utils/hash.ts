import { ethers } from 'ethers';

/**
 * Normalize a value (trim whitespace, lowercase for consistency)
 * Must match iOS implementation exactly
 */
export function normalizeValue(value: string): string {
  return value.trim().toLowerCase();
}

/**
 * Compute valueHash = keccak256(normalize(value))
 * Must match iOS implementation
 */
export function computeValueHash(value: string): string {
  const normalized = value.trim().toLowerCase();
  return ethers.keccak256(ethers.toUtf8Bytes(normalized));
}

/**
 * Compute fieldHash = keccak256("VerifyENS:" + field + ":" + valueHash)
 * This is what gets stored in the database and signed
 * Must match iOS implementation exactly
 */
export function computeFieldHash(field: string, valueHash: string): string {
  const input = `VerifyENS:${field}:${valueHash}`;
  return ethers.keccak256(ethers.toUtf8Bytes(input));
}

/**
 * Compute both valueHash and fieldHash for a field value
 * This matches the iOS CryptoUtils.computeHashes function
 */
export function computeHashes(field: string, value: string): { valueHash: string; fieldHash: string } {
  const normalized = value.trim().toLowerCase();
  const valueHash = ethers.keccak256(ethers.toUtf8Bytes(normalized));
  const fieldHash = computeFieldHash(field, valueHash);
  return { valueHash, fieldHash };
}

