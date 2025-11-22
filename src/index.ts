import 'dotenv/config';
import express, { Request, Response } from 'express';
import cors from 'cors';
import { ethers, JsonRpcProvider } from 'ethers';
import { prisma } from './db.js';
import { getEnsName, getEnsOwner, getEnsExpiry } from './utils/ens.js';
import { verifyVerification, VerificationMessage } from './utils/eip712.js';
import { getAttestationExplorerUrl } from './utils/eas.js';
import { createRequestsRouter } from './routes/requests.js';

const app = express();
const PORT = process.env.PORT || 8080;
// Use public Sepolia RPC endpoint (no API key required)
// Alternatives: https://rpc.ankr.com/eth_sepolia, https://ethereum-sepolia-rpc.publicnode.com
// Or set ETH_RPC_URL in .env with your own RPC endpoint
const ETH_RPC_URL = process.env.ETH_RPC_URL || 'https://rpc.ankr.com/eth_sepolia';

// Initialize providers
const ethProvider = new ethers.JsonRpcProvider(ETH_RPC_URL);

app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Get ENS names for an address (GET /api/ensNames/:address)
app.get('/api/ensNames/:address', async (req: Request<{ address: string }>, res: Response) => {
  const { address } = req.params;

  try {

    // Normalize address to lowercase for The Graph query
    const normalizedAddress = address.toLowerCase();

    // Query The Graph ENS subgraph to get all names for this address
    // Try multiple subgraph endpoints and query types
    const namesSet = new Set<string>();

    // First, try The Graph subgraph (if available for Sepolia)
    try {
      // Try the official ENS subgraph for Sepolia
      const subgraphUrl = 'https://api.studio.thegraph.com/query/49574/enssepolia/version/latest';

      const query = `
        {
          domains(where: { owner: "${normalizedAddress}" }) {
            name
          }
          wrappedDomains(where: { owner: "${normalizedAddress}" }) {
            name
          }
          registrations(where: { registrant: "${normalizedAddress}" }) {
            domain {
              name
            }
          }
        }
      `;

      const response = await fetch(subgraphUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query }),
      });

      if (response.ok) {
        const data = await response.json() as any;

        // Add names from domains
        if (data.data?.domains) {
          for (const domain of data.data.domains) {
            if (domain.name) {
              namesSet.add(domain.name);
            }
          }
        }

        // Add names from wrapped domains
        if (data.data?.wrappedDomains) {
          for (const domain of data.data.wrappedDomains) {
            if (domain.name) {
              namesSet.add(domain.name);
            }
          }
        }

        // Add names from registrations
        if (data.data?.registrations) {
          for (const registration of data.data.registrations) {
            if (registration.domain?.name) {
              namesSet.add(registration.domain.name);
            }
          }
        }

        console.log(`The Graph returned ${namesSet.size} names for ${address}`);
      }
    } catch (graphError) {
      console.log('The Graph query failed, using fallback methods:', graphError);
    }

    // Always include reverse lookup (primary name)
    try {
      const reverseName = await getEnsName(address, ethProvider);
      if (reverseName) {
        namesSet.add(reverseName);
        console.log(`Reverse lookup found: ${reverseName}`);
      }
    } catch (reverseError) {
      console.log('Reverse lookup failed:', reverseError);
    }

    // If we still have no names, try querying the chain directly
    // This is a fallback that queries recent Transfer events
    if (namesSet.size === 0) {
      console.log('No names found via subgraph or reverse lookup, trying direct chain query...');
      // Note: Direct chain querying would require scanning events, which is slow
      // For now, we'll just return what we have
    }

    // Filter out reverse records (technical internal names, not user-facing ENS names)
    // Reverse records look like: [hash].addr.reverse
    const filteredNames = Array.from(namesSet).filter((name: string) => {
      // Exclude reverse records
      if (name.endsWith('.addr.reverse') || name.startsWith('[')) {
        return false;
      }
      // Only include valid ENS names (ending with .eth or other TLDs)
      return name.includes('.');
    });

    console.log(`Returning ${filteredNames.length} ENS names for ${address}:`, filteredNames);

    res.json({ names: filteredNames });
  } catch (error) {
    console.error('Error fetching ENS names:', error);

    // Fallback to reverse lookup on error
    try {
      const ensName = await getEnsName(req.params.address, ethProvider);
      const names: string[] = [];
      if (ensName) {
        // Filter out reverse records
        if (!ensName.endsWith('.addr.reverse') && !ensName.startsWith('[') && ensName.includes('.')) {
          names.push(ensName);
        }
      }
      res.json({ names });
    } catch (fallbackError) {
      console.error('Fallback error:', fallbackError);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Resolve ENS owner (GET /api/resolveOwner/:ensName)
app.get('/api/resolveOwner/:ensName', async (req: Request<{ ensName: string }>, res: Response) => {
  try {
    const { ensName } = req.params;
    const owner = await getEnsOwner(ensName, ethProvider);
    const expiry = await getEnsExpiry(ensName, ethProvider);

    res.json({
      ensName: ensName.toLowerCase(),
      owner: owner || null,
      expiry: expiry ? expiry.toISOString() : null,
      isValid: owner !== null && (!expiry || expiry > new Date()),
    });
  } catch (error) {
    console.error('Error resolving ENS owner:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify wallet signature for ENS ownership (POST /api/verifyOwnership)
interface VerifyOwnershipBody {
  ensName: string;
  address: string;
  signature: string;
  message?: string;
}

app.post('/api/verifyOwnership', async (req: Request<{}, {}, VerifyOwnershipBody>, res: Response) => {
  try {
    const { ensName, address, signature, message } = req.body;

    if (!ensName || !address || !signature) {
      return res.status(400).json({ error: 'Missing required fields: ensName, address, signature' });
    }

    const currentOwner = await getEnsOwner(ensName, ethProvider);
    if (!currentOwner) {
      return res.status(404).json({ error: 'ENS name not found or invalid' });
    }

    if (currentOwner.toLowerCase() !== address.toLowerCase()) {
      return res.status(403).json({ error: 'Address does not own this ENS name' });
    }

    const messageToVerify = message || `Verify ENS ownership: ${ensName}\n\nThis signature proves you own the ENS name.`;

    try {
      const messageHash = ethers.hashMessage(messageToVerify);
      const recoveredAddress = ethers.recoverAddress(messageHash, signature);
      const isValid = recoveredAddress.toLowerCase() === address.toLowerCase();

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid signature' });
      }

      res.json({
        verified: true,
        ensName: ensName.toLowerCase(),
        address: address.toLowerCase(),
        message: messageToVerify,
      });
    } catch (error) {
      console.error('Signature verification error:', error);
      return res.status(400).json({ error: 'Invalid signature format' });
    }
  } catch (error) {
    console.error('Error verifying ownership:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verification requests routes
app.use('/api/requests', createRequestsRouter(prisma, ethProvider));

interface CreateVerificationBody {
  verifierAddress: string;
  verifiedEns: string;
  field: string;
  fieldHash: string;
  methodUrl?: string;
  sig: string;
  attestationUid?: string;
}

// Create verification with ENS (POST /api/verifications)
app.post('/api/verifications', async (req: Request<{}, {}, CreateVerificationBody>, res: Response) => {
  try {
    const { verifierAddress, verifiedEns, field, fieldHash, methodUrl, sig, attestationUid } = req.body;

    if (!verifierAddress || !verifiedEns || !field || !fieldHash || !sig) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const validFields = ['full_name', 'dob', 'passport_id'];
    if (!validFields.includes(field)) {
      return res.status(400).json({ error: `Invalid field. Must be one of: ${validFields.join(', ')}` });
    }

    const verifierEnsSnapshot = await getEnsName(verifierAddress, ethProvider);
    if (!verifierEnsSnapshot) {
      return res.status(403).json({
        error: 'Verifier must own an ENS name. Use /verify/world for World ID verification.'
      });
    }

    const verifierEnsExpiry = await getEnsExpiry(verifierEnsSnapshot, ethProvider);
    if (verifierEnsExpiry && verifierEnsExpiry < new Date()) {
      return res.status(403).json({
        error: 'Verifier ENS name has expired. Please renew your ENS name.'
      });
    }

    const message: VerificationMessage = {
      verifierAddress,
      verifiedEns,
      field,
      valueHash: fieldHash,
      methodUrl: methodUrl || undefined,
      expiresAt: undefined,
    };

    const isValid = await verifyVerification(message, sig);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const verifiedEnsOwner = await getEnsOwner(verifiedEns, ethProvider);
    const verifiedEnsExpiry = await getEnsExpiry(verifiedEns, ethProvider);

    const verification = await prisma.verification.create({
      data: {
        verifiedEns: verifiedEns.toLowerCase(),
        field,
        fieldHash,
        verifierType: 'ens',
        verifierId: verifierAddress.toLowerCase(),
        ensName: verifierEnsSnapshot,
        ownerSnapshot: verifiedEnsOwner || null,
        expirySnapshot: verifiedEnsExpiry || null,
        methodUrl: methodUrl || null,
        status: 'active',
        sig,
        attestationUid,
      },
    });

    await prisma.verificationRequest.updateMany({
      where: {
        verifierAddress: verifierAddress.toLowerCase(),
        verifiedEns: verifiedEns.toLowerCase(),
        field,
        status: 'approved',
      },
      data: {
        status: 'completed',
        completedAt: new Date(),
        revealedValue: null,
      },
    });

    const response: any = { ...verification };
    if (attestationUid) {
      response.attestationExplorerUrl = getAttestationExplorerUrl(attestationUid, 84532);
    }

    res.status(201).json(response);
  } catch (error) {
    console.error('Error creating verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

interface VerifyWorldBody {
  verifiedEns: string;
  field: string;
  fieldHash: string;
  worldProof: {
    merkleRoot: string;
    nullifierHash: string;
    proof: string;
    signal?: string;
  };
  methodUrl?: string;
}

// Verify with World ID (POST /verify/world)
app.post('/verify/world', async (req: Request<{}, {}, VerifyWorldBody>, res: Response) => {
  try {
    const { verifiedEns, field, fieldHash, worldProof, methodUrl } = req.body;

    if (!verifiedEns || !field || !fieldHash || !worldProof) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const validFields = ['full_name', 'dob', 'passport_id'];
    if (!validFields.includes(field)) {
      return res.status(400).json({ error: `Invalid field. Must be one of: ${validFields.join(', ')}` });
    }

    const WORLDCOIN_APP_ID = process.env.WORLDCOIN_APP_ID;
    if (!WORLDCOIN_APP_ID) {
      return res.status(500).json({ error: 'Worldcoin App ID not configured' });
    }

    const verifyResponse = await fetch('https://developer.worldcoin.org/api/v1/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        app_id: WORLDCOIN_APP_ID,
        merkle_root: worldProof.merkleRoot,
        nullifier_hash: worldProof.nullifierHash,
        proof: worldProof.proof,
        verification_level: 'orb',
        action: 'verify-ens',
        signal: worldProof.signal || `${verifiedEns}:${fieldHash}`,
      }),
    });

    if (!verifyResponse.ok) {
      const errorData: any = await verifyResponse.json().catch(() => ({ detail: 'Unknown error' }));
      return res.status(400).json({ error: `World ID verification failed: ${errorData.detail || 'Invalid proof'}` });
    }

    const verifyData: any = await verifyResponse.json();
    if (!verifyData.verified) {
      return res.status(400).json({ error: 'World ID proof verification failed' });
    }

    const existingProof = await prisma.worldProof.findUnique({
      where: { nullifierHash: worldProof.nullifierHash },
    });

    if (existingProof) {
      return res.status(400).json({ error: 'This World ID proof has already been used' });
    }

    await prisma.worldProof.create({
      data: {
        nullifierHash: worldProof.nullifierHash,
        merkleRoot: worldProof.merkleRoot,
        proof: worldProof.proof,
        signal: worldProof.signal || `${verifiedEns}:${fieldHash}`,
      },
    });

    const verifiedEnsOwner = await getEnsOwner(verifiedEns, ethProvider);
    const verifiedEnsExpiry = await getEnsExpiry(verifiedEns, ethProvider);

    const verification = await prisma.verification.create({
      data: {
        verifiedEns: verifiedEns.toLowerCase(),
        field,
        fieldHash,
        verifierType: 'world',
        verifierId: worldProof.nullifierHash,
        ensName: null,
        ownerSnapshot: verifiedEnsOwner || null,
        expirySnapshot: verifiedEnsExpiry || null,
        methodUrl: methodUrl || null,
        status: 'active',
        sig: null,
        attestationUid: null,
      },
    });

    res.status(201).json(verification);
  } catch (error: any) {
    console.error('Error verifying with World ID:', error);
    res.status(500).json({ error: `Internal server error: ${error.message || 'Unknown error'}` });
  }
});

interface VerificationQuery {
  field?: string;
  status?: string;
}

// Get verifications for an ENS (GET /api/verifications/:subjectEns)
app.get('/api/verifications/:subjectEns', async (req: Request<{ subjectEns: string }, {}, {}, VerificationQuery>, res: Response) => {
  try {
    const { subjectEns } = req.params;
    const { field, status } = req.query;

    const where: {
      verifiedEns: string;
      field?: string;
      status?: string;
    } = {
      verifiedEns: subjectEns.toLowerCase(),
    };

    if (field) {
      where.field = field;
    }

    if (status) {
      where.status = status;
    }

    const verifications = await prisma.verification.findMany({
      where,
      orderBy: {
        createdAt: 'desc',
      },
    });

    const enriched = await Promise.all(
      verifications.map(async (v) => {
        const currentOwner = await getEnsOwner(v.verifiedEns, ethProvider);
        const currentExpiry = await getEnsExpiry(v.verifiedEns, ethProvider);

        const ownershipMatches = currentOwner?.toLowerCase() === v.ownerSnapshot?.toLowerCase();
        const expiryValid = !v.expirySnapshot ||
          (currentExpiry && currentExpiry > new Date() &&
            (!v.expirySnapshot || currentExpiry.getTime() === v.expirySnapshot.getTime()));

        const result: any = { ...v };
        if (v.attestationUid) {
          result.attestationExplorerUrl = getAttestationExplorerUrl(v.attestationUid, 84532);
        }

        const isEnsValid = ownershipMatches && expiryValid;

        let verifierValid = true;
        if (v.verifierType === 'ens' && v.ensName) {
          const verifierEnsExpiry = await getEnsExpiry(v.ensName, ethProvider);
          if (verifierEnsExpiry && verifierEnsExpiry < new Date()) {
            verifierValid = false;
            if (v.status === 'active') {
              await prisma.verification.update({
                where: { id: v.id },
                data: { status: 'revoked', revokedAt: new Date() },
              });
            }
          }
        } else if (v.verifierType === 'world') {
          const worldProof = await prisma.worldProof.findUnique({
            where: { nullifierHash: v.verifierId },
          });
          verifierValid = worldProof !== null;
        }

        const isActive = v.status === 'active';
        const isValid = isActive && isEnsValid && verifierValid;

        return {
          ...result,
          isValid,
          isEnsValid,
          isActive,
          ownershipMatches,
          expiryValid,
          verifierValid,
        };
      })
    );

    res.json(enriched);
  } catch (error) {
    console.error('Error fetching verifications:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get verification statistics (GET /api/verifications/:subjectEns/stats)
app.get('/api/verifications/:subjectEns/stats', async (req: Request<{ subjectEns: string }>, res: Response) => {
  try {
    const { subjectEns } = req.params;

    const verifications = await prisma.verification.findMany({
      where: {
        verifiedEns: subjectEns.toLowerCase(),
        status: 'active',
      },
      select: {
        field: true,
        verifierType: true,
        verifierId: true,
        ensName: true,
        createdAt: true,
      },
    });

    const statsByField: Record<string, {
      count: number;
      verifiers: Array<{
        verifierType: string;
        verifierId: string;
        ensName: string | null;
        verifiedAt: string;
      }>;
    }> = {};

    verifications.forEach((v) => {
      if (!statsByField[v.field]) {
        statsByField[v.field] = {
          count: 0,
          verifiers: [],
        };
      }

      const existingVerifier = statsByField[v.field].verifiers.find(
        (ver) => ver.verifierId === v.verifierId && ver.verifierType === v.verifierType
      );

      if (!existingVerifier) {
        statsByField[v.field].count++;
        statsByField[v.field].verifiers.push({
          verifierType: v.verifierType,
          verifierId: v.verifierId,
          ensName: v.ensName,
          verifiedAt: v.createdAt.toISOString(),
        });
      }
    });

    const totalFields = Object.keys(statsByField).length;
    const allVerifiers = Object.values(statsByField).flatMap((s) => s.verifiers);
    const totalVerifiers = new Set(
      allVerifiers.map((v) => `${v.verifierType}:${v.verifierId}`)
    ).size;
    const ensVerifiersCount = allVerifiers.filter((v) => v.verifierType === 'ens').length;
    const worldVerifiersCount = allVerifiers.filter((v) => v.verifierType === 'world').length;

    res.json({
      subjectEns: subjectEns.toLowerCase(),
      totalFields,
      totalVerifiers,
      ensVerifiers: ensVerifiersCount,
      worldVerifiers: worldVerifiersCount,
      byField: statsByField,
    });
  } catch (error) {
    console.error('Error fetching verification stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

interface UpdateAttestationBody {
  attestationUid: string;
  verifierAddress: string;
}

// Update verification with attestation UID (POST /api/verifications/:id/attestation)
app.post('/api/verifications/:id/attestation', async (req: Request<{ id: string }, {}, UpdateAttestationBody>, res: Response) => {
  try {
    const { id } = req.params;
    const { attestationUid, verifierAddress } = req.body;

    if (!attestationUid || !verifierAddress) {
      return res.status(400).json({ error: 'Missing attestationUid or verifierAddress' });
    }

    const verification = await prisma.verification.findUnique({
      where: { id },
    });

    if (!verification) {
      return res.status(404).json({ error: 'Verification not found' });
    }

    if (verification.verifierType === 'ens' && verification.verifierId.toLowerCase() !== verifierAddress.toLowerCase()) {
      return res.status(403).json({ error: 'Only the original verifier can add attestation' });
    }

    const updated = await prisma.verification.update({
      where: { id },
      data: { attestationUid },
    });

    const response: any = { ...updated };
    response.attestationExplorerUrl = getAttestationExplorerUrl(attestationUid, 84532);

    res.json(response);
  } catch (error) {
    console.error('Error updating attestation:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

interface RevokeVerificationBody {
  verifierId: string;
  verifierType: string;
}

// Revoke verification (POST /api/verifications/:id/revoke)
app.post('/api/verifications/:id/revoke', async (req: Request<{ id: string }, {}, RevokeVerificationBody>, res: Response) => {
  try {
    const { id } = req.params;
    const { verifierId, verifierType } = req.body;

    if (!verifierId || !verifierType) {
      return res.status(400).json({ error: 'Missing verifierId or verifierType' });
    }

    const verification = await prisma.verification.findUnique({
      where: { id },
    });

    if (!verification) {
      return res.status(404).json({ error: 'Verification not found' });
    }

    if (verification.verifierId.toLowerCase() !== verifierId.toLowerCase() ||
      verification.verifierType !== verifierType) {
      return res.status(403).json({ error: 'Only the original verifier can revoke' });
    }

    const updated = await prisma.verification.update({
      where: { id },
      data: { status: 'revoked', revokedAt: new Date() },
    });

    res.json(updated);
  } catch (error) {
    console.error('Error revoking verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get verifications by verifier (GET /api/verifications/verifier/:verifierType/:verifierId)
app.get('/api/verifications/verifier/:verifierType/:verifierId', async (req: Request<{ verifierType: string; verifierId: string }, {}, {}, { status?: string }>, res: Response) => {
  try {
    const { verifierType, verifierId } = req.params;
    const { status } = req.query;

    if (verifierType !== 'ens' && verifierType !== 'world') {
      return res.status(400).json({ error: 'Invalid verifierType. Must be "ens" or "world"' });
    }

    const where: {
      verifierType: string;
      verifierId: string;
      status?: string;
    } = {
      verifierType,
      verifierId: verifierId.toLowerCase(),
    };

    if (status) {
      where.status = status;
    }

    const verifications = await prisma.verification.findMany({
      where,
      orderBy: {
        createdAt: 'desc',
      },
    });

    res.json(verifications);
  } catch (error) {
    console.error('Error fetching verifier verifications:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check if address has World ID proof (GET /api/worldcoin/:address)
app.get('/api/worldcoin/:address', async (req: Request<{ address: string }>, res: Response) => {
  try {
    res.json({ verified: false });
  } catch (error: any) {
    console.error('Error fetching Worldcoin verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`AskMe Server running on port ${PORT}`);
});

