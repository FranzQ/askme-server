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
const ETH_RPC_URL = process.env.ETH_RPC_URL || 'https://sepolia.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161';

// Initialize providers
const ethProvider = new ethers.JsonRpcProvider(ETH_RPC_URL);

app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
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

app.listen(PORT, () => {
  console.log(`AskMe Server running on port ${PORT}`);
});

