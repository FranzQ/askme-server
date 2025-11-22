import 'dotenv/config';
import express, { Request, Response } from 'express';
import cors from 'cors';
import { ethers, JsonRpcProvider } from 'ethers';
import { prisma } from './db.js';
import { getEnsName, getEnsOwner, getEnsExpiry } from './utils/ens.js';
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

app.listen(PORT, () => {
  console.log(`AskMe Server running on port ${PORT}`);
});

