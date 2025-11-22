import 'dotenv/config';
import express, { Request, Response } from 'express';
import cors from 'cors';
import { ethers, JsonRpcProvider } from 'ethers';
import { prisma } from './db.js';
import { getEnsName, getEnsOwner, getEnsExpiry } from './utils/ens.js';

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

app.listen(PORT, () => {
  console.log(`AskMe Server running on port ${PORT}`);
});

