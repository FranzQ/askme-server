import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { ethers, JsonRpcProvider } from 'ethers';
import { getEnsName, getEnsOwner } from '../utils/ens.js';
import { computeHashes } from '../utils/hash.js';

const router = Router();

export function createRequestsRouter(prisma: PrismaClient, ethProvider: JsonRpcProvider) {
  // Create verification request (POST /api/requests)
  router.post('/', async (req: Request, res: Response) => {
    try {
      const { verifierAddress, verifiedEns, field } = req.body;

      if (!verifierAddress || !verifiedEns || !field) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      const validFields = ['full_name', 'dob', 'passport_id'];
      if (!validFields.includes(field)) {
        return res.status(400).json({ error: `Invalid field. Must be one of: ${validFields.join(', ')}` });
      }

      // Get verifier ENS snapshot
      const verifierEns = await getEnsName(verifierAddress, ethProvider);

      // Check if there's already a pending request
      const existingRequest = await prisma.verificationRequest.findFirst({
        where: {
          verifierAddress: verifierAddress.toLowerCase(),
          verifiedEns: verifiedEns.toLowerCase(),
          field,
          status: 'pending',
        },
      });

      if (existingRequest) {
        return res.status(409).json({ error: 'A pending request already exists for this field' });
      }

      const request = await prisma.verificationRequest.create({
        data: {
          verifierAddress: verifierAddress.toLowerCase(),
          verifierEns: verifierEns || null,
          verifiedEns: verifiedEns.toLowerCase(),
          field,
          status: 'pending',
        },
      });

      res.status(201).json(request);
    } catch (error) {
      console.error('Error creating request:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Get a single request by ID (GET /api/requests/id/:id)
  router.get('/id/:id', async (req: Request<{ id: string }>, res: Response) => {
    try {
      const { id } = req.params;

      const request = await prisma.verificationRequest.findUnique({
        where: { id },
        select: {
          id: true,
          verifierAddress: true,
          verifierEns: true,
          verifiedEns: true,
          field: true,
          status: true,
          revealMode: true,
          requestedAt: true,
          approvedAt: true,
          expiresAt: true,
          completedAt: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      if (!request) {
        return res.status(404).json({ error: 'Request not found' });
      }

      res.json(request);
    } catch (error) {
      console.error('Error fetching request:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Get requests for an ENS (GET /api/requests/:ensName)
  router.get('/:ensName', async (req: Request<{ ensName: string }>, res: Response) => {
    try {
      const { ensName } = req.params;
      const { status } = req.query;

      const where: {
        verifiedEns: string;
        status?: string;
      } = {
        verifiedEns: ensName.toLowerCase(),
      };

      if (status) {
        where.status = status as string;
      }

      const requests = await prisma.verificationRequest.findMany({
        where,
        orderBy: {
          requestedAt: 'desc',
        },
        select: {
          id: true,
          verifierAddress: true,
          verifierEns: true,
          verifiedEns: true,
          field: true,
          status: true,
          revealMode: true,
          requestedAt: true,
          approvedAt: true,
          expiresAt: true,
          completedAt: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      res.json(requests);
    } catch (error) {
      console.error('Error fetching requests:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Approve request (POST /api/requests/:id/approve)
  router.post('/:id/approve', async (req: Request<{ id: string }>, res: Response) => {
    try {
      const { id } = req.params;
      const { verifiedEnsOwner, fieldValue, revealMode } = req.body;

      if (!fieldValue) {
        return res.status(400).json({ error: 'Missing fieldValue' });
      }

      if (!revealMode || (revealMode !== 'reveal' && revealMode !== 'no-reveal')) {
        return res.status(400).json({ error: 'Missing or invalid revealMode. Must be "reveal" or "no-reveal"' });
      }

      const request = await prisma.verificationRequest.findUnique({
        where: { id },
      });

      if (!request) {
        return res.status(404).json({ error: 'Request not found' });
      }

      if (request.status !== 'pending') {
        return res.status(400).json({ error: `Request is ${request.status}, cannot approve` });
      }

      // Verify ENS ownership (optional check - user should verify on their end)
      if (verifiedEnsOwner) {
        const currentOwner = await getEnsOwner(request.verifiedEns, ethProvider);
        if (currentOwner?.toLowerCase() !== verifiedEnsOwner.toLowerCase()) {
          return res.status(403).json({ error: 'ENS ownership verification failed' });
        }
      }

      // Compute hashes
      const { valueHash, fieldHash } = computeHashes(request.field, fieldValue);

      // Store revealed value temporarily (expires in 1 hour) only if reveal mode
      const expiresAt = revealMode === 'reveal' ? new Date(Date.now() + 60 * 60 * 1000) : null;

      const updated = await prisma.verificationRequest.update({
        where: { id },
        data: {
          status: 'approved',
          approvedAt: new Date(),
          expiresAt,
          revealMode,
          revealedValue: revealMode === 'reveal' ? fieldValue : null, // Only store if reveal mode
          fieldHash, // Always store fieldHash for verification
        },
      });

      // Log the reveal event (only if reveal mode)
      if (revealMode === 'reveal') {
        await prisma.fieldRevealLog.create({
          data: {
            requestId: id,
            verifiedEns: request.verifiedEns,
            field: request.field,
            verifierAddress: request.verifierAddress,
            verifierEns: request.verifierEns,
            valueHash, // Store hash for audit trail
          },
        });
      }

      res.json({
        ...updated,
        fieldHash, // Return fieldHash
        valueHash,
      });
    } catch (error) {
      console.error('Error approving request:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Reject request (POST /api/requests/:id/reject)
  router.post('/:id/reject', async (req: Request<{ id: string }>, res: Response) => {
    try {
      const { id } = req.params;

      const request = await prisma.verificationRequest.findUnique({
        where: { id },
      });

      if (!request) {
        return res.status(404).json({ error: 'Request not found' });
      }

      if (request.status !== 'pending') {
        return res.status(400).json({ error: `Request is ${request.status}, cannot reject` });
      }

      const updated = await prisma.verificationRequest.update({
        where: { id },
        data: { status: 'rejected' },
      });

      res.json(updated);
    } catch (error) {
      console.error('Error rejecting request:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Get revealed value (GET /api/requests/:id/reveal) - Verifier only
  router.get('/:id/reveal', async (req: Request<{ id: string }>, res: Response) => {
    try {
      const { id } = req.params;
      const { verifierAddress } = req.query;

      if (!verifierAddress) {
        return res.status(400).json({ error: 'Missing verifierAddress' });
      }

      const request = await prisma.verificationRequest.findUnique({
        where: { id },
      });

      if (!request) {
        return res.status(404).json({ error: 'Request not found' });
      }

      // Verify the requester is the verifier
      if (request.verifierAddress.toLowerCase() !== (verifierAddress as string).toLowerCase()) {
        return res.status(403).json({ error: 'Only the requester can access revealed value' });
      }

      if (request.status !== 'approved') {
        return res.status(400).json({ error: `Request is ${request.status}, value not available` });
      }

      // Check if this is a no-reveal request
      if (request.revealMode === 'no-reveal') {
        return res.status(400).json({ error: 'This request was approved with no-reveal mode. Use /verify-value endpoint to verify by typing the value.' });
      }

      // Check if expired
      if (request.expiresAt && request.expiresAt < new Date()) {
        // Clear the revealed value
        await prisma.verificationRequest.update({
          where: { id },
          data: {
            status: 'expired',
            revealedValue: null,
          },
        });
        return res.status(410).json({ error: 'Reveal access has expired' });
      }

      if (!request.revealedValue) {
        return res.status(404).json({ error: 'Value not available' });
      }

      // Compute fieldHash for the verifier
      const { fieldHash, valueHash } = computeHashes(request.field, request.revealedValue);

      res.json({
        value: request.revealedValue,
        valueHash,
        fieldHash,
        field: request.field,
        verifiedEns: request.verifiedEns,
        expiresAt: request.expiresAt,
      });
    } catch (error) {
      console.error('Error getting revealed value:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Verify typed value (POST /api/requests/:id/verify-value)
  // For no-reveal mode: verifier types value, system checks if it matches
  router.post('/:id/verify-value', async (req: Request<{ id: string }>, res: Response) => {
    try {
      const { id } = req.params;
      const { verifierAddress, typedValue } = req.body;

      if (!verifierAddress || !typedValue) {
        return res.status(400).json({ error: 'Missing verifierAddress or typedValue' });
      }

      const request = await prisma.verificationRequest.findUnique({
        where: { id },
      });

      if (!request) {
        return res.status(404).json({ error: 'Request not found' });
      }

      if (request.verifierAddress.toLowerCase() !== verifierAddress.toLowerCase()) {
        return res.status(403).json({ error: 'Only the verifier can verify the value' });
      }

      if (request.status !== 'approved') {
        return res.status(400).json({ error: `Request is ${request.status}, cannot verify` });
      }

      if (!request.fieldHash) {
        return res.status(400).json({ error: 'Request fieldHash not found. Request may not be approved yet.' });
      }

      // Compute hash of typed value
      const { fieldHash: computedFieldHash } = computeHashes(request.field, typedValue);

      // Check if typed value matches the stored fieldHash
      if (computedFieldHash.toLowerCase() !== request.fieldHash.toLowerCase()) {
        return res.status(400).json({ 
          error: 'Value does not match',
          matches: false,
        });
      }

      // Value matches! Return success with the fieldHash
      res.json({
        verified: true,
        matches: true,
        verifiedEns: request.verifiedEns,
        field: request.field,
        fieldHash: request.fieldHash,
        message: 'Value verified successfully! You can now create the attestation.',
      });
    } catch (error) {
      console.error('Error verifying value:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Mark request as completed (POST /api/requests/:id/complete)
  router.post('/:id/complete', async (req: Request<{ id: string }>, res: Response) => {
    try {
      const { id } = req.params;
      const { verifierAddress } = req.body;

      if (!verifierAddress) {
        return res.status(400).json({ error: 'Missing verifierAddress' });
      }

      const request = await prisma.verificationRequest.findUnique({
        where: { id },
      });

      if (!request) {
        return res.status(404).json({ error: 'Request not found' });
      }

      if (request.verifierAddress.toLowerCase() !== verifierAddress.toLowerCase()) {
        return res.status(403).json({ error: 'Only the requester can complete the request' });
      }

      const updated = await prisma.verificationRequest.update({
        where: { id },
        data: {
          status: 'completed',
          completedAt: new Date(),
          revealedValue: null, // Clear the value after attestation
        },
      });

      res.json(updated);
    } catch (error) {
      console.error('Error completing request:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Get requests by verifier (GET /api/requests/verifier/:address)
  router.get('/verifier/:address', async (req: Request<{ address: string }>, res: Response) => {
    try {
      const { address } = req.params;
      const { status } = req.query;

      const where: {
        verifierAddress: string;
        status?: string;
      } = {
        verifierAddress: address.toLowerCase(),
      };

      if (status) {
        where.status = status as string;
      }

      const requests = await prisma.verificationRequest.findMany({
        where,
        orderBy: {
          requestedAt: 'desc',
        },
      });

      res.json(requests);
    } catch (error) {
      console.error('Error fetching verifier requests:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Get reveal logs for an ENS (GET /api/requests/logs/:ensName)
  router.get('/logs/:ensName', async (req: Request<{ ensName: string }>, res: Response) => {
    try {
      const { ensName } = req.params;

      const logs = await prisma.fieldRevealLog.findMany({
        where: {
          verifiedEns: ensName.toLowerCase(),
        },
        orderBy: {
          revealedAt: 'desc',
        },
      });

      res.json(logs);
    } catch (error) {
      console.error('Error fetching reveal logs:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}

