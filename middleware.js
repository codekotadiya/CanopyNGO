import { next } from '@vercel/functions/middleware';
import { handleLaunchpadHandoff } from './lib/launchpad-handoff.js';

export default async function middleware(request) {
  const response = await handleLaunchpadHandoff(request, process.env);
  if (response) return response;
  return next();
}
