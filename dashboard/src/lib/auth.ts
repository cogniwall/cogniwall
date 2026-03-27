import { NextRequest } from "next/server";

export function checkApiKey(request: NextRequest): boolean {
  const requiredKey = process.env.COGNIWALL_API_KEY;
  if (!requiredKey) return true;
  const providedKey = request.headers.get("X-CogniWall-Key");
  return providedKey === requiredKey;
}
