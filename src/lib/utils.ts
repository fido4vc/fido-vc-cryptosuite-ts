export function base64urlToUtf8(base64urlString: string): string {
  return Buffer.from(base64urlString, 'base64url').toString('utf8');
}
