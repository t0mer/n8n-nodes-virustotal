/** VirusTotal's URL identifier: unpadded base64url of the URL. */
export function urlId(url: string): string {
	return Buffer.from(url, 'utf8').toString('base64url');
}
