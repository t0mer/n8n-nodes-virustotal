import { createHash } from 'crypto';
import type { IDataObject } from 'n8n-workflow';
import { NodeOperationError, randomString } from 'n8n-workflow';
import type { VtContext, Waiter } from './transport';
import { vtLookup, vtRequest } from './transport';

export const DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024;
export const MAX_UPLOAD_SIZE = 650 * 1024 * 1024;

export type UploadRoute = 'direct' | 'upload_url' | 'too_large';

export function uploadRoute(size: number): UploadRoute {
	if (size > MAX_UPLOAD_SIZE) return 'too_large';
	return size > DIRECT_UPLOAD_LIMIT ? 'upload_url' : 'direct';
}

export function sha256Hex(data: Buffer): string {
	return createHash('sha256').update(data).digest('hex');
}

export interface MultipartFile {
	field: string;
	fileName: string;
	data: Buffer;
}

export interface Multipart {
	body: Buffer;
	contentType: string;
}

function headerValue(value: string): string {
	return value.replace(/[\r\n"]/g, '_');
}

/** Builds a multipart/form-data body with an explicit boundary. */
export function buildMultipart(
	file: MultipartFile,
	fields: Record<string, string> = {},
	boundary: string = `----n8nVirusTotal${randomString(24)}`,
): Multipart {
	const chunks: Buffer[] = [];
	for (const [name, value] of Object.entries(fields)) {
		chunks.push(
			Buffer.from(
				`--${boundary}\r\nContent-Disposition: form-data; name="${headerValue(name)}"\r\n\r\n${value}\r\n`,
			),
		);
	}
	chunks.push(
		Buffer.from(
			`--${boundary}\r\nContent-Disposition: form-data; name="${headerValue(file.field)}"; filename="${headerValue(file.fileName)}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
		),
		file.data,
		Buffer.from(`\r\n--${boundary}--\r\n`),
	);
	return { body: Buffer.concat(chunks), contentType: `multipart/form-data; boundary=${boundary}` };
}

export interface UploadOptions {
	data: Buffer;
	fileName: string;
	password?: string;
	checkHashFirst: boolean;
	throttle?: Waiter;
	itemIndex?: number;
}

export type UploadResult =
	| { kind: 'existing'; sha256: string; report: IDataObject }
	| { kind: 'submitted'; sha256: string; analysisId: string };

interface AnalysisRef {
	data?: { id?: string };
}

/**
 * Uploads a file for scanning. With `checkHashFirst`, a file VirusTotal already knows
 * is not uploaded; its existing report is returned instead.
 */
export async function uploadFile(ctx: VtContext, options: UploadOptions): Promise<UploadResult> {
	const sha256 = sha256Hex(options.data);

	if (options.checkHashFirst) {
		const report = await vtLookup<IDataObject>(ctx, {
			path: `/files/${sha256}`,
			throttle: options.throttle,
		});
		if (report) return { kind: 'existing', sha256, report };
	}

	const route = uploadRoute(options.data.length);
	if (route === 'too_large') {
		throw new NodeOperationError(
			ctx.getNode(),
			'The file is larger than 650 MB, which is the VirusTotal upload limit',
			{ itemIndex: options.itemIndex },
		);
	}

	const multipart = buildMultipart(
		{ field: 'file', fileName: options.fileName, data: options.data },
		options.password ? { password: options.password } : {},
	);
	const headers = { 'content-type': multipart.contentType };

	let response: AnalysisRef;
	if (route === 'direct') {
		response = await vtRequest<AnalysisRef>(ctx, {
			method: 'POST',
			path: '/files',
			body: multipart.body,
			headers,
			throttle: options.throttle,
		});
	} else {
		const target = await vtRequest<{ data?: string }>(ctx, {
			path: '/files/upload_url',
			throttle: options.throttle,
		});
		if (typeof target.data !== 'string' || !target.data) {
			throw new NodeOperationError(ctx.getNode(), 'VirusTotal did not return an upload URL', {
				itemIndex: options.itemIndex,
			});
		}
		// The upload URL is pre-authorized and single-use: no API key header.
		response = await vtRequest<AnalysisRef>(ctx, {
			method: 'POST',
			path: target.data,
			absolute: true,
			unauthenticated: true,
			body: multipart.body,
			headers,
			throttle: options.throttle,
		});
	}

	const analysisId = response.data?.id;
	if (!analysisId) {
		throw new NodeOperationError(
			ctx.getNode(),
			'VirusTotal did not return an analysis ID for the upload',
			{
				itemIndex: options.itemIndex,
			},
		);
	}
	return { kind: 'submitted', sha256, analysisId };
}
