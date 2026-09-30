import type {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class VirusTotalApi implements ICredentialType {
	name = 'virusTotalApi';

	icon = {
		light: 'file:../nodes/VirusTotal/virustotal.svg',
		dark: 'file:../nodes/VirusTotal/virustotal.dark.svg',
	} as const;

	displayName = 'VirusTotal API';

	documentationUrl = 'https://docs.virustotal.com/reference/overview';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'Get your key at virustotal.com: profile menu, then API key. The public API is for non-commercial use only and is limited to 4 requests per minute, 500 per day and 15.5K per month. The credential test costs one request.',
		},
		{
			displayName: 'Tier',
			name: 'tier',
			type: 'options',
			options: [
				{ name: 'Premium', value: 'premium' },
				{ name: 'Public', value: 'public' },
			],
			default: 'public',
			description: 'Premium enables the Premium-only operations',
		},
		{
			displayName: 'Requests per Minute',
			name: 'requestsPerMinute',
			type: 'number',
			typeOptions: { minValue: 1 },
			default: 4,
			description:
				'Client-side throttle applied to every request. Keep 4 on the public tier; raise it to match your contract on Premium.',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: { 'x-apikey': '={{$credentials.apiKey}}' },
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: 'https://www.virustotal.com/api/v3',
			url: '=/users/{{$credentials.apiKey}}',
			method: 'GET',
		},
	};
}
