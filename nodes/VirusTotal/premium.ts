import { NodeOperationError } from 'n8n-workflow';
import type { OperationContext } from './types';

/**
 * Premium-only operations cannot be hidden in the UI, because n8n's displayOptions cannot
 * read credential fields. They are labelled in their descriptions and enforced here.
 */
export function requirePremium(ctx: OperationContext, feature: string): void {
	if (ctx.tier === 'premium') return;
	throw new NodeOperationError(
		ctx.fn.getNode(),
		`${feature} requires a VirusTotal Premium API key`,
		{
			itemIndex: ctx.index,
			description:
				'Set "Tier" to Premium in the VirusTotal API credential if your key is a Premium key.',
		},
	);
}
