import type { IDataObject, IExecuteFunctions, INodeProperties } from 'n8n-workflow';
import type { Throttle } from '../../shared/throttle';

export type Tier = 'public' | 'premium';

export interface OperationContext {
	fn: IExecuteFunctions;
	index: number;
	throttle: Throttle;
	tier: Tier;
	/** Records the indicator being processed so failures can report it. */
	setIndicator(value: string): void;
}

/** One operation; returns one item, or several items that all pair with the input item. */
export type OperationHandler = (ctx: OperationContext) => Promise<IDataObject | IDataObject[]>;

export interface ResourceModule {
	properties: INodeProperties[];
	handlers: Record<string, OperationHandler>;
}
