import { DurableObject } from 'cloudflare:workers';
import { parseConfig } from './config';

export interface Snapshot { text?: string; version: number; epoch: number; rulesEpoch: number; gistId?: string; }
export class ConfigStore extends DurableObject<Env> {
  async snapshot(): Promise<Snapshot> {
    return await this.ctx.storage.get<Snapshot>('state') ?? { version: 0, epoch: 0, rulesEpoch: 0 };
  }
  async update(text: string): Promise<Snapshot> {
    parseConfig(text);
    return this.ctx.storage.transaction(async tx => {
      const old = await tx.get<Snapshot>('state') ?? { version: 0, epoch: 0, rulesEpoch: 0 };
      const next = { ...old, text, version: old.version + 1 };
      await tx.put('state', next); return next;
    });
  }
  async bump(kind: 'epoch' | 'rulesEpoch' | 'version'): Promise<void> {
    await this.ctx.storage.transaction(async tx => {
      const old = await tx.get<Snapshot>('state') ?? { version: 0, epoch: 0, rulesEpoch: 0 };
      old[kind]++; await tx.put('state', old);
    });
  }
  async saveGist(id: string): Promise<void> {
    await this.ctx.storage.transaction(async tx => {
      const old = await tx.get<Snapshot>('state') ?? { version: 0, epoch: 0, rulesEpoch: 0 };
      old.gistId = id; await tx.put('state', old);
    });
  }
}
