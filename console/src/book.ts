// This browser's own address book. Which devices a console talks to is a fact
// about the console, not a row on the relay: the device decides by its own
// `trust` list, and the relay only ever routes. Clearing site data loses the
// list, and nothing on any device changes because of it.
import { BOOK_STORE, idbDelete, idbEntries, idbGet, idbPut, openDb } from "./db";

export interface BookEntry {
  address: string;
  label: string;
  created_at: number;
}

const ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/;

export function looksLikeAddress(value: string): boolean {
  return ADDRESS.test(value.trim());
}

function labelFor(address: string, label?: string): string {
  const trimmed = label?.trim();
  return trimmed ? trimmed.slice(0, 80) : address.slice(0, 12);
}

export async function bookList(): Promise<BookEntry[]> {
  const db = await openDb();
  const entries = await idbEntries<BookEntry>(db, BOOK_STORE);
  return entries.sort((a, b) => b.created_at - a.created_at);
}

/** Adding a device is typing its address: no code, no approval, no pairing. */
export async function bookPut(address: string, label?: string): Promise<BookEntry> {
  const db = await openDb();
  const existing = await idbGet<BookEntry>(db, BOOK_STORE, address);
  const entry: BookEntry = existing
    ? { ...existing, label: labelFor(address, label ? label : existing.label) }
    : { address, label: labelFor(address, label), created_at: Math.floor(Date.now() / 1000) };
  await idbPut(db, BOOK_STORE, address, entry);
  return entry;
}

/** Forgetting a device is local: it stops this console from listing it, nothing more. */
export async function bookRemove(address: string): Promise<void> {
  const db = await openDb();
  await idbDelete(db, BOOK_STORE, address);
}
