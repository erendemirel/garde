import { writable } from 'svelte/store';
import type { User } from './api';

export const user = writable<User | null>(null);
export const isAdmin = writable(false);
export const isSuperuser = writable(false);

