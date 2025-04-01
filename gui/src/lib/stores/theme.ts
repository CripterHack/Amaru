import { writable } from 'svelte/store';

// Create a writable store for theme preference
export const theme = writable<'light' | 'dark' | 'system'>('light'); 