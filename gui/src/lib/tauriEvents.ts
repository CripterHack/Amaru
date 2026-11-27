import type { UnlistenFn } from '@tauri-apps/api/event';

// Tauri may finish registering a listener after its component has unmounted.
export function manageListeners(registrations: Promise<UnlistenFn>[]): () => void {
  let active = true;
  const listeners: UnlistenFn[] = [];
  for (const registration of registrations) {
    registration.then(unlisten => {
      if (active) listeners.push(unlisten);
      else unlisten();
    }).catch(error => console.error('Failed to register Tauri event listener:', error));
  }
  return () => {
    active = false;
    for (const unlisten of listeners.splice(0)) unlisten();
  };
}
