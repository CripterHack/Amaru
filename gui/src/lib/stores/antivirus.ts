import { writable } from 'svelte/store';
import type { Notification } from '$lib/types';
import { invoke } from '@tauri-apps/api/tauri';

export interface AntivirusState {
  scanning: boolean;
  realtimeProtection: boolean;
  heuristicEnabled: boolean;
  currentFile: string | null;
  notifications: Notification[];
  stats: {
    filesScanned: number;
    threatsFound: number;
    heuristicThreats: number;
    lastScan: Date | null;
  };
  config: {
    maxThreads: number;
    yaraRulesPath: string;
    scanArchives: boolean;
    excludePaths: string[];
  };
}

const initialState: AntivirusState = {
  scanning: false,
  realtimeProtection: false,
  heuristicEnabled: true,
  currentFile: null,
  notifications: [],
  stats: {
    filesScanned: 0,
    threatsFound: 0,
    heuristicThreats: 0,
    lastScan: null,
  },
  config: {
    maxThreads: 4,
    yaraRulesPath: '',
    scanArchives: true,
    excludePaths: [],
  },
};

function createAntivirusStore() {
  const { subscribe, set, update } = writable<AntivirusState>(initialState);

  return {
    subscribe,
    startScan: async (path: string, useHeuristic: boolean = true) => {
      update(state => ({ ...state, scanning: true }));
      try {
        await invoke('start_scan', { path, useHeuristic });
      } catch (error) {
        console.error('Error starting scan:', error);
        update(state => ({ ...state, scanning: false }));
      }
    },
    stopScan: async () => {
      try {
        await invoke('stop_scan');
        update(state => ({ ...state, scanning: false, currentFile: null }));
      } catch (error) {
        console.error('Error stopping scan:', error);
      }
    },
    toggleRealtimeProtection: async () => {
      update(state => {
        const newState = !state.realtimeProtection;
        invoke('toggle_realtime_protection', { 
          enabled: newState,
          useHeuristic: state.heuristicEnabled
        })
          .catch(error => console.error('Error toggling protection:', error));
        return { ...state, realtimeProtection: newState };
      });
    },
    toggleHeuristicAnalysis: async () => {
      update(state => {
        const newState = !state.heuristicEnabled;
        invoke('set_heuristic_analysis', { enabled: newState })
          .catch(error => console.error('Error toggling heuristic analysis:', error));
        
        // Si la protección en tiempo real está activa, actualizar también allí
        if (state.realtimeProtection) {
          invoke('toggle_realtime_protection', { 
            enabled: state.realtimeProtection,
            useHeuristic: newState
          })
            .catch(error => console.error('Error updating realtime protection:', error));
        }
        
        return { ...state, heuristicEnabled: newState };
      });
    },
    updateConfig: async (config: Partial<AntivirusState['config']>) => {
      update(state => {
        const newConfig = { ...state.config, ...config };
        invoke('update_config', { config: newConfig })
          .catch(error => console.error('Error updating config:', error));
        return { ...state, config: newConfig };
      });
    },
    addNotification: (notification: Notification) => {
      update(state => ({
        ...state,
        notifications: [notification, ...state.notifications].slice(0, 100),
      }));
    },
    clearNotifications: () => {
      update(state => ({ ...state, notifications: [] }));
    },
    updateStats: (stats: Partial<AntivirusState['stats']>) => {
      update(state => ({
        ...state,
        stats: { ...state.stats, ...stats },
      }));
    },
    setCurrentFile: (filePath: string | null) => {
      update(state => ({
        ...state,
        currentFile: filePath,
      }));
    },
    updateSystemStatus: (status: any) => {
      update(state => ({
        ...state,
        realtimeProtection: status.realtimeProtection || state.realtimeProtection,
        heuristicEnabled: status.heuristicEnabled || state.heuristicEnabled,
        stats: {
          ...state.stats,
          filesScanned: status.filesScanned || state.stats.filesScanned,
          threatsFound: status.threatsFound || state.stats.threatsFound,
          heuristicThreats: status.heuristicThreats || state.stats.heuristicThreats,
          lastScan: status.lastScan ? new Date(status.lastScan) : state.stats.lastScan
        }
      }));
    },
    acknowledge: (notificationId: string) => {
      update(state => ({
        ...state,
        notifications: state.notifications.map(n => 
          n.id === notificationId ? { ...n, acknowledged: true } : n
        )
      }));
    },
    reset: () => set(initialState),
  };
}

export const antivirusStore = createAntivirusStore(); 