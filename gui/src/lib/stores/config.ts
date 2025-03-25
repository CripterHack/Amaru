import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export interface ConfigState {
  autostart: boolean;
  heuristicAnalysis: boolean;
  heuristicThreshold: number;
  performance: {
    lowResourceMode: boolean;
    processPriority: 'low' | 'below-normal' | 'normal' | 'above-normal' | 'high';
    cpuUsageLimit: number | null;
    pauseOnHighUsage: boolean;
    highUsageThreshold: number;
  };
  ui: {
    theme: 'light' | 'dark' | 'system';
    showNotifications: boolean;
    minimizeToTray: boolean;
    showStatistics: boolean;
    language: string;
  };
  scan: {
    scheduledScan: boolean;
    scanTime: number;
    scanDay: number | null;
    scanFrequency: 'daily' | 'weekly' | 'monthly';
    maxThreads: number;
    maxFileSize: number;
    scanExtensions: string[];
    excludePaths: string[];
  };
}

const initialState: ConfigState = {
  autostart: true,
  heuristicAnalysis: true,
  heuristicThreshold: 70,
  performance: {
    lowResourceMode: false,
    processPriority: 'normal',
    cpuUsageLimit: null,
    pauseOnHighUsage: true,
    highUsageThreshold: 80,
  },
  ui: {
    theme: 'system',
    showNotifications: true,
    minimizeToTray: true,
    showStatistics: true,
    language: 'es-ES',
  },
  scan: {
    scheduledScan: true,
    scanTime: 2, // 2 AM
    scanDay: 0, // Sunday
    scanFrequency: 'weekly',
    maxThreads: 4,
    maxFileSize: 100 * 1024 * 1024, // 100MB
    scanExtensions: ['exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'js'],
    excludePaths: ['C:\\Windows\\WinSxS', 'C:\\Windows\\SystemResources'],
  },
};

function createConfigStore() {
  const { subscribe, set, update } = writable<ConfigState>(initialState);

  return {
    subscribe,
    update,
    
    init: async () => {
      try {
        const config = await invoke<ConfigState>('get_config');
        set(config);
      } catch (error) {
        console.error('Error loading config:', error);
      }
    },
    
    saveConfig: async () => {
      let currentConfig: ConfigState;
      
      subscribe(value => {
        currentConfig = value;
      })();
      
      try {
        await invoke('save_config', { config: currentConfig });
      } catch (error) {
        console.error('Error saving config:', error);
      }
    },
    
    toggleAutostart: async () => {
      update(state => {
        const newState = { ...state, autostart: !state.autostart };
        invoke('set_autostart', { enable: newState.autostart })
          .catch(error => console.error('Error setting autostart:', error));
        return newState;
      });
    },
    
    setTheme: (theme: 'light' | 'dark' | 'system') => {
      update(state => {
        const newState = { 
          ...state, 
          ui: { ...state.ui, theme }
        };
        
        // Apply theme to document
        if (theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
        
        return newState;
      });
    },
    
    toggleNotifications: () => {
      update(state => ({
        ...state,
        ui: { 
          ...state.ui, 
          showNotifications: !state.ui.showNotifications 
        }
      }));
    },
    
    setLowResourceMode: (enabled: boolean) => {
      update(state => {
        const newState = { 
          ...state, 
          performance: { ...state.performance, lowResourceMode: enabled }
        };
        
        invoke('set_performance_mode', { lowResource: enabled })
          .catch(error => console.error('Error setting performance mode:', error));
          
        return newState;
      });
    },
    
    setHeuristicAnalysis: (enabled: boolean) => {
      update(state => {
        const newState = { ...state, heuristicAnalysis: enabled };
        
        invoke('set_heuristic_analysis', { enabled })
          .catch(error => console.error('Error setting heuristic analysis:', error));
          
        return newState;
      });
    },
    
    setHeuristicThreshold: (threshold: number) => {
      update(state => {
        const newState = { ...state, heuristicThreshold: threshold };
        
        invoke('set_heuristic_threshold', { threshold })
          .catch(error => console.error('Error setting heuristic threshold:', error));
          
        return newState;
      });
    },
    
    reset: () => {
      set(initialState);
      return invoke('reset_config')
        .catch(error => console.error('Error resetting config:', error));
    },
  };
}

export const configStore = createConfigStore(); 