import { writable, type Writable } from 'svelte/store';

// Type definitions
export interface ProtectionStatus {
  enabled: boolean;
  monitored_paths: string[];
  scanning_enabled: boolean;
  last_updated: string | null;
  version: string | null;
}

export interface ScanRecord {
  id: string;
  scan_type: string;
  start_time: string;
  completed_at: string;
  duration: number;
  files_scanned: number;
  threats_found: number;
  items_quarantined: number;
  detected_threats: ThreatEntry[];
}

export interface ThreatEntry {
  id: string;
  name: string;
  path: string;
  risk_level: string;
  description: string;
  detected_at: string;
  in_quarantine: boolean;
  action: string | null;
}

export interface ThreatStatistics {
  total_detected: number;
  in_quarantine: number;
  recent_threats: ThreatEntry[];
  threats_by_type: Record<string, number>;
  threats_by_month: Record<string, number>;
}

export interface QuarantineEntry {
  id: string;
  original_path: string;
  quarantined_at: string;
  threat_name: string;
  file_size: number;
  can_restore: boolean;
}

export interface UpdateStatus {
  last_check: string | null;
  last_update: string | null;
  update_available: boolean;
  update_version: string | null;
  update_size: number;
}

export interface SystemStatus {
  is_protected: boolean;
  last_scan: string;
  threats_detected: number;
  realtime_protection: boolean;
  database_updated: string;
  system_load: number;
}

// Create stores
export const protectionStatus: Writable<ProtectionStatus> = writable({
  enabled: false,
  monitored_paths: [],
  scanning_enabled: false,
  last_updated: null,
  version: null
});

export const scanHistory: Writable<ScanRecord[]> = writable([]);

export const threatStats: Writable<ThreatStatistics> = writable({
  total_detected: 0,
  in_quarantine: 0,
  recent_threats: [],
  threats_by_type: {},
  threats_by_month: {}
});

export const quarantineItems: Writable<QuarantineEntry[]> = writable([]);

export const updateStatus: Writable<UpdateStatus> = writable({
  last_check: null,
  last_update: null,
  update_available: false,
  update_version: null,
  update_size: 0
});

export const statusStore: Writable<SystemStatus> = writable({
  is_protected: true,
  last_scan: 'Never',
  threats_detected: 0,
  realtime_protection: true,
  database_updated: 'Never',
  system_load: 0
}); 