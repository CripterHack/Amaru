export interface Notification {
  id: string;
  type: 'threat' | 'system' | 'update' | 'scan';
  title: string;
  message: string;
  timestamp: Date;
  priority: 'low' | 'medium' | 'high' | 'critical';
  acknowledged: boolean;
  metadata?: Record<string, unknown>;
}

export interface ScanResult {
  path: string;
  threatName?: string;
  riskLevel?: number;
  timestamp: Date;
  action: 'quarantine' | 'delete' | 'ignore';
}

export interface SystemStats {
  cpuUsage: number;
  memoryUsage: number;
  scanSpeed: number;
  threatsBlocked: number;
}

export interface ConfigOption {
  key: string;
  label: string;
  description: string;
  type: 'boolean' | 'number' | 'string' | 'path' | 'array';
  value: unknown;
  category: 'scanning' | 'protection' | 'performance' | 'updates';
  validation?: {
    min?: number;
    max?: number;
    pattern?: string;
    required?: boolean;
  };
} 