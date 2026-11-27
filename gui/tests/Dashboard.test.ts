/**
 * Dashboard Component Tests
 * 
 * These tests validate the Dashboard component's functionality,
 * API integration, and event handling.
 */

import { render, fireEvent, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/tauri';
import App from '../src/App.svelte';
import Dashboard from '../src/routes/Dashboard.svelte';
const protectionStatus = {
  enabled: true,
  monitored_paths: [],
  scanning_enabled: true,
  last_updated: '2025-01-01T00:00:00Z',
  version: '1.0.0'
};

// Mock Tauri API
vi.mock('@tauri-apps/api/tauri', () => ({
  invoke: vi.fn((command, args) => {
    switch (command) {
      case 'get_protection_status':
        return Promise.resolve(protectionStatus);
      case 'get_threat_statistics':
        return Promise.resolve({
          total_detected: 5,
          in_quarantine: 2,
          recent_threats: [
            {
              id: '1',
              name: 'Test.Malware.001',
              path: 'C:\\Users\\Test\\Downloads\\malware.exe',
              risk_level: 'high',
              description: 'Test malware',
              detected_at: new Date().toISOString(),
              in_quarantine: true,
              action: 'quarantined'
            }
          ],
          threats_by_type: { 'malware': 3, 'trojan': 2 },
          threats_by_month: { '2023-06': 5 }
        });
      case 'get_activity_log':
        return Promise.resolve([
          {
            id: '1',
            type: 'scan',
            message: 'Quick scan completed',
            date: new Date().toISOString(),
            status: 'success'
          }
        ]);
      case 'get_scan_history':
        return Promise.resolve([]);
      case 'get_system_resources':
        return Promise.resolve({ cpu_usage: 10, memory_usage: 20 });
      case 'start_quick_scan':
      case 'toggle_protection':
        return Promise.resolve();
      case 'toggle_protection_feature':
        return Promise.resolve();
      default:
        return Promise.reject(new Error(`Unknown command: ${command}`));
    }
  })
}));

// Mock Tauri events
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(() => Promise.resolve(() => {}))
}));

describe('Dashboard Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('loads threats and shows the current protection status', async () => {
    render(Dashboard, { protectionStatus });
    expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
    expect(screen.getByText('Protected')).toBeInTheDocument();
    expect(await screen.findByText('Test.Malware.001')).toBeInTheDocument();
  });

  test('waits for backend confirmation before showing a protected system', async () => {
    render(App);
    expect(screen.getByText('Protection status unavailable')).toBeInTheDocument();
    expect(screen.queryByText('Protected')).toBeNull();
    expect(await screen.findByRole('checkbox', { name: 'Protection' })).toBeChecked();
  });

  test('toggles protection using the application sidebar', async () => {
    render(App);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('get_protection_status'));
    await fireEvent.click(screen.getByRole('checkbox', { name: 'Protection' }));
    expect(invoke).toHaveBeenCalledWith('toggle_protection', { enable: false });
    expect(await screen.findByText('At Risk')).toBeInTheDocument();
  });

  test('preserves the confirmed protection state when a toggle fails', async () => {
    render(App);
    const toggle = await screen.findByRole('checkbox', { name: 'Protection' });
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      vi.mocked(invoke).mockRejectedValueOnce(new Error('Service unavailable'));
      await fireEvent.click(toggle);
      expect(await screen.findByText('Failed to toggle protection: Error: Service unavailable')).toBeInTheDocument();
      expect(toggle).toBeChecked();
      expect(toggle).toBeEnabled();
      expect(screen.queryByText('At Risk')).toBeNull();
    } finally {
      log.mockRestore();
    }
  });

  test('starts a quick scan', async () => {
    render(Dashboard, { protectionStatus });
    await fireEvent.click(screen.getByRole('button', { name: 'Run Quick Scan' }));
    expect(invoke).toHaveBeenCalledWith('start_quick_scan');
    expect(screen.getByRole('button', { name: 'Scanning...' })).toBeDisabled();
  });

  test('toggles the selected protection feature', async () => {
    render(Dashboard, { protectionStatus });
    const toggle = screen.getByRole('checkbox', { name: 'Real-time Protection' });
    await fireEvent.click(toggle);
    expect(invoke).toHaveBeenCalledWith('toggle_protection_feature', {
      featureId: 'realtime', enable: false
    });
    expect(toggle).not.toBeChecked();
  });

  test('displays loading status until the threat list arrives', async () => {
    render(Dashboard, { protectionStatus });
    expect(screen.getByRole('status', { name: 'Loading recent threats' })).toBeInTheDocument();
    await screen.findByText('Test.Malware.001');
    expect(screen.queryByRole('status', { name: 'Loading recent threats' })).toBeNull();
  });
});
