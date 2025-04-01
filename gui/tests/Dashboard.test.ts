/**
 * Dashboard Component Tests
 * 
 * These tests validate the Dashboard component's functionality,
 * API integration, and event handling.
 */

import { render, fireEvent, screen } from '@testing-library/svelte';
import { vi } from 'vitest';
import Dashboard from '../src/routes/Dashboard.svelte';
import { protectionStatus, threatStats, statusStore } from '../src/lib/stores/statusStore';
import { tick } from 'svelte';

// Mock Tauri API
vi.mock('@tauri-apps/api/tauri', () => ({
  invoke: vi.fn((command, args) => {
    switch (command) {
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
    // Reset mocks
    vi.clearAllMocks();
    
    // Reset stores
    protectionStatus.set({
      enabled: true,
      monitored_paths: [],
      scanning_enabled: true,
      last_updated: new Date().toISOString(),
      version: '1.0.0'
    });
    
    statusStore.set({
      is_protected: true,
      last_scan: 'Never',
      threats_detected: 0,
      realtime_protection: true,
      database_updated: 'Never',
      system_load: 0
    });
  });

  test('renders dashboard with protection status', async () => {
    const { getByText, queryByText } = render(Dashboard, {
      protectionStatus: {
        enabled: true,
        monitored_paths: [],
        scanning_enabled: true,
        last_updated: new Date().toISOString(),
        version: '1.0.0'
      }
    });

    // Check that it renders the title
    expect(getByText('Dashboard')).toBeTruthy();
    
    // Check protection status
    expect(getByText('Protected')).toBeTruthy();
    expect(queryByText('At Risk')).toBeFalsy();
    
    // Wait for API calls to complete
    await tick();
    
    // Check that threat stats loaded
    expect(getByText('Test.Malware.001')).toBeTruthy();
  });

  test('toggles protection when button is clicked', async () => {
    const { getByText } = render(Dashboard, {
      protectionStatus: {
        enabled: true,
        monitored_paths: [],
        scanning_enabled: true,
        last_updated: new Date().toISOString(),
        version: '1.0.0'
      }
    });

    // Get the protection status toggle
    const toggleButton = getByText('Protected');
    
    // Click the toggle
    await fireEvent.click(toggleButton);
    
    // Check that API was called with correct arguments
    expect(vi.mocked(invoke)).toHaveBeenCalledWith('toggle_protection', { enable: false });
  });

  test('starts scan when scan button is clicked', async () => {
    const { getByText } = render(Dashboard, {
      protectionStatus: {
        enabled: true,
        monitored_paths: [],
        scanning_enabled: true,
        last_updated: new Date().toISOString(),
        version: '1.0.0'
      }
    });

    // Get the scan button
    const scanButton = getByText('Run Quick Scan');
    
    // Click the scan button
    await fireEvent.click(scanButton);
    
    // Check that API was called
    expect(vi.mocked(invoke)).toHaveBeenCalledWith('start_quick_scan');
  });

  test('toggles protection feature when toggle is clicked', async () => {
    const { getAllByRole } = render(Dashboard, {
      protectionStatus: {
        enabled: true,
        monitored_paths: [],
        scanning_enabled: true,
        last_updated: new Date().toISOString(),
        version: '1.0.0'
      }
    });

    // Get the feature toggles (checkboxes)
    const checkboxes = getAllByRole('checkbox');
    
    // Click the first toggle
    await fireEvent.click(checkboxes[0]);
    
    // Check that API was called with correct arguments
    expect(vi.mocked(invoke)).toHaveBeenCalledWith('toggle_protection_feature', { 
      featureId: 'realtime', 
      enable: false 
    });
  });

  test('shows loading indicators when data is being fetched', () => {
    const { getByText, getAllByRole } = render(Dashboard, {
      protectionStatus: {
        enabled: true,
        monitored_paths: [],
        scanning_enabled: true,
        last_updated: new Date().toISOString(),
        version: '1.0.0'
      }
    });

    // Check that loading spinners are visible
    expect(getAllByRole('status').length).toBeGreaterThan(0);
  });
}); 