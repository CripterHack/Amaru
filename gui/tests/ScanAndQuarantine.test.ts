import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, expect, test, vi } from 'vitest';
import { ask } from '@tauri-apps/api/dialog';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import Scan from '../src/routes/Scan.svelte';
import Quarantine from '../src/routes/Quarantine.svelte';

vi.mock('@tauri-apps/api/dialog', () => ({ ask: vi.fn(), open: vi.fn() }));

beforeEach(() => {
  vi.clearAllMocks();
});

test('displays live scan counts and waits for the terminal event after cancellation', async () => {
  const progress = { id: 'session', currentFile: 'report.txt', filesScanned: 12, filesSkipped: 0, filesFailed: 0, threatsFound: 1, elapsedMs: 1500 };
  let active = false;
  vi.mocked(invoke).mockImplementation(async (command) => {
    if (command === 'get_scan_history') return [];
    if (command === 'get_scan_progress') return active ? progress : null;
    if (command === 'start_quick_scan') { active = true; return; }
    if (command === 'cancel_scan') return;
    throw new Error(command);
  });
  render(Scan);
  const quick = screen.getByRole('heading', { name: 'Quick scan' }).parentElement!.parentElement!.parentElement!;
  await fireEvent.click(quick.querySelector('button')!);
  expect(await screen.findByText('report.txt')).toBeInTheDocument();
  expect(screen.getByText('12')).toBeInTheDocument();
  await fireEvent.click(screen.getByRole('button', { name: /Cancel scan/i }));
  expect(invoke).toHaveBeenCalledWith('cancel_scan');
  expect(screen.getByRole('button', { name: /Cancelling/ })).toBeDisabled();
  const completion = vi.mocked(listen).mock.calls.find(([event]) => event === 'scan-completed')![1];
  completion({event:'scan-completed',windowLabel:'main',id:1,payload:{status:'cancelled'}});
  await waitFor(() => expect(screen.queryByRole('button', { name: /Cancelling/ })).toBeNull());
});

test('restores only confirmed quarantine selections and keeps a failed item visible', async () => {
  const row = { id: 'q1', fileName: 'sample.txt', originalPath: 'C:\\sample.txt', threatType: 'Test', detectionDate: new Date().toISOString(), fileSize: 68 };
  vi.mocked(invoke).mockImplementation(async (command) => {
    if (command === 'get_quarantined_files') return [row];
    if (command === 'restore_quarantined_file') throw new Error('Destination exists');
    throw new Error(command);
  });
  vi.mocked(ask).mockResolvedValueOnce(false).mockResolvedValueOnce(true);
  render(Quarantine);
  await fireEvent.click(await screen.findByRole('button', { name: 'Restore', exact: true }));
  await waitFor(() => expect(ask).toHaveBeenCalledOnce());
  expect(invoke).not.toHaveBeenCalledWith('restore_quarantined_file', {id:'q1', scope:'desktop'});
  await fireEvent.click(await screen.findByRole('button', {name:'Restore', exact:true}));
  await waitFor(() => expect(invoke).toHaveBeenCalledWith('restore_quarantined_file', {id:'q1', scope:'desktop'}));
  expect(await screen.findByText('sample.txt')).toBeInTheDocument();
});

test('shows service access errors when switching quarantine source', async () => {
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    if (command !== 'get_quarantined_files') throw new Error(command);
    if (args?.scope === 'service') throw new Error('Service access denied');
    return [];
  });
  render(Quarantine);
  await screen.findByText('The selected quarantine contains no files.');
  await fireEvent.change(screen.getByRole('combobox', { name: 'Quarantine source' }), { target: {value: 'service'} });
  expect(await screen.findByText(/Error: .*Service access denied/)).toBeInTheDocument();
  expect(screen.queryByText('The selected quarantine contains no files.')).toBeNull();
});
