import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mock ResizeObserver which is not available in jsdom
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}));

// jsdom has no Web Animations timeline. Complete transitions on the next microtask.
Object.defineProperty(Element.prototype, 'animate', {
  configurable: true,
  value() {
    const animation = {
      currentTime: 0,
      playState: 'running',
      onfinish: null as (() => void) | null,
      cancel() { this.playState = 'idle'; }
    };
    queueMicrotask(() => {
      if (animation.playState !== 'running') return;
      animation.playState = 'finished';
      animation.onfinish?.();
    });
    return animation;
  }
});

// Mock window.matchMedia which is not available in jsdom
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(), // deprecated
    removeListener: vi.fn(), // deprecated
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Setup global mocks
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

vi.mock('@tauri-apps/api/tauri', () => ({
  invoke: vi.fn(),
})); 