import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Prevent unit tests from opening real network/WebSocket connections when .env.local exists
vi.mock('./services/supabaseClient', () => ({
  isSupabaseConfigured: false,
  supabase: null,
}));
