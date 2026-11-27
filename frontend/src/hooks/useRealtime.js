import { useEffect, useRef, useState } from 'react';
import { isSupabaseConfigured, supabase } from '../services/supabaseClient';

/**
 * Subscribe to Supabase Realtime `postgres_changes` for live SOC monitoring.
 * Uses ref-backed callbacks to avoid duplicate listeners or re-subscription churn,
 * and cleans up the WebSocket channel cleanly on unmount.
 */
export function useRealtimeFeed({
  enabled = true,
  channelName = 'log-sentinel-live',
  onEventInsert = null,
  onIncidentChange = null,
  onDeviceChange = null,
  onReconnectSync = null,
} = {}) {
  const [connectionState, setConnectionState] = useState(
    isSupabaseConfigured && enabled ? 'connecting' : 'offline',
  );
  const [lastMessageAt, setLastMessageAt] = useState(null);

  const eventCbRef = useRef(onEventInsert);
  const incidentCbRef = useRef(onIncidentChange);
  const deviceCbRef = useRef(onDeviceChange);
  const reconnectCbRef = useRef(onReconnectSync);
  const sawErrorRef = useRef(false);

  eventCbRef.current = onEventInsert;
  incidentCbRef.current = onIncidentChange;
  deviceCbRef.current = onDeviceChange;
  reconnectCbRef.current = onReconnectSync;

  useEffect(() => {
    if (!enabled || !isSupabaseConfigured || !supabase) {
      setConnectionState('offline');
      return undefined;
    }

    setConnectionState('connecting');
    const uniqueChannelId = `${channelName}-${Math.random().toString(36).slice(2, 8)}`;
    const channel = supabase.channel(uniqueChannelId);

    channel
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'authentication_events' },
        (payload) => {
          setLastMessageAt(new Date().toISOString());
          if (payload?.new && eventCbRef.current) {
            eventCbRef.current(payload.new);
          }
        },
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'security_incidents' },
        (payload) => {
          setLastMessageAt(new Date().toISOString());
          if (incidentCbRef.current) {
            incidentCbRef.current(payload);
          }
        },
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'monitored_devices' },
        (payload) => {
          setLastMessageAt(new Date().toISOString());
          if (deviceCbRef.current) {
            deviceCbRef.current(payload);
          }
        },
      )
      .subscribe((status) => {
        if (status === 'SUBSCRIBED') {
          setConnectionState('connected');
          if (sawErrorRef.current) {
            sawErrorRef.current = false;
            reconnectCbRef.current?.();
          }
        } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
          sawErrorRef.current = true;
          setConnectionState('reconnecting');
        } else if (status === 'CLOSED') {
          setConnectionState('offline');
        }
      });

    return () => {
      supabase.removeChannel(channel);
    };
  }, [enabled, channelName]);

  return { connectionState, lastMessageAt };
}
