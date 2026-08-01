// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com

export class EventEmitter<T extends Record<string, any>> {
  private listeners: { [K in keyof T]?: Array<(event: T[K]) => void> } = {};

  on<K extends keyof T>(event: K, callback: (event: T[K]) => void): void {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event]!.push(callback);
  }

  off<K extends keyof T>(event: K, callback: (event: T[K]) => void): void {
    if (!this.listeners[event]) return;
    this.listeners[event] = this.listeners[event]!.filter((cb) => cb !== callback);
  }

  emit<K extends keyof T>(event: K, data: T[K]): void {
    if (!this.listeners[event]) return;
    this.listeners[event]!.forEach((callback) => callback(data));
  }
}
