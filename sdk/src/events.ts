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
