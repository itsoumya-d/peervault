export class CryptoEngine {
  private key: CryptoKey | null = null;

  async generateKey(): Promise<string> {
    this.key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const rawKey = await crypto.subtle.exportKey('raw', this.key);
    return this.bufferToBase64Url(rawKey);
  }

  async importKey(base64UrlKey: string): Promise<void> {
    const rawKey = this.base64UrlToBuffer(base64UrlKey);
    this.key = await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async encryptChunk(data: ArrayBuffer): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
    if (!this.key) throw new Error('Key not initialized');

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.key,
      data
    );

    return { iv, ciphertext };
  }

  async decryptChunk(iv: Uint8Array, ciphertext: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.key) throw new Error('Key not initialized');

    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      this.key,
      ciphertext
    );
  }

  private bufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private base64UrlToBuffer(base64Url: string): ArrayBuffer {
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
