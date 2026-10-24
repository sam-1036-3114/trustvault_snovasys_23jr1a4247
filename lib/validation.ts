import { z } from 'zod';

export const ALLOWED_FILE_TYPES = [
  'pdf', 'docx', 'xlsx', 'pptx', 'txt', 'png', 'jpg', 'jpeg',
];

export const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const FILE_SIGNATURES: Record<string, number[]> = {
  pdf: [0x25, 0x50, 0x44, 0x46],
  png: [0x89, 0x50, 0x4E, 0x47],
  jpg: [0xFF, 0xD8, 0xFF],
  jpeg: [0xFF, 0xD8, 0xFF],
  docx: [0x50, 0x4B, 0x03, 0x04],
  xlsx: [0x50, 0x4B, 0x03, 0x04],
  pptx: [0x50, 0x4B, 0x03, 0x04],
  txt: [],
};

export const uploadSchema = z.object({
  title: z.string().min(1, 'Title is required').max(200, 'Title too long'),
  description: z.string().max(2000).optional().default(''),
  category: z.string().min(1).max(50).default('general'),
});

export const updateDocumentSchema = z.object({
  title: z.string().min(1).max(200).optional(),
  description: z.string().max(2000).optional(),
  category: z.string().min(1).max(50).optional(),
});

export const grantPermissionSchema = z.object({
  user_id: z.string().uuid(),
  access_level: z.enum(['read', 'edit']),
});

export const signUpSchema = z.object({
  email: z.string().email('Valid email required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  display_name: z.string().min(1, 'Display name required').max(100),
  role: z.enum(['admin', 'owner', 'viewer']).default('viewer'),
});

export const signInSchema = z.object({
  email: z.string().email('Valid email required'),
  password: z.string().min(1, 'Password required'),
});

export function getFileExtension(filename: string): string {
  const parts = filename.toLowerCase().split('.');
  return parts.length > 1 ? parts[parts.length - 1] : '';
}

export function isAllowedFileType(filename: string, declaredMimeType: string): boolean {
  const ext = getFileExtension(filename);
  if (!ALLOWED_FILE_TYPES.includes(ext)) return false;

  const mimeMap: Record<string, string[]> = {
    pdf: ['application/pdf'],
    png: ['image/png'],
    jpg: ['image/jpeg'],
    jpeg: ['image/jpeg'],
    docx: ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    xlsx: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    pptx: ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
    txt: ['text/plain'],
  };

  const expectedMimes = mimeMap[ext];
  if (expectedMimes && expectedMimes.length > 0) {
    if (!expectedMimes.some(m => declaredMimeType.includes(m))) return false;
  }

  return true;
}

export function verifyFileSignature(fileBuffer: ArrayBuffer, extension: string): boolean {
  const bytes = new Uint8Array(fileBuffer.slice(0, 8));
  const expected = FILE_SIGNATURES[extension];
  if (!expected || expected.length === 0) return true; // txt has no signature

  for (let i = 0; i < expected.length; i++) {
    if (bytes[i] !== expected[i]) return false;
  }
  return true;
}

export function isExecutableFile(filename: string): boolean {
  const ext = getFileExtension(filename);
  const dangerous = ['exe', 'bat', 'cmd', 'sh', 'js', 'jar', 'msi', 'com', 'scr', 'vbs', 'ps1'];
  return dangerous.includes(ext);
}

export function sanitizeFilename(filename: string): string {
  return filename.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 255);
}

export function generateStorageKey(userId: string, extension: string): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 10);
  return `${userId}/${timestamp}-${random}.${extension}`;
}
