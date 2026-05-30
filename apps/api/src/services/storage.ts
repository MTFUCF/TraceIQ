/**
 * Blob storage helper.
 *
 * Author: Matthew Faber
 *
 * Thin wrapper around @azure/storage-blob so callers don't need to know about
 * containers, clients, or the difference between connection-string auth and
 * Managed Identity. In Azure we'll later swap the connection-string client
 * for DefaultAzureCredential (Managed Identity), but the public API stays the
 * same.
 *
 * One container ("logs" by default). Uploaded files are written under a key
 * like  uploads/<uploadId>/<filename>  so a single upload's artifacts are
 * grouped together if we ever add derived files (parsed JSON, etc.).
 */
import {
  BlobServiceClient,
  ContainerClient,
} from "@azure/storage-blob";
import { config } from "../config.js";

const service = BlobServiceClient.fromConnectionString(
  config.storage.connectionString,
);

let containerCached: ContainerClient | null = null;
async function container(): Promise<ContainerClient> {
  if (containerCached) return containerCached;
  const c = service.getContainerClient(config.storage.container);
  await c.createIfNotExists();
  containerCached = c;
  return c;
}

export async function uploadBuffer(
  blobPath: string,
  data: Buffer,
  contentType = "text/plain",
): Promise<void> {
  const c = await container();
  const block = c.getBlockBlobClient(blobPath);
  await block.uploadData(data, {
    blobHTTPHeaders: { blobContentType: contentType },
  });
}

export async function downloadAsText(blobPath: string): Promise<string> {
  const c = await container();
  const block = c.getBlockBlobClient(blobPath);
  const buf = await block.downloadToBuffer();
  return buf.toString("utf8");
}
