// Runs the check off the main thread so the page stays responsive while the test database works.
import { analyze, type Source } from "../../src/analyze.js";

export type WorkerRequest = { projectName: string; source: Source };
export type WorkerMessage =
  | { type: "progress"; step: string }
  | { type: "result"; result: Awaited<ReturnType<typeof analyze>> }
  | { type: "error"; message: string };

// Typed as a worker scope without pulling the WebWorker lib, which conflicts with the DOM lib.
const scope = self as unknown as {
  postMessage(message: WorkerMessage): void;
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
};

const post = (message: WorkerMessage) => scope.postMessage(message);

scope.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  try {
    const result = await analyze({
      projectName: event.data.projectName,
      source: event.data.source,
      onProgress: (step) => post({ type: "progress", step }),
    });
    post({ type: "result", result });
  } catch (err) {
    post({ type: "error", message: (err as Error).message });
  }
};
